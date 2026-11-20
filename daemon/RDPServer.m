#import "daemon/RDPServer.h"
#import "daemon/RDPSession.h"
#import "daemon/SecurityPolicy.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <fcntl.h>
#import <unistd.h>
#define RDP_LOG_COMPONENT "server"
#include "logging/RDPLog.h"
#include <stdatomic.h>

@interface RDPServer () <RDPSessionDelegate>
/* One listen socket per bound address (dual-stack "::" = 1; "localhost" = 2). */
@property (nonatomic, strong) NSMutableArray<NSNumber *> *listenFds;
@property (nonatomic, assign) uint16_t portValue;
@property (nonatomic, assign) BOOL running;
@property (nonatomic, strong) NSMutableArray<RDPSession *> *sessions;
@property (nonatomic, strong) NSMutableArray<dispatch_source_t> *acceptSources;
@property (nonatomic, strong) dispatch_queue_t acceptQueue;
/* The single active (authenticated) session that owns the display. Guarded by
 * @synchronized(self) along with `sessions`. A new client that authenticates
 * supersedes whatever is here. */
@property (nonatomic, strong, nullable) RDPSession *activeSession;
@end

/* Process-wide active-session flag. The daemon runs a single RDPServer, so a
 * class-level flag faithfully mirrors that instance's `_activeSession`. The
 * auto-updater reads this (off any thread) to decide whether to defer a swap. */
/* Previously volatile int32_t: volatile prevents register caching but not
 * CPU reordering — readers on other cores could see stale values.
 * _Atomic with acquire/release gives the correct happens-before guarantee. */
static _Atomic int32_t g_hasActiveSession = 0;

@implementation RDPServer

+ (BOOL)hasActiveSession {
    return atomic_load_explicit(&g_hasActiveSession, memory_order_acquire) != 0;
}

- (void)updateActiveSessionFlag {
    /* Caller holds @synchronized(self); the store pairs with the acquire load
     * in +hasActiveSession to form a proper happens-before edge. */
    atomic_store_explicit(&g_hasActiveSession,
                          (_activeSession != nil) ? 1 : 0,
                          memory_order_release);
}

- (instancetype)initWithPort:(uint16_t)port {
    if ((self = [super init])) {
        _portValue = port;
        _listenFds = [NSMutableArray array];
        _acceptSources = [NSMutableArray array];
        _sessions  = [NSMutableArray array];
        _acceptQueue = dispatch_queue_create("com.macosrdp.accept",
                                             DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (uint16_t)port    { return _portValue; }
- (BOOL)isRunning   { return _running; }

/* Resolve the --bind / RDP_BIND_ADDRESS value into concrete socket addresses.
 * nil / "::" / "any" / "*" = IPv6 dual-stack any (the historical default);
 * "0.0.0.0" = IPv4 any; "localhost" = 127.0.0.1 + ::1; otherwise an IPv4/IPv6
 * literal or a resolvable host name. `v6only` is set for explicit IPv6 addresses. */
typedef struct {
    struct sockaddr_storage ss;
    socklen_t               len;
    int                     family;
    int                     v6only;
    BOOL                    optional;   /* failure to bind is tolerated (localhost's ::1) */
} BindSpec;

static int add_spec(BindSpec *out, int n, int family, const void *addr, uint16_t port,
                    int v6only, BOOL optional) {
    if (n >= 8) return n;
    BindSpec *b = &out[n];
    memset(b, 0, sizeof(*b));
    b->family = family;
    b->v6only = v6only;
    b->optional = optional;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&b->ss;
        a->sin_family = AF_INET;
        a->sin_len = sizeof(*a);
        a->sin_port = htons(port);
        memcpy(&a->sin_addr, addr, sizeof(a->sin_addr));
        b->len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&b->ss;
        a->sin6_family = AF_INET6;
        a->sin6_len = sizeof(*a);
        a->sin6_port = htons(port);
        memcpy(&a->sin6_addr, addr, sizeof(a->sin6_addr));
        b->len = sizeof(*a);
    }
    return n + 1;
}

static int resolve_bind(NSString *bindAddr, uint16_t port, BindSpec *out) {
    int n = 0;
    struct in_addr v4any = { .s_addr = htonl(INADDR_ANY) };
    struct in_addr v4lo  = { .s_addr = htonl(INADDR_LOOPBACK) };
    NSString *b = bindAddr ?: @"";
    if ([b hasPrefix:@"["] && [b hasSuffix:@"]"] && b.length > 2)
        b = [b substringWithRange:NSMakeRange(1, b.length - 2)];

    if (b.length == 0 || [b isEqualToString:@"::"] || [b isEqualToString:@"*"] ||
        [b caseInsensitiveCompare:@"any"] == NSOrderedSame)
        return add_spec(out, 0, AF_INET6, &in6addr_any, port, 0, NO);
    if ([b caseInsensitiveCompare:@"localhost"] == NSOrderedSame) {
        n = add_spec(out, n, AF_INET, &v4lo, port, 0, NO);
        return add_spec(out, n, AF_INET6, &in6addr_loopback, port, 1, YES);
    }
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, b.UTF8String, &a4) == 1)
        return add_spec(out, 0, AF_INET, &a4, port, 0, NO);
    if (inet_pton(AF_INET6, b.UTF8String, &a6) == 1)
        return add_spec(out, 0, AF_INET6, &a6, port, 1, NO);
    (void)v4any;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(b.UTF8String, NULL, &hints, &res) != 0) return 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET)
            n = add_spec(out, n, AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, port, 0, NO);
        else if (ai->ai_family == AF_INET6)
            n = add_spec(out, n, AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, port, 1, NO);
    }
    freeaddrinfo(res);
    return n;
}

- (BOOL)startWithError:(NSError **)error {
    NSString *bindAddr = [SecurityPolicy bindAddress];
    BindSpec specs[8];
    int nspec = resolve_bind(bindAddr, _portValue, specs);
    if (nspec == 0) {
        rdp_error("cannot resolve listen address '%s' (use an IPv4/IPv6 address or localhost)",
                  bindAddr.UTF8String);
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
        return NO;
    }
    rdp_verbose("creating listen socket(s) for %s on port %u",
                bindAddr.length ? bindAddr.UTF8String : "any (IPv6 dual-stack)", _portValue);

    int lastErr = 0;
    for (int i = 0; i < nspec; i++) {
        BindSpec *sp = &specs[i];
        int fd = socket(sp->family, SOCK_STREAM, 0);
        if (fd < 0) {
            lastErr = errno;
            if (!sp->optional) rdp_error("socket() failed: %s", strerror(errno));
            continue;
        }
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (sp->family == AF_INET6) {
            int v6only = sp->v6only;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        if (bind(fd, (struct sockaddr *)&sp->ss, sp->len) < 0 || listen(fd, 8) < 0) {
            lastErr = errno;
            if (sp->optional)
                rdp_verbose("optional listen address unavailable: %s", strerror(errno));
            else
                rdp_error("bind/listen failed on port %u: %s", _portValue, strerror(errno));
            close(fd);
            continue;
        }
        [_listenFds addObject:@(fd)];
        rdp_debug("listen socket fd=%d ready", fd);
        dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                                       (uintptr_t)fd, 0, _acceptQueue);
        __weak typeof(self) weak = self;
        dispatch_source_set_event_handler(src, ^{ [weak acceptConnectionOnFd:fd]; });
        dispatch_resume(src);
        [_acceptSources addObject:src];
    }
    if (_listenFds.count == 0) {
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                code:lastErr ?: EINVAL userInfo:nil];
        return NO;
    }
    _running = YES;
    [SecurityPolicy logConfiguration];
    return YES;
}

/* Dotted-quad for IPv4 (including v4-mapped IPv6), canonical text for IPv6. */
static NSString *client_address_string(const struct sockaddr_storage *ss) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (ss->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf, sizeof(buf));
    } else {
        const struct in6_addr *a = &((const struct sockaddr_in6 *)ss)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(a))
            inet_ntop(AF_INET, &a->s6_addr[12], buf, sizeof(buf));
        else
            inet_ntop(AF_INET6, a, buf, sizeof(buf));
    }
    return [NSString stringWithUTF8String:buf];
}

- (void)acceptConnectionOnFd:(int)listenFd {
    struct sockaddr_storage clientAddr = {0};
    socklen_t len = sizeof(clientAddr);
    int clientFd = accept(listenFd, (struct sockaddr *)&clientAddr, &len);
    if (clientFd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            rdp_error("accept() failed: %s", strerror(errno));
        return;
    }

    NSString *addr = client_address_string(&clientAddr);

    /* Lockout: refuse a locked-out address before any protocol work (no FreeRDP
     * peer, no TLS handshake). Loopback is never locked out. */
    int locked = [SecurityPolicy lockedSecondsForAddress:addr];
    if (locked > 0) {
        rdp_info("refused connection from %s: locked out for %d more s", addr.UTF8String, locked);
        [SecurityPolicy auditEvent:@"connect" ip:addr user:nil proto:nil result:@"refused"
                            reason:[NSString stringWithFormat:@"locked out (%d s remaining)", locked]
                          duration:-1];
        close(clientFd);
        return;
    }

    rdp_verbose("accepted connection from %s (fd=%d)", addr.UTF8String, clientFd);

    RDPSession *session = [[RDPSession alloc] initWithFileDescriptor:clientFd
                                                       clientAddress:addr];
    session.delegate = self;

    @synchronized(self) { [_sessions addObject:session]; }
    rdp_debug("active sessions: %lu", (unsigned long)_sessions.count);

    [self.delegate serverDidAcceptSession:session];
    [session start];
}

- (void)stop {
    rdp_info("stopping server");
    _running = NO;
    for (dispatch_source_t src in _acceptSources) dispatch_source_cancel(src);
    [_acceptSources removeAllObjects];
    for (NSNumber *fd in _listenFds) close(fd.intValue);
    [_listenFds removeAllObjects];
    NSArray<RDPSession *> *sessions;
    @synchronized(self) {
        rdp_verbose("disconnecting %lu active sessions", (unsigned long)_sessions.count);
        sessions = [_sessions copy];
        for (RDPSession *s in sessions) [s disconnect];
        [_sessions removeAllObjects];
        _activeSession = nil;
        [self updateActiveSessionFlag];
    }
    /* Let each session tear down before the process exits: it unmounts the
     * client's drives (a mount left behind hangs Finder) and restores the
     * displays. A session that hangs costs at most this long in total. */
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:2.5];
    for (RDPSession *s in sessions) {
        NSTimeInterval left = deadline.timeIntervalSinceNow;
        if (left <= 0.05) break;
        [s waitForTeardown:left];
    }
}

/* A session authenticated its client and wants to own the display. Make it the
 * single active session, superseding (disconnecting + waiting on the teardown
 * of) any session currently active. Called on the NEW session's serial queue;
 * the blocking wait happens off-lock so concurrent connection attempts don't
 * stall. Returns NO if the server is stopping. */
- (BOOL)sessionDidAuthenticateAndRequestActivation:(RDPSession *)session {
    if (!_running) {
        rdp_info("activation refused: server is stopping");
        return NO;
    }

    RDPSession *previous = nil;
    @synchronized(self) {
        previous = _activeSession;
        if (previous == session) {
            rdp_verbose("session %s already active", session.clientAddress.UTF8String);
            return YES;
        }
        /* Claim active immediately so a third concurrent client that authenticates
         * supersedes US in turn rather than racing on a stale pointer. */
        _activeSession = session;
        [self updateActiveSessionFlag];
    }

    if (previous) {
        rdp_info("TAKEOVER: %s superseding active session %s",
                 session.clientAddress.UTF8String,
                 previous.clientAddress.UTF8String);
        /* Tell the old session to exit its peer loop + tear down (releases its
         * virtual display + display assertions), then block until it has done so
         * BEFORE we let the new session create its own virtual display — two live
         * virtual displays would both map to the main display and fight. */
        [previous disconnect];
        if (![previous waitForTeardown:10.0])
            rdp_error("TAKEOVER: previous session %s did not tear down in time — "
                      "proceeding anyway (display may briefly conflict)",
                      previous.clientAddress.UTF8String);
        else
            rdp_info("TAKEOVER: previous session %s released the display",
                     previous.clientAddress.UTF8String);
    } else {
        rdp_info("session %s is now the active session (no prior session)",
                 session.clientAddress.UTF8String);
    }

    /* If a still-newer client superseded us while we waited, abort. */
    @synchronized(self) {
        if (_activeSession != session) {
            rdp_info("session %s was superseded while activating — aborting",
                     session.clientAddress.UTF8String);
            [self updateActiveSessionFlag];
            return NO;
        }
    }
    return YES;
}

- (void)sessionDidEnd:(RDPSession *)session error:(NSError *)error {
    @synchronized(self) {
        [_sessions removeObject:session];
        if (_activeSession == session) _activeSession = nil;
        [self updateActiveSessionFlag];
    }
    rdp_debug("session removed; %lu remaining", (unsigned long)_sessions.count);
    [self.delegate serverSession:session didEndWithError:error];
}

@end
