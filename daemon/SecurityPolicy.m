#import "daemon/SecurityPolicy.h"
#import "daemon/Authenticator.h"
#include "daemon/SecurityCore.h"
#import <arpa/inet.h>
#import <membership.h>
#import <netinet/in.h>
#import <grp.h>
#import <pwd.h>
#import <readpassphrase.h>
#import <stdatomic.h>
#import <sys/stat.h>
#import <time.h>
#import <unistd.h>
#define RDP_LOG_COMPONENT "security"
#include "logging/RDPLog.h"

/* RDP security protocol flags (MS-RDPBCGR 2.2.1.1.1) as stored in
 * FreeRDP_SelectedProtocol. */
enum { kProtoRDP = 0, kProtoTLS = 1, kProtoNLA = 2, kProtoRDSTLS = 4, kProtoNLAEX = 8 };

static const NSTimeInterval kLockoutWindowSec  = 600;      /* failures counted within 10 min */
static const long           kAuditMaxBytes     = 1 << 20;  /* rotate at 1 MB, keep one .1 */

/* ── small helpers ───────────────────────────────────────────────────────── */

static int env_int(const char *name, int dflt, int lo, int hi) {
    const char *v = getenv(name);
    if (!v || !*v) return dflt;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v || *end) {
        rdp_error("%s='%s' is not a number — using default %d", name, v, dflt);
        return dflt;
    }
    if (n < lo) n = lo;
    if (n > hi) n = hi;
    return (int)n;
}

static NSString *trimmed(NSString *s) {
    return [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

static NSArray<NSString *> *env_list(const char *name) {
    const char *v = getenv(name);
    if (!v || !*v) return @[];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *p in [[NSString stringWithUTF8String:v] componentsSeparatedByString:@","]) {
        NSString *t = trimmed(p);
        if (t.length) [out addObject:t];
    }
    return out;
}

static const char *protocol_name(uint32_t p) {
    if (p & kProtoNLAEX)  return "NLA-EX";
    if (p & kProtoNLA)    return "NLA";
    if (p & kProtoRDSTLS) return "RDSTLS";
    if (p & kProtoTLS)    return "TLS";
    return "RDP";
}

/* The UID whose desktop this daemon shows. A LaunchAgent runs as that user; if a
 * root LaunchDaemon is used instead, it is the console user. */
static uid_t owner_uid(void) {
    uid_t u = geteuid();
    if (u != 0) return u;
    struct stat st;
    if (stat("/dev/console", &st) == 0 && st.st_uid != 0) return st.st_uid;
    return 0;
}

static NSString *owner_name(void) {
    struct passwd *pw = getpwuid(owner_uid());
    return pw ? [NSString stringWithUTF8String:pw->pw_name] : NSUserName();
}

/* ── lockout state ───────────────────────────────────────────────────────── */

static NSLock       *g_lock;
static sc_lockout   *g_ipLock;      /* per client IP, refused at accept        */
static sc_lockout   *g_userLock;    /* per username                            */
static sc_lockout   *g_nlaFail;     /* per IP: NLA stage failures → TLS-only fallback */
static dispatch_once_t g_once;

static void init_state(void) {
    dispatch_once(&g_once, ^{
        g_lock = [[NSLock alloc] init];
        int thr  = env_int("RDP_LOCKOUT_THRESHOLD", 5, 1, 32);
        int mins = env_int("RDP_LOCKOUT_MINUTES", 15, 1, 1440);
        g_ipLock   = sc_lockout_new(thr, (int)kLockoutWindowSec, mins * 60, 1);
        g_userLock = sc_lockout_new(thr, (int)kLockoutWindowSec, mins * 60, 1);
        /* Two NLA-stage failures within 10 min → offer TLS-only for 5 min so a
         * stale hash (password changed on the Mac) can be re-learned. */
        g_nlaFail  = sc_lockout_new(2, (int)kLockoutWindowSec, 300, 0);
    });
}

static NSString *user_key(NSString *u) {
    return [@"user:" stringByAppendingString:trimmed(u).lowercaseString];
}
static NSString *ip_key(NSString *ip) { return [@"ip:" stringByAppendingString:ip]; }

/* ── SecurityPolicy ──────────────────────────────────────────────────────── */

@implementation SecurityPolicy

static NSString *g_bindOverride;

+ (void)setBindAddress:(NSString *)addr {
    g_bindOverride = addr.length ? [addr copy] : nil;
}

+ (NSString *)bindAddress {
    if (g_bindOverride.length) return g_bindOverride;
    const char *e = getenv("RDP_BIND_ADDRESS");
    if (e && *e) return trimmed([NSString stringWithUTF8String:e]);
    return nil;
}

+ (BOOL)isLoopbackAddressString:(NSString *)addr {
    if (addr.length == 0) return NO;
    NSString *a = addr;
    if ([a hasPrefix:@"["] && [a hasSuffix:@"]"]) a = [a substringWithRange:NSMakeRange(1, a.length - 2)];
    if ([a caseInsensitiveCompare:@"localhost"] == NSOrderedSame) return YES;
    struct in_addr v4;
    if (inet_pton(AF_INET, a.UTF8String, &v4) == 1)
        return (ntohl(v4.s_addr) >> 24) == 127;
    struct in6_addr v6;
    if (inet_pton(AF_INET6, a.UTF8String, &v6) == 1) {
        if (IN6_IS_ADDR_LOOPBACK(&v6)) return YES;
        if (IN6_IS_ADDR_V4MAPPED(&v6)) return v6.s6_addr[12] == 127;
    }
    return NO;
}

+ (BOOL)noAuthEffective {
    const char *e = getenv("RDP_ALLOW_NO_AUTH");
    if (!(e && strcmp(e, "1") == 0)) return NO;
    NSString *bind = [self bindAddress];
    BOOL loop = [self isLoopbackAddressString:bind];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (loop)
            rdp_info("RDP_ALLOW_NO_AUTH=1 honoured: bound to loopback only (%s)", bind.UTF8String);
        else
            rdp_error("RDP_ALLOW_NO_AUTH=1 IGNORED: the daemon is bound to %s, not a loopback "
                      "address. Use --bind localhost (or RDP_BIND_ADDRESS=127.0.0.1) to allow "
                      "unauthenticated connections for testing.",
                      bind.length ? bind.UTF8String : "all interfaces");
    });
    return loop;
}

+ (RDPNlaMode)nlaMode {
    const char *e = getenv("RDP_NLA");
    if (!e || !*e) return RDPNlaModeAuto;
    if (strcasecmp(e, "auto") == 0) return RDPNlaModeAuto;
    if (strcasecmp(e, "off") == 0 || strcmp(e, "0") == 0) return RDPNlaModeOff;
    if (strcasecmp(e, "require") == 0) return RDPNlaModeRequire;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        rdp_error("RDP_NLA='%s' not recognised (auto|off|require) — using auto", e);
    });
    return RDPNlaModeAuto;
}

+ (NSString *)samPath {
    const char *e = getenv("RDP_NLA_SAM_FILE");
    if (e && *e) return [NSString stringWithUTF8String:e];
    return [NSHomeDirectory() stringByAppendingPathComponent:@".macos-rdp/nla.sam"];
}

+ (NSTimeInterval)idleTimeoutSeconds {
    return env_int("RDP_IDLE_TIMEOUT_MIN", 0, 0, 100000) * 60.0;
}

+ (void)logConfiguration {
    static const char *modes[] = {"off", "auto", "require"};
    RDPNlaMode m = [self nlaMode];
    size_t n = 0;
    int chk = sc_sam_file_check(self.samPath.UTF8String, &n);
    rdp_info("security: NLA=%s sam=%s (%s, %zu entries); allowed=%s%s%s; lockout=%d/10min→%dmin; "
             "idle-timeout=%dmin; bind=%s",
             modes[m], self.samPath.UTF8String,
             chk == 0 ? "ok" : (chk == -2 ? "REFUSED: not owned by this user" : "absent"), n,
             owner_name().UTF8String,
             env_list("RDP_ALLOWED_USERS").count
                 ? [NSString stringWithFormat:@" + users[%@]",
                       [env_list("RDP_ALLOWED_USERS") componentsJoinedByString:@","]].UTF8String : "",
             getenv("RDP_ALLOWED_GROUP") && *getenv("RDP_ALLOWED_GROUP")
                 ? [NSString stringWithFormat:@" + group[%s]", getenv("RDP_ALLOWED_GROUP")].UTF8String : "",
             env_int("RDP_LOCKOUT_THRESHOLD", 5, 1, 32), env_int("RDP_LOCKOUT_MINUTES", 15, 1, 1440),
             (int)([self idleTimeoutSeconds] / 60),
             [self bindAddress] ? [self bindAddress].UTF8String : "any (dual-stack)");
    if (m == RDPNlaModeRequire && n == 0)
        rdp_error("RDP_NLA=require but the SAM file has no entries — nobody can log in. "
                  "Run: macos-rdp-daemon --set-nla-password");
    (void)[self noAuthEffective];   /* logs the loopback restriction verdict if set */
}

/* ── lockout ── */

+ (int)lockedSecondsForAddress:(NSString *)ip {
    if (ip.length == 0 || [self isLoopbackAddressString:ip]) return 0;
    init_state();
    [g_lock lock];
    int r = sc_lockout_remaining(g_ipLock, ip_key(ip).UTF8String, time(NULL));
    [g_lock unlock];
    return r;
}

+ (int)lockedSecondsForUser:(NSString *)user address:(NSString *)ip {
    if (user.length == 0 || [self isLoopbackAddressString:ip]) return 0;
    init_state();
    [g_lock lock];
    int r = sc_lockout_remaining(g_userLock, user_key(user).UTF8String, time(NULL));
    [g_lock unlock];
    return r;
}

+ (void)recordFailureForAddress:(NSString *)ip user:(NSString *)user {
    if ([self isLoopbackAddressString:ip]) return;   /* loopback is never locked out */
    init_state();
    time_t now = time(NULL);
    [g_lock lock];
    int ipLock = sc_lockout_fail(g_ipLock, ip_key(ip).UTF8String, now);
    int usLock = user.length ? sc_lockout_fail(g_userLock, user_key(user).UTF8String, now) : 0;
    [g_lock unlock];
    if (ipLock)
        rdp_error("LOCKOUT: %s refused for %d min after repeated failed logons",
                  ip.UTF8String, ipLock / 60);
    if (usLock)
        rdp_error("LOCKOUT: account '%s' locked for %d min after repeated failed logons",
                  user.UTF8String, usLock / 60);
}

+ (void)recordSuccessForAddress:(NSString *)ip user:(NSString *)user {
    init_state();
    [g_lock lock];
    sc_lockout_reset(g_ipLock, ip_key(ip).UTF8String);
    sc_lockout_reset(g_nlaFail, ip_key(ip).UTF8String);
    if (user.length) sc_lockout_reset(g_userLock, user_key(user).UTF8String);
    [g_lock unlock];
}

/* ── allowed users ── */

/* Is the account (typed name) permitted to take this desktop? Default: only the
 * account the daemon runs as. RDP_ALLOWED_USERS / RDP_ALLOWED_GROUP extend it. */
+ (BOOL)isUserAllowed:(NSString *)typed info:(NSDictionary *)acct reason:(NSString **)reason {
    if (!acct) { if (reason) *reason = @"unknown account"; return NO; }
    long uid = [acct[@"uid"] longValue];
    NSArray<NSString *> *names = acct[@"names"];
    NSString *shortName = acct[@"short"];

    if (uid >= 0 && (uid_t)uid == owner_uid()) return YES;
    NSDictionary *own = [Authenticator accountInfoForName:owner_name()];
    for (NSString *n in own[@"names"])
        for (NSString *m in names)
            if ([n caseInsensitiveCompare:m] == NSOrderedSame) return YES;

    for (NSString *allowed in env_list("RDP_ALLOWED_USERS")) {
        NSDictionary *a = [Authenticator accountInfoForName:allowed];
        if (a && uid >= 0 && [a[@"uid"] longValue] == uid) return YES;
        for (NSString *m in names)
            if ([allowed caseInsensitiveCompare:m] == NSOrderedSame) return YES;
    }

    const char *grp = getenv("RDP_ALLOWED_GROUP");
    if (grp && *grp) {
        /* membership(3): resolve the account and group to UUIDs and ask the
         * membership service (covers nested groups and directory-backed groups). */
        uuid_t u, g;
        int isMember = 0;
        struct group *gr = getgrnam(grp);
        if (uid >= 0 && gr &&
            mbr_uid_to_uuid((uid_t)uid, u) == 0 &&
            mbr_gid_to_uuid(gr->gr_gid, g) == 0 &&
            mbr_check_membership(u, g, &isMember) == 0 && isMember)
            return YES;
        if (!gr) rdp_error("RDP_ALLOWED_GROUP='%s' does not exist", grp);
    }
    if (reason) *reason = [NSString stringWithFormat:@"user '%@' is not an allowed Remote Desktop user", shortName];
    return NO;
}

/* ── NLA SAM maintenance ── */

+ (NSArray<NSString *> *)samAliasesForAccount:(NSDictionary *)acct typed:(NSString *)typed {
    NSMutableOrderedSet<NSString *> *set = [NSMutableOrderedSet orderedSet];
    NSString *shortName = acct[@"short"];
    if (shortName) { [set addObject:shortName]; [set addObject:shortName.lowercaseString]; }
    for (NSString *n in acct[@"names"]) [set addObject:n];
    if (typed.length) { [set addObject:typed]; [set addObject:typed.lowercaseString]; }
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *n in set) if (sc_sam_name_ok(n.UTF8String)) [out addObject:n];
    return out;
}

/* Store (or refresh) the NT hash for an account whose password OpenDirectory has
 * just verified. Returns YES on success. */
+ (BOOL)storeNlaHashForAccount:(NSDictionary *)acct typed:(NSString *)typed
                      password:(NSString *)password quiet:(BOOL)quiet {
    uint8_t nt[16];
    if (sc_nt_hash_utf8(password.UTF8String, nt) != 0) {
        rdp_error("nla: password is not valid UTF-8; hash not stored");
        return NO;
    }
    NSString *owner = acct[@"short"];
    NSArray<NSString *> *aliases = [self samAliasesForAccount:acct typed:typed];
    if (!sc_sam_name_ok(owner.UTF8String) || aliases.count == 0) {
        rdp_error("nla: account name '%s' cannot be stored in the SAM file", owner.UTF8String);
        return NO;
    }
    const char **arr = calloc(aliases.count, sizeof(char *));
    for (NSUInteger i = 0; i < aliases.count; i++) arr[i] = aliases[i].UTF8String;
    int rc = sc_sam_file_set_user([self samPath].UTF8String, owner.UTF8String,
                                  arr, aliases.count, nt);
    free(arr);
    memset(nt, 0, sizeof(nt));
    if (rc < 0) {
        rdp_error("nla: could not write %s (%s)", [self samPath].UTF8String, strerror(errno));
        return NO;
    }
    if (rc == 1 || !quiet)
        rdp_info("nla: %s NLA credential for '%s' (%lu name forms) in %s",
                 rc == 1 ? "stored" : "already current:", owner.UTF8String,
                 (unsigned long)aliases.count, [self samPath].UTF8String);
    return YES;
}

+ (void)removeNlaEntriesForUser:(NSString *)user {
    NSDictionary *acct = [Authenticator accountInfoForName:user];
    const char *path = [self samPath].UTF8String;
    int n = user.length ? sc_sam_file_remove(path, user.UTF8String) : 0;
    NSString *shortName = acct[@"short"];
    if (shortName && [shortName caseInsensitiveCompare:user] != NSOrderedSame) {
        int m = sc_sam_file_remove(path, shortName.UTF8String);
        if (m > 0) n += m;
    }
    if (n > 0)
        rdp_info("nla: removed %d stored NLA entr%s for '%s' — next connect falls back to TLS logon",
                 n, n == 1 ? "y" : "ies", user.UTF8String);
}

/* ── audit log ── */

+ (void)auditEvent:(NSString *)event ip:(NSString *)ip user:(NSString *)user
             proto:(NSString *)proto result:(NSString *)result
            reason:(NSString *)reason duration:(NSTimeInterval)duration {
    static NSLock *auditLock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ auditLock = [[NSLock alloc] init]; });

    NSString * (^clean)(NSString *) = ^NSString *(NSString *s) {
        NSMutableString *m = [NSMutableString string];
        for (NSUInteger i = 0; i < s.length; i++) {
            unichar c = [s characterAtIndex:i];
            if (c < 0x20 || c == '"' || c == 0x7F) c = '_';
            [m appendString:[NSString stringWithCharacters:&c length:1]];
        }
        return m;
    };
    char ts[40];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tmv);

    NSMutableString *line = [NSMutableString stringWithFormat:
        @"%s ip=%@ user=\"%@\" proto=%@ event=%@ result=%@",
        ts, clean(ip ?: @"-"), clean(user.length ? user : @"-"),
        proto.length ? proto : @"-", event, result];
    if (reason.length) [line appendFormat:@" reason=\"%@\"", clean(reason)];
    if (duration >= 0) [line appendFormat:@" duration=%llds", (long long)duration];

    rdp_info("audit: %s", [line substringFromIndex:strlen(ts) + 1].UTF8String);

    const char *override = getenv("RDP_AUDIT_LOG");
    NSString *path = (override && *override)
        ? [NSString stringWithUTF8String:override]
        : [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/macos-rdp-connections.log"];
    [auditLock lock];
    [[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent
                              withIntermediateDirectories:YES attributes:nil error:nil];
    if (sc_audit_append(path.UTF8String, line.UTF8String, kAuditMaxBytes) != 0)
        rdp_error("audit: could not append to %s (%s)", path.UTF8String, strerror(errno));
    [auditLock unlock];
}

/* ── CLI ── */

+ (NSString *)cliAccountName:(NSString *)user {
    return user.length ? user : owner_name();
}

+ (int)runSetNlaPassword:(NSString *)user {
    NSString *name = [self cliAccountName:user];
    NSDictionary *acct = [Authenticator accountInfoForName:name];
    if (!acct) {
        fprintf(stderr, "error: no local account named '%s'\n", name.UTF8String);
        return 1;
    }
    if ([self nlaMode] == RDPNlaModeOff)
        fprintf(stderr, "note: RDP_NLA=off is set in this environment; the daemon will not offer NLA "
                        "until it is auto or require.\n");
    char prompt[256];
    snprintf(prompt, sizeof(prompt), "Mac password for '%s': ", [acct[@"short"] UTF8String]);
    char buf[512];
    if (!readpassphrase(prompt, buf, sizeof(buf), RPP_REQUIRE_TTY)) {
        fprintf(stderr, "error: could not read a password (a terminal is required)\n");
        return 1;
    }
    NSString *pw = [NSString stringWithUTF8String:buf];
    memset_s(buf, sizeof(buf), 0, sizeof(buf));
    if (pw.length == 0) { fprintf(stderr, "error: empty password\n"); return 1; }

    if (![Authenticator strictValidateUsername:acct[@"short"] password:pw domain:nil]) {
        fprintf(stderr, "error: that password is not correct for '%s'\n", [acct[@"short"] UTF8String]);
        return 1;
    }
    if (![self storeNlaHashForAccount:acct typed:name password:pw quiet:NO]) return 1;
    NSString *why = nil;
    if (![self isUserAllowed:name info:acct reason:&why])
        fprintf(stderr, "note: %s — it can store an NLA credential but cannot log in "
                        "(see RDP_ALLOWED_USERS / RDP_ALLOWED_GROUP)\n", why.UTF8String);
    printf("NLA credential stored for '%s' in %s\n", [acct[@"short"] UTF8String],
           [self samPath].UTF8String);
    return 0;
}

+ (int)runClearNla:(NSString *)user {
    NSString *name = [self cliAccountName:user];
    const char *path = [self samPath].UTF8String;
    NSDictionary *acct = [Authenticator accountInfoForName:name];
    int n = sc_sam_file_remove(path, name.UTF8String);
    if (n < 0) {
        fprintf(stderr, "error: could not update %s (%s)\n", path, strerror(errno));
        return 1;
    }
    NSString *shortName = acct[@"short"];
    if (shortName && [shortName caseInsensitiveCompare:name] != NSOrderedSame) {
        int m = sc_sam_file_remove(path, shortName.UTF8String);
        if (m > 0) n += m;
    }
    if (n > 0) printf("Removed %d NLA entr%s for '%s' from %s\n", n, n == 1 ? "y" : "ies",
                      name.UTF8String, path);
    else       printf("No NLA entry for '%s' in %s\n", name.UTF8String, path);
    return 0;
}

@end

/* ── SecurityConnection ──────────────────────────────────────────────────── */

@interface SecurityConnection () {
    _Atomic uint64_t _lastInput;
    CFAbsoluteTime   _connectTime;
    NSTimeInterval   _idleLimit;      /* RDP_IDLE_TIMEOUT_MIN in seconds, 0 = off */
    NSString        *_user;
    NSString        *_proto;
    NSString        *_samPathKeep;
    BOOL             _authenticated;
    BOOL             _logonSeen;
    BOOL             _nlaOffered;
}
@end

static uint64_t now_ns(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW); }

@implementation SecurityConnection

- (instancetype)initWithAddress:(NSString *)ip {
    if ((self = [super init])) {
        _address     = [ip copy];
        _proto       = @"-";
        _connectTime = CFAbsoluteTimeGetCurrent();
        _idleLimit   = [SecurityPolicy idleTimeoutSeconds];
        atomic_store_explicit(&_lastInput, now_ns(), memory_order_relaxed);
    }
    return self;
}

- (NSString *)protocolName { return _proto; }
- (BOOL)authenticated      { return _authenticated; }

- (void)noteInput {
    atomic_store_explicit(&_lastInput, now_ns(), memory_order_relaxed);
}

- (void)markActive { [self noteInput]; }

- (BOOL)idleTimeoutExceeded {
    NSTimeInterval limit = _idleLimit;
    if (limit <= 0) return NO;
    uint64_t last = atomic_load_explicit(&_lastInput, memory_order_relaxed);
    return (now_ns() - last) > (uint64_t)(limit * 1e9);
}

- (NSTimeInterval)elapsed { return CFAbsoluteTimeGetCurrent() - _connectTime; }

- (void)getNlaMode:(int *)mode samPath:(NSString **)samPath {
    RDPNlaMode m = [SecurityPolicy nlaMode];
    _samPathKeep = [SecurityPolicy samPath];
    *samPath = _samPathKeep;
    *mode = 0;
    if (m == RDPNlaModeOff || [SecurityPolicy noAuthEffective]) return;

    size_t count = 0;
    int chk = sc_sam_file_check(_samPathKeep.UTF8String, &count);
    if (chk == -2)
        rdp_error("nla: %s is not a regular file owned by this user — ignoring it",
                  _samPathKeep.UTF8String);

    if (m == RDPNlaModeRequire) {
        if (count == 0)
            rdp_error("nla: RDP_NLA=require but %s has no entries — this connection cannot "
                      "authenticate (run --set-nla-password)", _samPathKeep.UTF8String);
        *mode = 2;
        _nlaOffered = YES;
        return;
    }
    if (count == 0) return;     /* auto: nothing learned yet → TLS only */

    init_state();
    [g_lock lock];
    int fallback = sc_lockout_remaining(g_nlaFail, ip_key(_address).UTF8String, time(NULL));
    [g_lock unlock];
    if (fallback > 0) {
        rdp_info("nla: %s had repeated NLA failures — offering TLS only for %d more s so the "
                 "credential can be re-learned", _address.UTF8String, fallback);
        return;
    }
    *mode = 1;
    _nlaOffered = YES;
}

- (void)auditLogon:(NSString *)result user:(NSString *)user reason:(NSString *)reason {
    [SecurityPolicy auditEvent:@"logon" ip:_address user:user proto:_proto
                        result:result reason:reason duration:[self elapsed]];
}

- (BOOL)handleLogonNla:(BOOL)nla selectedProtocol:(uint32_t)protocol
                  user:(NSString *)user domain:(NSString *)domain password:(NSString *)password {
    _logonSeen = YES;
    _proto = [NSString stringWithUTF8String:protocol_name(protocol)];
    rdp_info("security: %s negotiated security protocol %s%s", _address.UTF8String,
             _proto.UTF8String, nla ? " (CredSSP credentials received)" : "");
    if (!nla) return YES;       /* TLS/RDP: credentials arrive later, see authenticateWithUser: */
    return [self verifyUser:user password:password domain:domain viaNla:YES];
}

- (BOOL)authenticateWithUser:(NSString *)user password:(NSString *)password
                      domain:(NSString *)domain {
    if (_authenticated) {
        rdp_verbose("authentication already completed via NLA for %s — skipping password prompt check",
                    _address.UTF8String);
        return YES;
    }
    return [self verifyUser:user password:password domain:domain viaNla:NO];
}

- (BOOL)verifyUser:(NSString *)user password:(NSString *)password
            domain:(NSString *)domain viaNla:(BOOL)nla {
    if ([Authenticator authenticationDisabled]) {
        _authenticated = YES;
        _user = user.length ? user : @"(no-auth)";
        [self auditLogon:@"success" user:_user reason:@"RDP_ALLOW_NO_AUTH (loopback)"];
        return YES;
    }

    int ulock = [SecurityPolicy lockedSecondsForUser:user address:_address];
    if (ulock > 0) {
        rdp_error("authentication REFUSED for %s: account '%s' is locked out for %d more s",
                  _address.UTF8String, user.UTF8String, ulock);
        [self auditLogon:@"failure" user:user reason:@"account locked out"];
        self.endReason = @"account locked out";
        return NO;
    }

    BOOL ok = [Authenticator strictValidateUsername:user password:password domain:domain];
    if (!ok) {
        [SecurityPolicy recordFailureForAddress:_address user:user];
        NSString *why = @"wrong password or unknown user";
        if (nla) {
            why = @"NLA credential stale or wrong (Mac password changed?)";
            [SecurityPolicy removeNlaEntriesForUser:user];
        }
        rdp_error("authentication FAILED for %s (user='%s', %s)", _address.UTF8String,
                  user.length ? user.UTF8String : "(none)", why.UTF8String);
        [self auditLogon:@"failure" user:user reason:why];
        self.endReason = @"authentication failed";
        return NO;
    }

    NSDictionary *acct = [Authenticator accountInfoForName:user];
    NSString *why = nil;
    if (![SecurityPolicy isUserAllowed:user info:acct reason:&why]) {
        [SecurityPolicy recordFailureForAddress:_address user:user];
        rdp_error("authentication REJECTED for %s: %s", _address.UTF8String, why.UTF8String);
        [self auditLogon:@"failure" user:user reason:why ?: @"user not allowed"];
        self.endReason = @"user not allowed";
        return NO;
    }

    [SecurityPolicy recordSuccessForAddress:_address user:user];
    _authenticated = YES;
    _user = acct[@"short"] ?: user;
    rdp_info("authentication OK for %s (user='%s', via %s)", _address.UTF8String,
             _user.UTF8String, nla ? "NLA" : "TLS logon");
    [self auditLogon:@"success" user:_user reason:nil];

    /* Learn the NLA credential from a verified TLS-path logon so the next
     * connection can use NLA. Only when the daemon would actually offer it. */
    if (!nla && [SecurityPolicy nlaMode] != RDPNlaModeOff)
        [SecurityPolicy storeNlaHashForAccount:acct typed:user password:password quiet:YES];
    return YES;
}

- (void)finishWithSelectedProtocol:(uint32_t)selectedProtocol serverEnded:(BOOL)serverEnded {
    if (_proto.length <= 1 && selectedProtocol != 0)
        _proto = [NSString stringWithUTF8String:protocol_name(selectedProtocol)];

    /* NLA was negotiated but CredSSP never completed (wrong/stale NTLM hash, user
     * cancelled the credential prompt, probe). Count it as a failed attempt for
     * the address and, after two, offer TLS-only so a stale hash can heal. */
    if (_nlaOffered && !_logonSeen && !serverEnded && (selectedProtocol & (kProtoNLA | kProtoNLAEX))) {
        init_state();
        [g_lock lock];
        int locked = sc_lockout_fail(g_nlaFail, ip_key(_address).UTF8String, time(NULL));
        [g_lock unlock];
        [SecurityPolicy recordFailureForAddress:_address user:nil];
        if (locked)
            rdp_info("nla: repeated NLA failures from %s — next connection gets TLS-only so the "
                     "credential can be re-learned", _address.UTF8String);
        [self auditLogon:@"failure" user:nil reason:@"NLA authentication failed or aborted"];
        if (!self.endReason) self.endReason = @"NLA authentication failed or aborted";
    }

    NSString *reason = self.endReason;
    if (!reason) {
        if (!_logonSeen)            reason = @"closed before logon";
        else if (!_authenticated)   reason = @"closed before authentication completed";
        else if (serverEnded)       reason = @"disconnected by server (takeover or shutdown)";
        else                        reason = @"client disconnected";
    }
    [SecurityPolicy auditEvent:@"disconnect" ip:_address user:_user proto:_proto
                        result:(_authenticated ? @"ended" : @"unauthenticated")
                        reason:reason duration:[self elapsed]];
}

@end
