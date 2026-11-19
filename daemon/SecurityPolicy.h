#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/* Authentication & session-security policy (see docs/security.md):
 *   NLA mode + SAM file, allowed users, lockout, listen address, idle timeout,
 *   connection audit log. Configuration comes from environment variables read
 *   at use time; --bind (main.m) overrides RDP_BIND_ADDRESS.
 * NEVER logs passwords or hashes. */

typedef NS_ENUM(int, RDPNlaMode) {
    RDPNlaModeOff     = 0,   /* RDP_NLA=off     TLS only                          */
    RDPNlaModeAuto    = 1,   /* RDP_NLA=auto    offer NLA when the SAM has entries */
    RDPNlaModeRequire = 2,   /* RDP_NLA=require refuse non-NLA clients             */
};

@interface SecurityPolicy : NSObject

/* ── Listen address / no-auth ── */
+ (void)setBindAddress:(nullable NSString *)addr;     /* --bind */
+ (nullable NSString *)bindAddress;                    /* --bind, else RDP_BIND_ADDRESS, else nil (dual-stack any) */
+ (BOOL)isLoopbackAddressString:(nullable NSString *)addr;  /* "localhost", 127/8, ::1, v4-mapped */
/* RDP_ALLOW_NO_AUTH=1 AND bound to loopback only. Logs an error once and
 * returns NO if the variable is set while bound elsewhere. */
+ (BOOL)noAuthEffective;
+ (void)logConfiguration;

/* ── NLA ── */
+ (RDPNlaMode)nlaMode;
+ (NSString *)samPath;

/* ── Lockout (per client IP / per username) ── */
+ (int)lockedSecondsForAddress:(NSString *)ip;        /* 0 = not locked; loopback never locked */

/* ── Idle timeout ── */
+ (NSTimeInterval)idleTimeoutSeconds;                 /* RDP_IDLE_TIMEOUT_MIN, 0 = off */

/* ── Audit log (~/Library/Logs/macos-rdp-connections.log) ── */
+ (void)auditEvent:(NSString *)event
                ip:(NSString *)ip
              user:(nullable NSString *)user
             proto:(nullable NSString *)proto
            result:(NSString *)result
            reason:(nullable NSString *)reason
          duration:(NSTimeInterval)duration;

/* ── Command line (return process exit codes) ── */
+ (int)runSetNlaPassword:(nullable NSString *)user;   /* --set-nla-password [user] */
+ (int)runClearNla:(nullable NSString *)user;         /* --clear-nla [user] */

@end

/* Per-connection security state. One per RDPSession. */
@interface SecurityConnection : NSObject

- (instancetype)initWithAddress:(NSString *)ip;

@property (nonatomic, readonly) NSString *address;
/* Negotiated security protocol name ("TLS", "NLA", "RDP", "-" until known). */
@property (nonatomic, readonly) NSString *protocolName;
@property (nonatomic, readonly) BOOL authenticated;
@property (nonatomic, copy, nullable) NSString *endReason;

/* Decide what to offer this client: *mode 0 = TLS only, 1 = NLA + TLS,
 * 2 = NLA only; *samPath is the SAM file for modes 1/2. The returned string is
 * kept alive by this object. */
- (void)getNlaMode:(int *)mode samPath:(NSString * _Nullable * _Nonnull)samPath;

/* Called from FreeRDP's Logon callback right after security negotiation (and,
 * for NLA, after CredSSP delivered the cleartext credentials). Returns NO if the
 * connection must be dropped. */
- (BOOL)handleLogonNla:(BOOL)nla
      selectedProtocol:(uint32_t)protocol
                  user:(nullable NSString *)user
                domain:(nullable NSString *)domain
              password:(nullable NSString *)password;

/* Called at activation (Client Info PDU credentials). NLA-authenticated
 * connections are already verified and pass straight through. */
- (BOOL)authenticateWithUser:(nullable NSString *)user
                    password:(nullable NSString *)password
                      domain:(nullable NSString *)domain;

- (void)noteInput;
- (void)markActive;
- (BOOL)idleTimeoutExceeded;

/* Final accounting when the session loop ends: NLA-incomplete handling plus the
 * disconnect audit line. `selectedProtocol` is the negotiated protocol mask
 * (0 if unknown); `ended` is YES if the server asked for the disconnect. */
- (void)finishWithSelectedProtocol:(uint32_t)selectedProtocol
                       serverEnded:(BOOL)serverEnded;

@end

NS_ASSUME_NONNULL_END
