# Authentication and session security

Goal: connecting from Windows `mstsc` should feel (and be) as safe as connecting
to a Windows PC. Implementation: `daemon/SecurityPolicy.{h,m}` (policy and glue),
`daemon/SecurityCore.{h,c}` (pure C: NT hash, SAM file, lockout, audit log; unit
tested in `tests/test_security_core.c`), the Logon hook and TLS settings in
`protocol/RDPPeer.c`.

## NLA (CredSSP / NTLM)

`mstsc` requests NLA by default. The daemon offers it when
`~/.macos-rdp/nla.sam` (override `RDP_NLA_SAM_FILE`) holds an entry. FreeRDP's
NTLM server looks the user up in that file (`FreeRDP_NtlmSamFile`), checks the
client's NTLMv2 proof against the stored NT hash, and then receives the
client's delegated password over the CredSSP channel. The daemon **re-verifies
that cleartext password with OpenDirectory** (so NLA is only a pre-authentication
gate, and OpenDirectory stays the source of truth) and applies the allowed-user
and lockout rules. Clients that do not request NLA still negotiate TLS.

### SAM file

* Mode 0600 in a 0700 directory, owned by the daemon's user (a file owned by
  someone else, or a symlink, is ignored). Written atomically (temp file, fsync,
  rename) under an `flock`ed `nla.sam.lock`.
* One line per name: `alias:::NTHASH:owner:` (WinPR format `user:domain:lm:nt:::`;
  the trailing `owner` is the account's short name so all aliases are replaced or
  removed together). NT hash = MD4(UTF-16LE(password)). It is a password-equivalent
  for NTLM, so the file is as sensitive as the password: keep it mode 0600.
* WinPR matches the user name case-sensitively, so a login writes the short name,
  the full name, the name as typed, and lowercase variants.
* Never logged: passwords and hashes.

### How entries get there

1. **Automatically**: after a successful TLS-path logon whose password
   OpenDirectory verified (and that passed the allowed-user check), unless
   `RDP_NLA=off`. The next connection can use NLA.
2. `macos-rdp-daemon --set-nla-password [user]` prompts for the password
   (no echo, needs a terminal), verifies it with OpenDirectory, then writes it.
   `user` defaults to the account running the command.
3. `macos-rdp-daemon --clear-nla [user]` removes that user's entries.

### Password changed on the Mac (stale hash)

* Client types the **old** password: NTLM passes, the OpenDirectory re-check
  fails; the entry is removed and the connection refused. The next connection is
  TLS-only and relearns the new password on success.
* Client types the **new** password: NTLM fails (stale hash) before the daemon
  sees credentials. After two such NLA failures from one address within 10
  minutes the daemon offers TLS only to that address for 5 minutes, so the
  client's retry logs on over TLS and relearns the hash. (Not in `require` mode.)

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `RDP_NLA` | `auto` | `auto`: offer NLA when the SAM has an entry. `off`: TLS only, nothing learned. `require`: NLA only (TLS and legacy RDP security refused); the SAM must be populated with `--set-nla-password`. |
| `RDP_NLA_SAM_FILE` | `~/.macos-rdp/nla.sam` | SAM file path. |
| `RDP_ALLOWED_USERS` | (empty) | Comma list of extra account short names allowed to connect. |
| `RDP_ALLOWED_GROUP` | (empty) | Extra group whose members may connect (membership(3) lookup, nested groups included). |
| `RDP_LOCKOUT_THRESHOLD` | `5` | Failed logons within 10 min that trigger a lockout (1 to 32). |
| `RDP_LOCKOUT_MINUTES` | `15` | Lockout length; doubles on each repeat (cap 24 h; resets on success or 24 h of good behaviour). |
| `RDP_BIND_ADDRESS` | (any) | Listen address; `--bind <addr>` overrides. IPv4, IPv6, `localhost` (127.0.0.1 and ::1), host name. Default is IPv6 dual-stack any. |
| `RDP_ALLOW_NO_AUTH` | unset | `1` skips authentication, **only when bound to loopback**; otherwise logged as an error and ignored. For tests. |
| `RDP_IDLE_TIMEOUT_MIN` | `0` (off) | Disconnect after this many minutes without keyboard or mouse input. |
| `RDP_TLS_MIN` | `1.2` | Minimum TLS version for the RDP transport (`1.0`, `1.1`, `1.2`, `1.3`). |
| `RDP_AUDIT_LOG` | `~/Library/Logs/macos-rdp-connections.log` | Audit log path (mainly for tests). |

## Allowed users

By default only the account the daemon runs as (a LaunchAgent: the logged-in
user) may connect. The typed name is resolved through OpenDirectory, so the short
name or the full name both work; accounts are compared by UID and record names.
`RDP_ALLOWED_USERS` and `RDP_ALLOWED_GROUP` add more. Anyone else, even with a
valid Mac password, is rejected after authentication with a log line
(`authentication REJECTED ... not an allowed Remote Desktop user`) and counted as
a failed logon.

## Lockout

Failures (wrong password, stale NLA credential, disallowed user, NLA that never
completed) are counted per client IP and per username. `RDP_LOCKOUT_THRESHOLD`
failures in 10 minutes refuse that IP at `accept()` (socket closed, no FreeRDP
peer, no TLS) for `RDP_LOCKOUT_MINUTES`, doubling on repeats; the username is
locked for the same time. A successful logon resets the IP and user counters.
Loopback is never locked out. Lockouts are in memory and reset on daemon restart.
Trade-off: a remote attacker who fails five times against your username also
locks you out of that username for 15 minutes (the same as Windows).

## Idle timeout

`RDP_IDLE_TIMEOUT_MIN=n` disconnects a session that has had no keyboard or mouse
input for n minutes (`idle timeout` in the log and audit file). Clipboard, audio
and video traffic do not count as activity.

## Audit log

`~/Library/Logs/macos-rdp-connections.log` (mode 0600, rotated at 1 MB with one
`.1` kept; the same lines also go through the normal daemon log as `audit: ...`):

```
2026-11-19T12:00:00+0100 ip=192.168.1.20 user="grio" proto=NLA event=logon result=success duration=1s
2026-11-19T12:40:12+0100 ip=192.168.1.20 user="grio" proto=NLA event=disconnect result=ended reason="client disconnected" duration=2412s
2026-11-19T12:41:00+0100 ip=10.0.0.9 user="-" proto=- event=connect result=refused reason="locked out (640 s remaining)"
```

`event=logon` is one attempt (success or failure with a reason); `event=connect
result=refused` is a lockout refusal; `event=disconnect` carries the session
duration and the reason (client disconnected, idle timeout, disconnected by
server (takeover or shutdown), negotiation timeout, authentication failed, ...).

## TLS

FreeRDP 3.10.3 honours `FreeRDP_TLSMinVersion` (`tls.c`, `tls_prepare`), so the
RDP transport requires TLS 1.2 or newer by default. Windows 7 clients without the
TLS 1.2 update need `RDP_TLS_MIN=1.0`. Legacy "standard RDP security" remains
available as a last-resort negotiation fallback (except with `RDP_NLA=require`);
a client has to request it explicitly and `mstsc` never does.

## Verifying (mstsc)

1. NLA first connect: first connect is TLS (the Mac password is verified and the
   NLA credential learned; or run `--set-nla-password` first). Reconnect: the log
   shows `negotiated security protocol NLA` and no second password prompt.
2. TLS-only client (for example `mstsc` with "enable NLA" cleared via an `.rdp`
   file, or any non-NLA client): `negotiated security protocol TLS`.
3. Wrong user / not allowed: `authentication REJECTED`, audit `result=failure`.
4. Lockout: five wrong passwords from a non-loopback IP; the sixth connection is
   closed immediately and `refused connection ... locked out` is logged.
