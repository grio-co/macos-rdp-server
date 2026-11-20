#pragma once
/*
 * RDPWebDAV — embedded single-file WebDAV/HTTP server for RDPDR drive mounting.
 *
 * When a Windows client announces a redirected drive over the RDPDR channel,
 * the daemon starts one RDPWebDAVServer per drive.  Each server:
 *
 *   1. Binds a POSIX TCP socket on 127.0.0.1:<port>.
 *   2. Translates incoming DAV requests (PROPFIND/GET/PUT/DELETE/MKCOL) into
 *      MS-RDPEFS IRPs, sends them to the Windows client over the RDPDR channel,
 *      and waits for the IOCOMPLETION response.
 *   3. Returns the result as a well-formed HTTP/WebDAV response.
 *
 * macOS mounts the share via:
 *   /sbin/mount_webdav -S -a <fd> -v RDP-<letter> http://127.0.0.1:<port>/ ~/RDP-Drives/<letter>
 * No kext, no macFUSE, no brew dependencies.
 *
 * Every request needs the drive password (HTTP Basic, 401 otherwise): a
 * random one per drive, which only mount_webdav gets, through -a <fd>. So
 * other local processes and users can't reach the client's drive through
 * the loopback port; what they can reach through the mounted folder is up to
 * its permissions (the daemon creates ~/RDP-Drives as 0700).
 *
 * Thread model:
 *   - The accept loop runs on its own pthread (not the peer run loop).
 *   - IRP sends acquire xportLock, then RELEASE it before blocking on a
 *     condition variable (see irp_waiter in RDPWebDAV.c).  The run loop
 *     thread fires the callback which signals the cond var.
 */

#include <stdint.h>
#include <stdbool.h>
#include <freerdp/freerdp.h>

typedef struct RDPWebDAVServer RDPWebDAVServer;

/*
 * rdp_webdav_server_create — create and start a WebDAV server for one drive.
 *
 * peer     — the owning freerdp_peer (used to reach xportLock and the RDPDR
 *            channel for IRP sends).
 * deviceId — the RDPDR device id from DEVICE_LIST_ANNOUNCE.
 * driveName — the 8-byte DOS drive name from DEVICE_LIST_ANNOUNCE (NUL-terminated).
 * port     — TCP port to bind on 127.0.0.1; 0 picks a free one.
 *
 * Returns NULL on failure (bind error, pthread_create failure, etc.).
 * On success the accept loop is running.  Call rdp_webdav_mount() next to
 * invoke mount_webdav(8) and make the volume appear in Finder.
 */
RDPWebDAVServer *rdp_webdav_server_create(freerdp_peer *peer,
                                           uint32_t deviceId,
                                           const char *driveName,
                                           uint16_t port);

/*
 * rdp_webdav_server_destroy — stop the server and free all resources.
 *
 * Signals the accept thread to exit and waits for it (pthread_join).
 * Safe to call if rdp_webdav_mount() was never called or already failed.
 * The caller must have already called rdp_webdav_unmount() or accept that
 * the mount point is left dangling (OS will clean up on unmount).
 */
void rdp_webdav_server_destroy(RDPWebDAVServer *srv);

/*
 * rdp_webdav_mount — mount the WebDAV share in Finder.
 *
 * Creates ~/RDP-Drives/<letter> (a user can only mount on a directory it owns;
 * /Volumes is root's) and runs:
 *   /sbin/mount_webdav -S -a <fd> -v RDP-<letter> http://127.0.0.1:<port>/ ~/RDP-Drives/<letter>
 * where <fd> is an unlinked file holding the drive password.
 *
 * Runs on its own thread and returns at once: true if that thread started.
 * mount_webdav's PROPFIND needs IRP replies that the peer thread receives, so
 * the caller (the peer thread) must not wait for it. The result is logged.
 */
bool rdp_webdav_mount(RDPWebDAVServer *srv);

/*
 * rdp_webdav_drive_label — the client's DOS drive name as a safe path and
 * Finder name: trailing ':' and spaces dropped ("E:" -> "E"), '/' and ':'
 * replaced, and "", "." or ".." (the name comes from the client) -> "DRIVE".
 */
void rdp_webdav_drive_label(const char *dosName, char *out, size_t outLen);

/*
 * rdp_webdav_unmount — unmount the Finder volume and remove the mountpoint.
 *
 * Stops a mount still in progress and waits for its thread, then runs:
 *   diskutil unmount force ~/RDP-Drives/<letter>
 * Then: rmdir ~/RDP-Drives/<letter>
 * Both operations are best-effort; errors are logged but not fatal.
 */
void rdp_webdav_unmount(RDPWebDAVServer *srv);
