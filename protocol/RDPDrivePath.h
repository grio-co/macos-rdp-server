#pragma once
/*
 * RDPDrivePath — pure text helpers for the redirected-drive bridge
 * (protocol/RDPWebDAV.c and the RDPDR IRP writers in protocol/RDPPeer.c).
 * No FreeRDP, no I/O; tested by tests/test_drivepath.c.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Percent-decodes in place. Returns false for a malformed escape or one that
 * decodes to NUL (the caller answers 400). */
bool rdp_url_decode(char *s);

/* The path of an absolute URL ("http://host:port/a/b" -> "/a/b", no path ->
 * ""); anything without "://" is returned as is. Points into url. */
const char *rdp_url_path_part(const char *url);

/* A decoded WebDAV URL path ("/a/b") as an MS-RDPEFS path relative to the
 * drive root: "" for the root, otherwise "\a\b" (leading backslash, none
 * trailing). Repeated and trailing '/' are dropped. Returns false for a
 * component that is "." or "..", or holds '\' or ':' (a Windows separator,
 * an NTFS stream name), or when the result does not fit. */
bool rdpdr_path_from_url(const char *urlPath, char *out, size_t outCap);

/* UTF-8 -> UTF-16LE with the terminating NUL, the form DR_CREATE_REQ and
 * DR_DRIVE_QUERY_DIRECTORY_REQ carry. Returns the byte count including the
 * NUL (the PathLength to send), or 0 for invalid UTF-8 or if it does not fit. */
size_t rdpdr_utf8_to_utf16le(const char *in, uint8_t *out, size_t outCap);

/* UTF-16LE (inBytes bytes; stops early at a NUL) -> NUL-terminated UTF-8.
 * An unpaired surrogate becomes U+FFFD. Returns false if it does not fit. */
bool rdpdr_utf16le_to_utf8(const uint8_t *in, size_t inBytes, char *out, size_t outCap);

/* Percent-encodes a URL path for a DAV:href, keeping A-Z a-z 0-9 - . _ ~ and '/'. */
bool rdp_url_path_encode(const char *in, char *out, size_t outCap);

/* Escapes & < > " ' for XML text. */
bool rdp_xml_escape(const char *in, char *out, size_t outCap);

/* A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as an HTTP date,
 * "Wed, 01 Jan 2025 00:00:00 GMT". 0 (unknown) and times before 1970 give
 * the Unix epoch. */
void rdp_http_date_from_filetime(uint64_t filetime, char *out, size_t outCap);

/* Standard base64 (RFC 4648 section 4) with '=' padding, NUL-terminated.
 * False if out is too small. */
bool rdp_base64_encode(const uint8_t *in, size_t inLen, char *out, size_t outCap);

/* Decodes standard base64; the '=' padding may be left off, nothing else
 * (no whitespace) is accepted. Returns the byte count, or -1 if the input is
 * invalid or doesn't fit. */
long rdp_base64_decode(const char *in, size_t inLen, uint8_t *out, size_t outCap);

/* True if an Authorization header value (len bytes, trimmed) is
 * "Basic <base64 of expectUserPass>". The scheme is case-insensitive; the
 * comparison takes the same time wherever the credentials differ. An empty
 * expectUserPass never matches. */
bool rdp_http_basic_auth_ok(const char *value, size_t len, const char *expectUserPass);
