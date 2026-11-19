#pragma once
#include <stdbool.h>

/*
 * Code-signature check for downloaded updates (and scripts/install-user.sh,
 * which uses the same requirement text).
 *
 * Accepted: a Developer ID Application signature (Apple anchor, Developer ID
 * intermediate and leaf certificate fields) from team FQKL8883DP, signing
 * identifier com.macosrdp.daemon, strictly valid for every architecture, with
 * the hardened runtime. An Apple Development or any other signature from the
 * same team is rejected: only release-signed builds may replace the daemon.
 */
#define UPDATE_REQUIREMENT                                                  \
    "anchor apple generic"                                                  \
    " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"             \
    " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"         \
    " and certificate leaf[subject.OU] = \"FQKL8883DP\""                    \
    " and identifier \"com.macosrdp.daemon\""

/* true if the file at `path` passes; otherwise false and, if `why` is not NULL,
 * a static reason string. */
bool update_verify_signature(const char *path, const char **why);
