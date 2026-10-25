#pragma once
#include <stddef.h>
#include <stdint.h>

/* Public SELinux status-page ABI: five native-endian uint32 fields. */
struct violin_selinux_status {
    uint32_t version, sequence, enforcing, policyload, deny_unknown;
};

static inline int violin_status_valid_mode(const struct violin_selinux_status *s, size_t bytes, uint32_t mode) {
    return bytes == sizeof(*s) && s->version == 1 && !(s->sequence & 1) &&
        mode <= 1 && s->enforcing == mode && s->deny_unknown <= 1;
}
static inline int violin_status_valid(const struct violin_selinux_status *s, size_t bytes) {
    return violin_status_valid_mode(s, bytes, 0);
}
static inline int violin_explicit_access(uint32_t allowed, uint32_t requested) {
    return requested && (allowed & requested) == requested;
}

/* Security server av_decision flags: SELINUX_AVD_FLAGS_PERMISSIVE = 1.
 * An allow bit alone is insufficient to prove the su-domain patch succeeded. */
static inline int violin_su_permissive(uint32_t flags) { return (flags & 1U) != 0; }
