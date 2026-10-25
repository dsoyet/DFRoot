#pragma once
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
/* 0: committed; 1: rolled back; -1: rollback failed. EOF, timeout, and any
 * unrecognized acknowledgement all roll back. Uses only inherited descriptors. */
static inline int violin_watchdog(int channel, int rollback, int timeout_ms) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return write(rollback, "0", 1) == 1 ? 1 : -1;
    long long deadline = (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000 + timeout_ms;
    struct pollfd fd = {.fd = channel, .events = POLLIN};
    int polled = 0;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) break;
        long long left = deadline - ((long long)now.tv_sec * 1000 + now.tv_nsec / 1000000);
        if (left <= 0) break;
        polled = poll(&fd, 1, (int)left);
        if (polled < 0 && errno == EINTR) continue;
        break;
    }
    char commit = 0;
    if (polled > 0 && read(channel, &commit, 1) == 1 && commit == 'C') return 0;
    return write(rollback, "0", 1) == 1 ? 1 : -1;
}
