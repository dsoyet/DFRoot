#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "violin_enforce.h"
#include "violin_ksu_policy.h"
#include "violin_selinux.h"
#include "violin_watchdog.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int apply_baseline(void) {
    int driver = -1;
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            char path[96], target[128];
            snprintf(path, sizeof(path), "/proc/self/fd/%.24s", entry->d_name);
            ssize_t n = readlink(path, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = 0;
            if (strstr(target, "[ksu_driver]")) {
                driver = fcntl(atoi(entry->d_name), F_DUPFD_CLOEXEC, 0); break;
            }
        }
        closedir(dir);
    }
    if (driver < 0) {
        /* Official KSU fd-install handshake, NOT a reboot: both magic values
         * are invalid Linux reboot magic. Without KSU the syscall fails EINVAL. */
        syscall(__NR_reboot, 0xDEADBEEFUL, 0xCAFEBABEUL, 0, &driver);
        if (driver >= 0) fcntl(driver, F_SETFD, FD_CLOEXEC);
    }
    if (driver < 0) return -1;
    struct { uint32_t version, flags, features; } info = {0};
    if (ioctl(driver, _IOC(_IOC_READ, 'K', 2, 0), &info) || info.version != 32302) {
        close(driver); return -1;
    }
    struct { uint32_t cmd, subcmd; const char *args[7]; } policy = {0};
    struct { uint64_t cmd, arg; } request = {0, (uint64_t)(uintptr_t)&policy};
    for (size_t i = 0; i < sizeof(violin_ksu_base_policy) / sizeof(*violin_ksu_base_policy); i++) {
        const struct violin_policy_rule *rule = &violin_ksu_base_policy[i];
        policy.cmd = rule->cmd; policy.subcmd = rule->subcmd;
        memcpy(policy.args, rule->args, sizeof(rule->args));
        if (ioctl(driver, _IOC(_IOC_READ | _IOC_WRITE, 'K', 4, 0), &request)) {
            printf("STOP: baseline ioctl %zu cmd=%u failed errno=%d\n", i, rule->cmd, errno);
            close(driver); return -1;
        }
    }
    close(driver); puts("KernelSU 3.1.0 atomic baseline: every ioctl succeeded"); return 0;
}

static int number(const char *path, uint32_t *out) {
    char text[48], *end;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, text, sizeof(text) - 1); close(fd);
    if (n <= 0) return -1;
    text[n] = 0; unsigned long v = strtoul(text, &end, 10);
    if (end == text || v > UINT32_MAX || (*end && *end != '\n')) return -1;
    *out = (uint32_t)v; return 0;
}
static int synchronized_mode(unsigned int expected) {
    uint32_t enforce;
    struct violin_selinux_status a, b;
    int fd = open("/sys/fs/selinux/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int valid = 0;
    for (int i = 0; i < 20; i++) {
        ssize_t n = pread(fd, &a, sizeof(a), 0), m = pread(fd, &b, sizeof(b), 0);
        if (n == (ssize_t)sizeof(a) && m == n &&
            violin_status_valid_mode(&a, (size_t)n, expected) && !memcmp(&a, &b, sizeof(a))) {
            valid = 1; break;
        }
        usleep(10000);
    }
    close(fd);
    return valid && !number("/sys/fs/selinux/enforce", &enforce) && enforce == expected ? 0 : -1;
}
static int access_decision(const char *source, const char *target, const char *klass,
                           const char *permission, int require_allow) {
    char path[160], request[384], response[256];
    uint32_t cls, mask;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", klass);
    if (number(path, &cls)) return -1;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/perms/%s", klass, permission);
    if (number(path, &mask) || !violin_permission_mask(mask)) return -1;
    mask = violin_permission_mask(mask);
    int size = snprintf(request, sizeof(request), "%s %s %u %x", source, target, cls, mask);
    if (size < 0 || (size_t)size >= sizeof(request)) return -1;
    int fd = open("/sys/fs/selinux/access", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t w = write(fd, request, (size_t)size);
    ssize_t n = w == size ? read(fd, response, sizeof(response) - 1) : -1;
    close(fd);
    if (n <= 0) return -1;
    response[n] = 0;
    unsigned int allowed, decided, auditallow, auditdeny, sequence, flags; char extra;
    if (sscanf(response, "%x %x %x %x %u %x %c", &allowed, &decided, &auditallow,
        &auditdeny, &sequence, &flags, &extra) != 6) return -1;
    int permitted = violin_explicit_access(allowed, mask);
    printf("Policy check %s -> %s %s/%s: allowed=%x flags=%x\n",
        source, target, klass, permission, allowed, flags);
    /* Never mistake permissive-domain bypass for an actual ingress allow rule. */
    return require_allow ? (permitted ? 0 : -1) : (!permitted && !(flags & 1) ? 0 : -1);
}
static int preflight(void) {
    const char *sources[] = {"untrusted_app", "system_server", "shell"};
    for (size_t i = 0; i < sizeof(sources) / sizeof(*sources); i++) {
        char context[96];
        snprintf(context, sizeof(context), "u:r:%s:s0", sources[i]);
        if (access_decision(context, "u:r:su:s0", "binder", "call", 1) ||
            access_decision(context, "u:r:su:s0", "binder", "transfer", 1) ||
            access_decision(context, "u:r:su:s0", "fd", "use", 1)) return -1;
    }
    return access_decision("u:r:servicemanager:s0", "u:r:su:s0", "process", "getattr", 1) ||
        access_decision("u:r:untrusted_app:s0", "u:r:untrusted_app:s0", "capability", "sys_admin", 0);
}
static int health(violin_run_command run) {
    const char *names[] = {"package", "activity", "user"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
        char output[256] = {0}, expected[96];
        int rc = run((char *[]){"/system/bin/service", "check", (char *)names[i], NULL}, output, sizeof(output), 5);
        snprintf(expected, sizeof(expected), "Service %s: found", names[i]);
        printf("Enforcing health: %s", output);
        if (rc || strncmp(output, expected, strlen(expected))) return -1;
    }
    char output[512] = {0};
    int rc = run((char *[]){"/system/bin/cmd", "package", "path", "android", NULL}, output, sizeof(output), 8);
    printf("Enforcing package command: exit=%d output=%s\n", rc, output);
    if (rc || strncmp(output, "package:", 8)) return -1;
    /* A native child changes its own context, verifies it, and attempts a real
     * read: do not depend on app-domain permission to exec shell_exec. */
    int control = open("/data/adb/ksud", O_RDONLY | O_CLOEXEC);
    if (control < 0) { printf("Enforcing su control open failed: errno=%d\n", errno); return -1; }
    char byte;
    ssize_t readable = read(control, &byte, 1); close(control);
    if (readable != 1) { printf("Enforcing su control read failed: bytes=%zd\n", readable); return -1; }
    pid_t canary = fork();
    if (canary < 0) return -1;
    if (!canary) {
        const char *app = "u:r:untrusted_app:s0";
        int attr = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
        if (attr < 0 || write(attr, app, strlen(app)) != (ssize_t)strlen(app)) _exit(2);
        close(attr);
        char label[128] = {0};
        attr = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
        if (attr < 0 || read(attr, label, sizeof(label) - 1) <= 0) _exit(2);
        close(attr);
        if (getuid() != 0 || strcmp(label, app)) _exit(2);
        int denied = open("/data/adb/ksud", O_RDONLY | O_CLOEXEC);
        if (denied >= 0) { close(denied); _exit(1); }
        _exit(errno == EACCES || errno == EPERM ? 0 : 2);
    }
    int result = 0; pid_t waited;
    do { waited = waitpid(canary, &result, 0); } while (waited < 0 && errno == EINTR);
    if (waited != canary || !WIFEXITED(result) || WEXITSTATUS(result)) {
        printf("Enforcing native canary failed: status=%d\n", result); return -1;
    }
    puts("Enforcing native canary: UID 0/untrusted_app denied adb data; su control read succeeded");
    return synchronized_mode(1);
}
int violin_restore_enforcing(const char *ksud, violin_run_command run) {
    if (getuid() != 0 || synchronized_mode(0)) return -1;
    (void)ksud;
    if (apply_baseline() || preflight()) { puts("STOP: enforcing policy preflight failed; remaining Permissive"); return -1; }
    /* The supervisor and watchdog must be in su, not init/shell, before enforcing.
     * Keeping an independent su child and preopened rollback FD prevents losing
     * rollback when the parent exits, hangs, or an exec/health check fails. */
    const char *context = "u:r:su:s0";
    int label = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (label < 0) return -1;
    ssize_t changed = write(label, context, strlen(context)); close(label);
    if (changed != (ssize_t)strlen(context)) return -1;
    int rollback = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    int signal[2];
    if (rollback < 0) return -1;
    if (pipe2(signal, O_CLOEXEC)) { close(rollback); return -1; }
    pid_t watcher = fork();
    if (watcher < 0) { close(rollback); close(signal[0]); close(signal[1]); return -1; }
    if (!watcher) {
        close(signal[1]);
        int outcome = violin_watchdog(signal[0], rollback, 45000);
        if (outcome) dprintf(STDERR_FILENO, "Enforcing watchdog: rollback to Permissive %s\n", outcome > 0 ? "done" : "FAILED");
        close(rollback); close(signal[0]); _exit(outcome >= 0 ? 0 : 1);
    }
    close(signal[0]);
    int enforce = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    int enabled = enforce >= 0 && write(enforce, "1", 1) == 1;
    if (enforce >= 0) close(enforce);
    int healthy = enabled && !health(run);
    if (healthy) healthy = write(signal[1], "C", 1) == 1;
    close(signal[1]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(watcher, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != watcher || !WIFEXITED(status) || WEXITSTATUS(status)) {
        lseek(rollback, 0, SEEK_SET);
        if (write(rollback, "0", 1) != 1) puts("CRITICAL: parent rollback failed");
        close(rollback); return -1;
    }
    close(rollback);
    if (!healthy) { puts("STOP: Enforcing health failed; watchdog restored Permissive"); return -1; }
    puts("Global SELinux Enforcing verified; su domain remains permissive (KernelSU baseline)");
    return 0;
}
