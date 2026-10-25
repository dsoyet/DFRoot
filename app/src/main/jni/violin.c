#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "violin.h"
#include "violin_patch.h"
#include "violin_selinux.h"
#include "violin_enforce.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BASE "/data/user_de/0/df.root/violin"
#define KSUD BASE "/ksud310"
#define KO BASE "/kernelsu310.ko"
#define MANAGER "/data/user_de/0/me.weishu.kernelsu"
#define KERNEL "6.6.77-android15-8-g561b227c0e7d-abogki425270610-4k"
#define KO_HASH "48afa2e0c7ce6b310bd2885c99e0a3276672f3c7fa2f597a011610fd9c989fb3"
#define KSUD_HASH "3c4da894bf2f0a09b5e666d1bb52ab346225e804260713f9fa635c4b52867b46"
#define MANAGER_HASH "480c52b8e8caf65a25f927028ff50e50c4fb5a762ea361406d6d6992233e3b31"

/* Fixed argument vectors only: no app-supplied shell command is executed. */
static int command(char *const args[], char *output, size_t capacity, int seconds) {
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC)) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        setsid(); close(pipes[0]);
        if (output) {
            /* cmd passes all three FDs through Binder. The bootstrap log was
             * opened in toolbox before we entered su: inheriting that stderr
             * makes system_server reject the transaction under Enforcing.
             * Create all command FDs in the current context, including stdin. */
            int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (input < 0 || dup2(input, STDIN_FILENO) < 0 ||
                dup2(pipes[1], STDOUT_FILENO) < 0 || dup2(pipes[1], STDERR_FILENO) < 0) _exit(126);
            if (input != STDIN_FILENO) close(input);
        }
        close(pipes[1]); execv(args[0], args); _exit(127);
    }
    close(pipes[1]);
    if (pid < 0) { close(pipes[0]); return -1; }
    fcntl(pipes[0], F_SETFL, O_NONBLOCK);
    size_t used = 0;
    int status = 0, complete = 0;
    time_t deadline = time(NULL) + seconds;
    for (;;) {
        char buffer[4096];
        ssize_t n;
        while ((n = read(pipes[0], buffer, sizeof(buffer))) > 0) {
            if (output && used < capacity - 1) {
                size_t take = (size_t)n < capacity - 1 - used ? (size_t)n : capacity - 1 - used;
                memcpy(output + used, buffer, take); used += take;
            }
        }
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) { complete = 1; break; }
        if (w < 0 && errno != EINTR) break;
        if (time(NULL) >= deadline) break;
        usleep(20000);
    }
    if (!complete) { kill(-pid, SIGKILL); waitpid(pid, &status, 0); }
    if (output && complete) {
        ssize_t n;
        while (used < capacity - 1 && (n = read(pipes[0], output + used, capacity - 1 - used)) > 0)
            used += n;
    }
    close(pipes[0]);
    if (output) output[used] = 0;
    return complete && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
static int read_text(const char *path, char *text, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t n = read(fd, text, size - 1); close(fd);
    if (n <= 0) return -1;
    text[n] = 0; text[strcspn(text, "\r\n")] = 0; return 0;
}
static int write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) return -1;
    size_t size = strlen(text);
    int rc = write(fd, text, size) == (ssize_t)size ? 0 : -1;
    close(fd); return rc;
}
static int copy_file(const char *source, const char *target) {
    int in = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) return -1;
    int out = open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (out < 0) { close(in); return -1; }
    char buffer[16384]; ssize_t n; int rc = 0;
    while ((n = read(in, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < n) {
            ssize_t written = write(out, buffer + offset, n - offset);
            if (written <= 0) { rc = -1; break; }
            offset += written;
        }
        if (rc) break;
    }
    if (n < 0) rc = -1;
    close(in); if (close(out)) rc = -1;
    return rc;
}
int violin_device(void) {
    char value[128];
    return command((char *[]){"/system/bin/getprop", "ro.product.device", NULL}, value, sizeof(value), 5) == 0 &&
        strncmp(value, "violin\n", 7) == 0;
}
static int hash_matches(const char *path, const char *hash) {
    char value[1024];
    return command((char *[]){"/system/bin/sha256sum", (char *)path, NULL}, value, sizeof(value), 10) == 0 &&
        !strncmp(value, hash, 64) && value[64] == ' ';
}
static int selinux_synchronized(void) {
    struct violin_selinux_status first, second;
    int fd = open("/sys/fs/selinux/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int valid = 0;
    for (int i = 0; i < 20; i++) {
        ssize_t a = pread(fd, &first, sizeof(first), 0);
        ssize_t b = pread(fd, &second, sizeof(second), 0);
        if (a == (ssize_t)sizeof(first) && b == (ssize_t)sizeof(second) &&
            violin_status_valid(&first, (size_t)a) && !memcmp(&first, &second, sizeof(first))) {
            valid = 1; break;
        }
        usleep(10000);
    }
    close(fd);
    char enforce[16];
    if (!valid || read_text("/sys/fs/selinux/enforce", enforce, sizeof(enforce)) || strcmp(enforce, "0")) {
        puts("STOP: SELinux kernel/status mismatch or unreadable; reboot with the updated DFRoot entry module");
        return -1;
    }
    printf("SELinux status synchronized: version=%u sequence=%u enforcing=%u policyload=%u\n",
        first.version, first.sequence, first.enforcing, first.policyload);
    return 0;
}
static int su_domain_ready(void) {
    char class_text[32], perm_text[32], request[256], response[256];
    if (read_text("/sys/fs/selinux/class/service_manager/index", class_text, sizeof(class_text)) ||
        read_text("/sys/fs/selinux/class/service_manager/perms/find", perm_text, sizeof(perm_text))) return -1;
    char *end;
    unsigned long cls = strtoul(class_text, &end, 10);
    if (!cls || cls > 65535 || *end) return -1;
    unsigned long perm = strtoul(perm_text, &end, 10);
    if (!perm || perm > UINT32_MAX || *end) return -1;
    int size = snprintf(request, sizeof(request), "u:r:su:s0 u:object_r:package_service:s0 %lu %lx", cls, perm);
    int fd = open("/sys/fs/selinux/access", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t written = write(fd, request, (size_t)size);
    ssize_t n = written == size ? read(fd, response, sizeof(response) - 1) : -1;
    close(fd);
    if (n <= 0) return -1;
    response[n] = 0;
    unsigned int allowed, decided, auditallow, auditdeny, seqno, flags;
    char extra;
    if (sscanf(response, "%x %x %x %x %u %x %c", &allowed, &decided, &auditallow,
        &auditdeny, &seqno, &flags, &extra) != 6) return -1;
    printf("su/package_service decision: allowed=%x flags=%x sequence=%u\n", allowed, flags, seqno);
    return violin_su_permissive(flags) ? 0 : -1;
}
static int initialize_su_domain(void) {
    /* Exact first rule from upstream v3.1.0 apply_kernelsu_rules(), scoped to su.
     * No wildcard allow rules, changes to other domains, or policy file writes.
     * ksud 3.1.0 can return zero despite an ioctl failure: verify the live result. */
    int rc = command((char *[]){KSUD, "sepolicy", "patch", "permissive su", NULL}, NULL, 0, 15);
    printf("KernelSU su-domain initialization exit=%d\n", rc);
    if (rc || su_domain_ready() || selinux_synchronized()) {
        puts("STOP: KernelSU su-domain initialization not verified"); return -1;
    }
    const char *services[] = {"package", "activity", "user"};
    for (size_t i = 0; i < sizeof(services) / sizeof(*services); i++) {
        char result[256] = {0}, expected[128];
        int code = command((char *[]){"/system/bin/runcon", "u:r:su:s0", "/system/bin/service",
            "check", (char *)services[i], NULL}, result, sizeof(result), 5);
        snprintf(expected, sizeof(expected), "Service %s: found", services[i]);
        printf("su-context Binder check: %s", result);
        if (code || strncmp(result, expected, strlen(expected))) return -1;
    }
    return 0;
}
static int kernel_version(void) {
    char version[256];
    if (command((char *[]){KSUD, "debug", "version", NULL}, version, sizeof(version), 10)) return -1;
    printf("%s", version);
    if (strstr(version, "Kernel Version: 32302\n")) return 32302;
    return strstr(version, "Kernel Version: 0\n") ? 0 : -1;
}
static int directory_has_entries(const char *path) {
    DIR *d = opendir(path);
    if (!d) return errno == ENOENT ? 0 : 1;
    struct dirent *e; int found = 0;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) { found = 1; break; }
    closedir(d); return found;
}
static int refresh_manager(void) {
    char result[1024];
    if (command((char *[]){"/system/bin/runcon", "u:r:shell:s0", "/system/bin/pm",
        "path", "me.weishu.kernelsu", NULL}, result, sizeof(result), 15)) return -1;
    /* Only reinstall the already installed, pinned official manager. No download,
       data clearing, downgrade, or direct packages.list modification. */
    result[strcspn(result, "\r\n")] = 0;
    if (strncmp(result, "package:/data/app/", 18)) return -1;
    char *apk = result + strlen("package:");
    if (!hash_matches(apk, MANAGER_HASH)) return -1;
    int rc = command((char *[]){"/system/bin/runcon", "u:r:shell:s0", "/system/bin/pm",
        "install", "-r", apk, NULL}, NULL, 0, 60);
    printf("Refresh manager package (preserve data) exit=%d\n", rc);
    /* KernelSU 3.1.0 observes packages.list CREATE/MOVE to discover its manager.
       boot-completed calls track_throne(true), which does not discover one. */
    return rc;
}
static void repair_list(void) {
    struct stat manager, jar;
    if (stat(MANAGER, &manager) || manager.st_uid < 10000 ||
        lstat(MANAGER "/cache/main.jar", &jar) || !S_ISREG(jar.st_mode) ||
        jar.st_uid != manager.st_uid || jar.st_size < 1 || jar.st_size > 1048576) {
        puts("List repair: open KernelSU Superuser first (main.jar not ready)"); return;
    }
    char pid[64], uid[32];
    if (command((char *[]){"/system/bin/pidof", "system_server", NULL}, pid, sizeof(pid), 5)) return;
    pid[strcspn(pid, " \r\n")] = 0;
    for (const char *p = pid; *p; p++) if (*p < '0' || *p > '9') return;
    if (!*pid) return;
    snprintf(uid, sizeof(uid), "%u", manager.st_uid);
    setenv("CLASSPATH", MANAGER "/cache/main.jar", 1);
    unsetenv("LD_LIBRARY_PATH");
    /* Class name is tied to the hash-checked official 3.1.0 manager APK. */
    int rc = command((char *[]){"/system/bin/runcon", "u:r:shell:s0", "/system/bin/nsenter", "-t", pid,
        "-m", "--", "/system/bin/app_process64", "-Xnoimage-dex2oat", "/system/bin",
        "--nice-name=dfroot-violin-list", "com.topjohnwu.superuser.internal.RootServerMain",
        "me.weishu.kernelsu/p7.d", uid, "start", NULL}, NULL, 0, 20);
    printf("List helper exited %d (verify list in manager)\n", rc);
}
static void list_listener(const char *boot) {
    char current[64];
    int lock = open(BASE "/list-helper.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) { if (lock >= 0) close(lock); return; }
    pid_t child = fork();
    if (child != 0) { close(lock); return; }
    setsid();
    int log = open(BASE "/list-helper.log", O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW, 0644);
    if (log < 0) _exit(1);
    dup2(log, STDOUT_FILENO); dup2(log, STDERR_FILENO); close(log);
    setvbuf(stdout, NULL, _IONBF, 0);
    /* A bounded helper for one boot. Only a fixed list operation can be requested. */
    write_text(BASE "/listener.boot", boot);
    time_t end = time(NULL) + 1800;
    while (time(NULL) < end) {
        if (read_text("/proc/sys/kernel/random/boot_id", current, sizeof(current)) || strcmp(current, boot)) break;
        int request = open(BASE "/list.request", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (request >= 0) {
            struct stat owner, req;
            int valid = !stat("/data/user_de/0/df.root", &owner) && !fstat(request, &req) &&
                S_ISREG(req.st_mode) && req.st_uid == owner.st_uid && req.st_size <= 64;
            close(request); unlink(BASE "/list.request");
            if (valid) {
                puts("List repair window: open Superuser now");
                for (int i = 0; i < 4; i++) { repair_list(); sleep(2); }
            }
        }
        sleep(1);
    }
    write_text(BASE "/listener.boot", "stopped"); close(lock); _exit(0);
}
int violin_resume_list(void) {
    char boot[64], ready[64]; struct utsname u;
    if (getuid() != 0 || !violin_device() || uname(&u) || strcmp(u.release, KERNEL) ||
        read_text("/proc/sys/kernel/random/boot_id", boot, sizeof(boot)) ||
        read_text(BASE "/ready.boot", ready, sizeof(ready)) || strcmp(ready, boot) ||
        read_text(BASE "/binder-ready.boot", ready, sizeof(ready)) || strcmp(ready, boot) ||
        !hash_matches(KSUD, KSUD_HASH) || kernel_version() != 32302 ||
        selinux_synchronized() || su_domain_ready()) return 1;
    list_listener(boot); return 0;
}
int violin_enable_enforcing(void) {
    char boot[64], ready[64]; struct utsname u;
    /* Allows testing/upgrading the already loaded pinned module without another
     * exploit, module insertion, manager reinstall, or automatic reboot. */
    if (getuid() != 0 || !violin_device() || uname(&u) || strcmp(u.release, KERNEL) ||
        read_text("/proc/sys/kernel/random/boot_id", boot, sizeof(boot)) ||
        read_text(BASE "/ready.boot", ready, sizeof(ready)) || strcmp(ready, boot) ||
        !hash_matches(KSUD, KSUD_HASH) || kernel_version() != 32302 || su_domain_ready()) return 1;
    if (violin_restore_enforcing(KSUD, command)) return 1;
    return write_text(BASE "/enforcing-ready.boot", boot) ? 1 : 0;
}
int violin_bootstrap(void) {
    struct utsname u; char boot[64], path[512], kptr[32], same_boot[64];
    if (getuid() != 0 || uname(&u) || strcmp(u.release, KERNEL) || strcmp(u.machine, "aarch64") ||
        read_text("/proc/sys/kernel/random/boot_id", boot, sizeof(boot))) return 1;
    char state[64];
    if (command((char *[]){"/system/bin/getenforce", NULL}, state, sizeof(state), 5) ||
        strncmp(state, "Permissive\n", 11)) return 1;
    if (!hash_matches(KO, KO_HASH) || !hash_matches(KSUD, KSUD_HASH)) return 1;
    snprintf(path, sizeof(path), BASE "/%s", boot);
    if (mkdir(path, 0755) && errno != EEXIST) return 1;
    char logpath[640]; snprintf(logpath, sizeof(logpath), "%s/bootstrap.log", path);
    int log = open(logpath, O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW, 0644);
    if (log < 0) return 1;
    dup2(log, STDOUT_FILENO); dup2(log, STDERR_FILENO); close(log);
    setvbuf(stdout, NULL, _IONBF, 0); printf("violin 3.1.0 bootstrap boot=%s\n", boot);
    if (selinux_synchronized()) return 1;
    int version = kernel_version();
    if (version != 0 && version != 32302) return 1;
    if (version == 0) {
        char symbols[640], patched[640], attempt[128];
        snprintf(symbols, sizeof(symbols), "%s/kallsyms.txt", path);
        snprintf(patched, sizeof(patched), "%s/kernelsu-patched.ko", path);
        if (read_text("/proc/sys/kernel/kptr_restrict", kptr, sizeof(kptr))) return 1;
        int set = write_text("/proc/sys/kernel/kptr_restrict", "0");
        int dumped = set ? -1 : copy_file("/proc/kallsyms", symbols);
        int restored = write_text("/proc/sys/kernel/kptr_restrict", kptr);
        printf("kallsyms=%d kptr_restore=%d original=%s\n", dumped, restored, kptr);
        if (dumped || restored || violin_patch_module(KO, symbols, patched)) return 1;
        if (read_text("/proc/sys/kernel/random/boot_id", same_boot, sizeof(same_boot)) || strcmp(boot, same_boot)) return 1;
        snprintf(attempt, sizeof(attempt), "/dev/dfroot-violin-attempt-%s", boot);
        int once = open(attempt, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
        if (once < 0) { puts("Already attempted this boot; no retry"); return 1; }
        close(once);
        snprintf(logpath, sizeof(logpath), "%s/kernel-before.log", path);
        int dlog = open(logpath, O_CREAT | O_WRONLY | O_EXCL | O_NOFOLLOW, 0644);
        if (dlog < 0) return 1;
        pid_t logger = fork();
        if (logger == 0) { dup2(dlog, STDOUT_FILENO); dup2(dlog, STDERR_FILENO); close(dlog);
            execl("/system/bin/dmesg", "dmesg", "-w", NULL); _exit(127); }
        close(dlog);
        if (logger < 0) return 1;
        int fd = open(patched, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        int loaded = fd < 0 ? -1 : (int)syscall(__NR_finit_module, fd, "", 0);
        int saved = errno; if (fd >= 0) close(fd);
        printf("finit_module=%d errno=%d\n", loaded, loaded ? saved : 0);
        int healthy = loaded == 0 && kernel_version() == 32302 &&
            command((char *[]){"/system/bin/sh", "-c", "id; stat /system/bin/sh", NULL}, NULL, 0, 10) == 0;
        kill(logger, SIGTERM); waitpid(logger, NULL, 0);
        if (!healthy) { puts("STOP: module/system check failed; recover manually"); return 1; }
    }
    const char *dirs[] = {"/data/adb/modules", "/data/adb/post-fs-data.d", "/data/adb/service.d", "/data/adb/boot-completed.d"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(*dirs); i++) {
        if (directory_has_entries(dirs[i])) { printf("STOP: existing modules/scripts in %s\n", dirs[i]); return 1; }
    }
    struct stat existing;
    if (!stat("/data/adb/ksud", &existing)) {
        snprintf(logpath, sizeof(logpath), "%s/ksud-before", path);
        /* Preserve the first backup; never overwrite a prior run's backup. */
        if (access(logpath, F_OK) && copy_file("/data/adb/ksud", logpath)) return 1;
    }
    if (initialize_su_domain()) return 1;
    const char *stages[] = {"install", "post-fs-data", "services", "boot-completed"};
    for (size_t i = 0; i < sizeof(stages) / sizeof(*stages); i++) {
        int rc = command((char *[]){KSUD, (char *)stages[i], NULL}, NULL, 0, 60);
        printf("ksud %s exit=%d\n", stages[i], rc); if (rc) return 1;
    }
    if (refresh_manager()) { puts("STOP: manager package refresh failed"); return 1; }
    if (violin_restore_enforcing(KSUD, command)) return 1;
    if (write_text(BASE "/enforcing-ready.boot", boot) ||
        write_text(BASE "/binder-ready.boot", boot) || write_text(BASE "/ready.boot", boot)) return 1;
    puts("KernelSU 32302 ready with global SELinux Enforcing; open manager to authorize apps");
    return 0;
}
