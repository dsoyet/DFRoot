# Xiaomi Pad 7S Pro (violin), experimental adaptation

This branch embeds the official **KernelSU v3.1.0** daemon and unpatched
`android15-6.6` module, downloaded and SHA-256 checked during the build.
It is restricted to the kernel below:

```
6.6.77-android15-8-g561b227c0e7d-abogki425270610-4k
```

The first device test confirmed module loading and UID 0 access, but exposed a
missing manager-discovery event: KernelSU displayed Not installed until its
official APK was reinstalled over itself. Version violin2 adds that step after
daemon initialization, checking the installed APK hash again and preserving its
data. The repair was verified live; the complete updated flow still needs a
fresh-boot device test. Version **4.8** merges restoration and list preparation
into the original **Launch Root** button and restores the upstream main layout.
Do not enable automatic boot execution;
the violin code path disables it, along with soft reboot and partition changes.

## 4.8.1 Binder initialization repair (device validation pending)

Diagnosis found kernel `enforce=0` while the shared SELinux status page still
reported `enforcing=1`. ServiceManager maps that page; its userspace AVC can
retain enforcing behavior even when kernel checks are permissive. The entry
module now resolves and calls `selinux_status_update_setenforce(false)` and
`selnl_notify_setenforce(0)` after the existing state change. This uses the
state-free Linux >= 6.4 ABI only; older kernel paths remain unchanged. No
enforcing interval, direct status-page edit, or ServiceManager restart is used.

Before loading KernelSU, violin validates a stable version-1 status snapshot
against `/sys/fs/selinux/enforce`. A mismatch stops initialization. Once the
pinned 3.1.0 module is loaded, the pinned daemon applies **only `permissive su`**,
the first rule in upstream `apply_kernelsu_rules()`. This is a targeted repair
of the demonstrated missing su-domain flag, not a replay of all early-boot
initialization. No wildcard allow rules or persistent policy files are added.
Since this ksud version can return zero even if applying a rule fails, the
bootstrap independently queries `/sys/fs/selinux/access` and requires the live
`SELINUX_AVD_FLAGS_PERMISSIVE` flag, then requires package/activity/user to be
visible from UID 0 in `u:r:su:s0`. All checks precede the new ready marker.

Install **4.8.1 over 4.8**, then manually reboot before testing Launch Root: a
previously loaded entry module cannot be updated in place. Old ready markers
alone no longer qualify as successful 4.8.1 initialization. The original
single-button layout and list-service compatibility helper are retained until
device regression testing establishes that the manager works without it.

This change was prepared without connecting to the tablet. Compilation and
offline tests do not prove Shizuku or InstallerX installation works. After the
next boot, verify normal su service access, the KernelSU list without invoking
the compatibility helper, Shizuku's normal Root start, and InstallerX Root and
Shizuku installs separately, including their Session commit/result callbacks.

Source references:
- [Linux 6.6 status synchronization](https://github.com/torvalds/linux/blob/v6.6/security/selinux/status.c)
- [Linux 6.6 setenforce notifications](https://github.com/torvalds/linux/blob/v6.6/security/selinux/selinuxfs.c)
- [KernelSU 3.1.0 su-domain initialization](https://github.com/tiann/KernelSU/blob/v3.1.0/kernel/selinux/rules.c)
- [KernelSU 3.1.0 non-strict CLI policy handling](https://github.com/tiann/KernelSU/blob/v3.1.0/userspace/ksud/src/sepolicy.rs)

## Use

Version **4.8.2** restores **global Enforcing** after daemon/manager setup. The
entry still temporarily uses Permissive while loading; it then replays the
KernelSU **3.1.0** `apply_kernelsu_rules()` baseline via the pinned daemon. This
includes su's permissive flag, attributes, ksu_file, ioctls, and incoming Binder/
FD rules; it is not `allow * * * *` and does not mark ordinary app domains
permissive. The upstream policy is embedded in `violin_ksu_policy.h`.

Before enforcing, raw access decisions must contain actual allow bits for app,
shell and system_server Binder/FD access to su. A nonpermissive untrusted_app
sys_admin denial must remain. A separate su-context watchdog holds a preopened
rollback descriptor and restores Permissive on parent exit, health failure or a
45-second timeout. The parent checks package/activity/user, cmd package, status
synchronization and a real UID-0/untrusted_app attempt to read adb data (must be
denied). Only then is Enforcing committed. Su remains domain-permissive, matching
KernelSU's baseline; global Enforcing is not a claim that every domain enforces.

The normal list workaround is not launched under Enforcing. Its diagnostic code
is retained. Runtime checks do not replace full app regression testing. An
explicit root-only `libbootstrap.so --violin-enforce` path can upgrade an already
initialized pinned 3.1.0 instance without reinserting the module or rebooting.
It performs the same preflight/watchdog/health checks, and is not a general
command execution endpoint. All runtime rules disappear on reboot.

1. Back up personal data. Install the Actions-built DFRoot APK. A debug APK has a
   different signing identity from upstream DFRoot: an existing upstream APK may
   need to be manually removed first. No installer automatically removes apps.
2. Install the unmodified official KernelSU **v3.1.0 (32302)** manager. Both version
   and APK hash are checked. Other managers and v3.3.1 are rejected on violin.
3. Select KernelSU in DFRoot and tap **Launch Root**.
   The existing DFRoot entry chain prepares privileged execution; the new
   bootstrap resolves symbols locally for this boot, validates and patches the
   module, loads it once, and initializes the matching daemon. It then reinstalls
   the already installed, hash-checked official manager over itself using
   `pm install -r` in the shell security domain. This preserves manager data and
   triggers KernelSU 3.1.0's package observer to recognize the manager. Running
   `boot-completed` alone does not perform that scan.
4. After successful initialization, the same action automatically prepares the
   list helper and opens KernelSU. Open the manager's **Superuser** tab. A bounded helper starts the
   official manager's list service in the working shell security domain and
   system mount namespace. The four connection attempts form a short repair
   window; if needed, return to DFRoot and tap **Launch Root** again. A successful
   same-boot initialization skips the entry chain and module loading, and only
   repeats list preparation. Failed initialization still prevents module retries.
5. Grant Root to individual apps in KernelSU. For an explicit check, authorize
   Shell and run `su -c id` from an ADB shell; UID 0 is the success criterion.
   Module initialization is reported separately from application authorization.

The list helper accepts only a fixed repair request from DFRoot's private data
directory. It performs no arbitrary requested command and exits after its
bounded 30-minute session. Authorize DFRoot itself in KernelSU after the first
successful recovery: the same Launch Root button can then use that normal authorization
to restart an expired list helper, without an exploit or module reload.

## Reboot and factory reset

After reboot, run the same manual restore flow. Symbol addresses are resolved
again; an old patched module is never bundled or reused. A factory reset removes
apps, saved permissions and data: reinstall both APKs and repeat the flow. This
still requires the same firmware to be vulnerable to DFRoot's entry chain.
An OTA or security fix may invalidate this method; a different kernel is blocked.

## Boundaries and logs

- No boot/partition flashing, bootloader unlocking, automatic reboot, or automatic
  authorization of all apps is implemented.
- No v3.3.1 KernelSU module is loaded on violin. Its syscall table write failed in
  the manual experiment; changing symbol addresses did not resolve that fault.
- The existing upstream entry exploit is retained. Changes in `lkm/dfroot.c`
  are not required by this adaptation, and its behavior must be tested separately.
- Existing third-party modules/common scripts stop the violin initialization.
- A per-boot exclusive attempt marker prevents repeated module insertion.
- `kptr_restrict` is restored after symbol capture, including dump failures.
- All real symbol addresses and device logs remain on the device. Actions only
  receives source code, official payload downloads and synthetic host tests.
- Initialization logs appear in the original output area; errors also append the
  local bootstrap/helper logs. No additional buttons are shown. Kernel logs and
  kallsyms remain in DFRoot's private `violin/<boot-id>/`
  directory. They are not included in Actions artifacts.

The class name `p7.d` is specific to the hash-checked official 3.1.0 APK. The
workaround does not modify that APK and does not claim to fix arbitrary managers.

## Build

Push this branch or use the **Build** workflow's manual trigger. Actions builds
the upstream DFRoot bootstrap modules, runs host-only ELF rejection tests,
checks native sources, fetches the pinned payloads and builds the Android APK.
Without release signing secrets it creates an installable debug APK and uploads
the **DFRoot** artifact. No public release is created for ordinary branch pushes.
Optional release signing uses the existing `KEYSTORE`, `KEYSTORE_PASSWORD`,
`KEY_ALIAS`, and `KEY_PASSWORD` repository secrets.

Host tests exercise valid patching, missing/zero/conflicting imports, module-only
symbols, corrupt bounds/strings and wrong architecture. They never load a module
or contain real device addresses.
