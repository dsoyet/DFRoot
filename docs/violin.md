# Xiaomi Pad 7S Pro (violin), experimental adaptation

This branch embeds the official **KernelSU v3.1.0** daemon and unpatched
`android15-6.6` module, downloaded and SHA-256 checked during the build.
It is restricted to the kernel below:

```
6.6.77-android15-8-g561b227c0e7d-abogki425270610-4k
```

This is an experimental integration of previously tested manual recovery steps.
Successful compilation does **not** establish that this version of DFRoot's
DirtyFrag entry chain works on violin. Do not enable automatic boot execution;
the violin code path disables it, along with soft reboot and partition changes.

## Use

1. Back up personal data. Install the Actions-built DFRoot APK. A debug APK has a
   different signing identity from upstream DFRoot: an existing upstream APK may
   need to be manually removed first. No installer automatically removes apps.
2. Install the unmodified official KernelSU **v3.1.0 (32302)** manager. Both version
   and APK hash are checked. Other managers and v3.3.1 are rejected on violin.
3. Select KernelSU in DFRoot and tap **Restore violin Root (3.1.0)**.
   The existing DFRoot entry chain prepares privileged execution; the new
   bootstrap resolves symbols locally for this boot, validates and patches the
   module, loads it once, and initializes the matching daemon.
4. After successful initialization, tap **Repair app list / Open KernelSU** and
   open the manager's **Superuser** tab immediately. A bounded helper starts the
   official manager's list service in the working shell security domain and
   system mount namespace. The four connection attempts form a short repair
   window; if needed, return to DFRoot and tap Repair again.
5. Grant Root to individual apps in KernelSU. For an explicit check, authorize
   Shell and run `su -c id` from an ADB shell; UID 0 is the success criterion.
   Module initialization is reported separately from application authorization.

The list helper accepts only a fixed repair request from DFRoot's private data
directory. It performs no arbitrary requested command and exits after its
bounded 30-minute session. Authorize DFRoot itself in KernelSU after the first
successful recovery: the Repair button can then use that normal authorization
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
- **Show local recovery logs** reads bootstrap and helper logs without uploading
  them. Kernel logs and kallsyms remain in DFRoot's private `violin/<boot-id>/`
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
