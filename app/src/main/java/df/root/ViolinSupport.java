package df.root;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.os.Build;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;

final class ViolinSupport {
    static final String MANAGER = "me.weishu.kernelsu";
    private static final String KERNEL = "6.6.77-android15-8-g561b227c0e7d-abogki425270610-4k";
    private static final String APK_HASH = "480c52b8e8caf65a25f927028ff50e50c4fb5a762ea361406d6d6992233e3b31";
    static boolean isViolin() { return "violin".equals(Build.DEVICE); }
    static File directory(Context context) { return new File(context.getDataDir(), "violin"); }
    private static String read(File file) throws Exception {
        return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8).trim();
    }
    static boolean ready(Context context) {
        try {
            String boot = read(new File("/proc/sys/kernel/random/boot_id"));
            return boot.equals(read(new File(directory(context), "ready.boot")))
                    && boot.equals(read(new File(directory(context), "binder-ready.boot")));
        }
        catch (Exception e) { return false; }
    }
    private static String sha256(InputStream in) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[16384]; int count;
        while ((count = in.read(buffer)) != -1) digest.update(buffer, 0, count);
        StringBuilder hex = new StringBuilder();
        for (byte b : digest.digest()) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return hex.toString();
    }
    static void validateManager(Context context, String selected) throws Exception {
        if (!KERNEL.equals(System.getProperty("os.version")))
            throw new IllegalStateException("This violin firmware/kernel has not been validated; stopping");
        if (!MANAGER.equals(selected)) throw new IllegalStateException("violin requires official KernelSU 3.1.0");
        PackageInfo manager = context.getPackageManager().getPackageInfo(MANAGER, 0);
        if (manager.getLongVersionCode() != 32302)
            throw new IllegalStateException("Install official KernelSU v3.1.0 (32302); 3.3.1 is blocked on violin");
        try (InputStream in = new FileInputStream(manager.applicationInfo.sourceDir)) {
            if (!APK_HASH.equals(sha256(in))) throw new IllegalStateException("Manager APK SHA-256 mismatch");
        }
    }
    static void stage(Context context) throws Exception {
        File dir = directory(context);
        if (!dir.isDirectory() && !dir.mkdir()) throw new IllegalStateException("Cannot create violin directory");
        stageAsset(context, "kernelsu310.ko", "48afa2e0c7ce6b310bd2885c99e0a3276672f3c7fa2f597a011610fd9c989fb3", false);
        stageAsset(context, "ksud310", "3c4da894bf2f0a09b5e666d1bb52ab346225e804260713f9fa635c4b52867b46", true);
    }
    private static void stageAsset(Context context, String name, String hash, boolean executable) throws Exception {
        File dest = new File(directory(context), name);
        File tmp = new File(directory(context), name + ".tmp");
        try (InputStream in = context.getAssets().open("violin/" + name);
             FileOutputStream out = new FileOutputStream(tmp)) {
            byte[] buffer = new byte[16384]; int n;
            while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
            out.getFD().sync();
        }
        try (InputStream in = new FileInputStream(tmp)) {
            if (!hash.equals(sha256(in))) { tmp.delete(); throw new IllegalStateException("Bad payload hash: " + name); }
        }
        Files.move(tmp.toPath(), dest.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        if (executable && !dest.setExecutable(true, true)) throw new IllegalStateException("Cannot chmod " + name);
    }
    static void repairList(Context context) throws Exception {
        validateManager(context, MANAGER);
        String boot = read(new File("/proc/sys/kernel/random/boot_id"));
        if (!ready(context)) throw new IllegalStateException("No successful recovery for this boot. Do not repeat module loading");
        boolean listenerReady;
        try { listenerReady = boot.equals(read(new File(directory(context), "listener.boot"))); }
        catch (Exception e) { listenerReady = false; }
        // The native parent writes ready.boot just before its listener child starts.
        for (int i = 0; !listenerReady && i < 20; i++) {
            Thread.sleep(50);
            try { listenerReady = boot.equals(read(new File(directory(context), "listener.boot"))); }
            catch (Exception ignored) { }
        }
        if (!listenerReady) {
            String binary = new File(context.getApplicationInfo().nativeLibraryDir, "libbootstrap.so").getAbsolutePath();
            String quoted = "'" + binary.replace("'", "'\\''") + "' --violin-list";
            Process process = new ProcessBuilder("su", "-c", quoted).redirectErrorStream(true).start();
            if (!process.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly(); throw new IllegalStateException("Timed out starting list helper");
            }
            if (process.exitValue() != 0)
                throw new IllegalStateException("Authorize DFRoot in KernelSU to restart the expired list helper");
            for (int i = 0; i < 20; i++) {
                try { if (boot.equals(read(new File(directory(context), "listener.boot")))) break; }
                catch (Exception ignored) { }
                Thread.sleep(50);
            }
            if (!boot.equals(read(new File(directory(context), "listener.boot"))))
                throw new IllegalStateException("List helper did not become ready");
        }
        File request = new File(directory(context), "list.request");
        try (FileOutputStream out = new FileOutputStream(request)) { out.write(boot.getBytes(StandardCharsets.UTF_8)); }
        request.setReadable(false, false); request.setReadable(true, true);
        request.setWritable(false, false); request.setWritable(true, true);
        Intent launch = context.getPackageManager().getLaunchIntentForPackage(MANAGER);
        if (launch == null) throw new IllegalStateException("Manager launch activity missing");
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); context.startActivity(launch);
    }
    static String logs(Context context) {
        try {
            String boot = read(new File("/proc/sys/kernel/random/boot_id"));
            File dir = directory(context);
            StringBuilder log = new StringBuilder();
            for (File file : new File[]{new File(new File(dir, boot), "bootstrap.log"), new File(dir, "list-helper.log")}) {
                if (!file.exists()) continue;
                String text = read(file);
                log.append("\n--- ").append(file.getName()).append(" ---\n")
                    .append(text.substring(Math.max(0, text.length() - 12000))).append('\n');
            }
            return log.toString();
        } catch (Exception e) { return "Could not read local log: " + e.getMessage(); }
    }
}
