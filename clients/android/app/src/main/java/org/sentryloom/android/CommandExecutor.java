package org.sentryloom.android;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.UserManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

final class CommandExecutor {
    private final Context context;
    private final DevicePolicyManager policy;
    private final ComponentName admin;
    private final SecurityEventStore events;

    CommandExecutor(Context context) {
        this.context = context;
        this.policy = context.getSystemService(DevicePolicyManager.class);
        this.admin = new ComponentName(context, SentryDeviceAdminReceiver.class);
        this.events = new SecurityEventStore(context);
    }

    JSONObject execute(JSONObject command) throws Exception {
        String type = command.getString("type");
        switch (type) {
            case "scan.quick":
            case "scan.apps":
                return scanPackages();
            case "inventory.refresh":
                return new AndroidProtectionEngine(context).runProtectionCycle()
                        .put("refreshedAt", TelemetryCollector.isoNow());
            case "protection.restart":
                return new AndroidProtectionEngine(context).runProtectionCycle()
                        .put("restartedAt", TelemetryCollector.isoNow());
            case "device.lock":
                requireAdmin();
                policy.lockNow();
                return new JSONObject().put("lockedAt", TelemetryCollector.isoNow());
            case "device.reboot":
                requireDeviceOwner();
                // The acknowledgement is posted before reboot by the connector.
                return new JSONObject().put("rebootRequired", true);
            case "policy.bluetooth-sharing.block":
                requireOwner();
                policy.addUserRestriction(admin, UserManager.DISALLOW_BLUETOOTH_SHARING);
                return new JSONObject().put("bluetoothSharingBlocked", true);
            case "policy.bluetooth-sharing.allow":
                requireOwner();
                policy.clearUserRestriction(admin, UserManager.DISALLOW_BLUETOOTH_SHARING);
                return new JSONObject().put("bluetoothSharingBlocked", false);
            case "policy.camera.block":
                requireOwner();
                policy.setCameraDisabled(admin, true);
                return new JSONObject().put("cameraDisabled", true);
            case "policy.camera.allow":
                requireOwner();
                policy.setCameraDisabled(admin, false);
                return new JSONObject().put("cameraDisabled", false);
            case "policy.screen-capture.block":
                requireOwner();
                policy.setScreenCaptureDisabled(admin, true);
                return new JSONObject().put("screenCaptureDisabled", true);
            case "policy.screen-capture.allow":
                requireOwner();
                policy.setScreenCaptureDisabled(admin, false);
                return new JSONObject().put("screenCaptureDisabled", false);
            case "policy.unknown-sources.block":
                requireOwner();
                policy.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES);
                return new JSONObject().put("unknownSourcesBlocked", true);
            case "policy.unknown-sources.allow":
                requireOwner();
                policy.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES);
                return new JSONObject().put("unknownSourcesBlocked", false);
            case "policy.safe-boot.block":
                requireDeviceOwner();
                policy.addUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT);
                return new JSONObject().put("safeBootBlocked", true);
            case "policy.safe-boot.allow":
                requireDeviceOwner();
                policy.clearUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT);
                return new JSONObject().put("safeBootBlocked", false);
            case "policy.factory-reset.block":
                requireDeviceOwner();
                policy.addUserRestriction(admin, UserManager.DISALLOW_FACTORY_RESET);
                return new JSONObject().put("factoryResetBlocked", true);
            case "policy.factory-reset.allow":
                requireDeviceOwner();
                policy.clearUserRestriction(admin, UserManager.DISALLOW_FACTORY_RESET);
                return new JSONObject().put("factoryResetBlocked", false);
            case "policy.usb-data.block":
                requireDeviceOwner();
                if (Build.VERSION.SDK_INT < 31) {
                    throw new UnsupportedOperationException("USB data signaling control requires Android 12");
                }
                policy.setUsbDataSignalingEnabled(false);
                return new JSONObject().put("usbDataSignalingEnabled", false);
            case "policy.usb-data.allow":
                requireDeviceOwner();
                if (Build.VERSION.SDK_INT < 31) {
                    throw new UnsupportedOperationException("USB data signaling control requires Android 12");
                }
                policy.setUsbDataSignalingEnabled(true);
                return new JSONObject().put("usbDataSignalingEnabled", true);
            default:
                throw new SecurityException("HQ command is not allowed on Android: " + type);
        }
    }

    boolean shouldReboot(JSONObject command, JSONObject result) {
        return "device.reboot".equals(command.optString("type")) &&
                result.optBoolean("rebootRequired");
    }

    void reboot() {
        requireDeviceOwner();
        policy.reboot(admin);
    }

    private JSONObject scanPackages() throws Exception {
        String scanId = java.util.UUID.randomUUID().toString();
        events.startScan(scanId, "apps");
        events.record(
                "scan.started", "info", "Installed application integrity scan started",
                new JSONObject().put("scanId", scanId)
        );
        PackageManager manager = context.getPackageManager();
        long flags = PackageManager.GET_PERMISSIONS |
                (Build.VERSION.SDK_INT >= 28
                        ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        List<PackageInfo> packages = Build.VERSION.SDK_INT >= 33
                ? manager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
                : manager.getInstalledPackages((int) flags);
        List<PackageInfo> sorted = new ArrayList<>(packages);
        sorted.sort(Comparator.comparing(item -> item.packageName));
        JSONArray reports = new JSONArray();
        int scanned = 0;
        int errors = 0;
        int riskSignals = 0;
        for (PackageInfo item : sorted) {
            ApplicationInfo application = item.applicationInfo;
            if (application == null || application.sourceDir == null) continue;
            try {
                File apk = new File(application.sourceDir);
                boolean system = (application.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                boolean debuggable = (application.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                String installer = Build.VERSION.SDK_INT >= 30
                        ? manager.getInstallSourceInfo(item.packageName).getInstallingPackageName()
                        : manager.getInstallerPackageName(item.packageName);
                JSONArray risks = new JSONArray();
                if (debuggable && !system) risks.put("debuggable-release");
                if (!system && installer == null) risks.put("unknown-installer");
                if (application.targetSdkVersion < 28) risks.put("legacy-target-sdk");
                riskSignals += risks.length();
                reports.put(new JSONObject()
                        .put("package", item.packageName)
                        .put("versionName", item.versionName)
                        .put("apkSize", apk.length())
                        .put("sha256", sha256(apk))
                        .put("signerSha256", signerSha256(item))
                        .put("installer", installer)
                        .put("targetSdk", application.targetSdkVersion)
                        .put("requestedPermissionCount",
                                item.requestedPermissions == null ? 0 : item.requestedPermissions.length)
                        .put("riskSignals", risks)
                        .put("system", system));
                scanned++;
            } catch (Exception error) {
                errors++;
            }
            if (reports.length() >= 500) break;
        }
        JSONObject result = new JSONObject()
                .put("scanId", scanId)
                .put("type", "apps")
                .put("scanned", scanned)
                .put("detections", 0)
                .put("riskSignals", riskSignals)
                .put("errors", errors)
                .put("endedAt", TelemetryCollector.isoNow())
                .put("packages", reports);
        events.finishScan(scanId, result, "completed");
        events.record(
                "scan.completed", riskSignals > 0 ? "warning" : "info",
                "Installed application integrity scan completed",
                new JSONObject().put("scanId", scanId)
                        .put("scanned", scanned)
                        .put("riskSignals", riskSignals)
                        .put("errors", errors)
        );
        return result;
    }

    private String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (FileInputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) >= 0) digest.update(buffer, 0, count);
        }
        StringBuilder result = new StringBuilder(64);
        for (byte value : digest.digest()) {
            result.append(String.format(Locale.ROOT, "%02x", value));
        }
        return result.toString();
    }

    private String signerSha256(PackageInfo item) {
        try {
            android.content.pm.Signature[] signatures = Build.VERSION.SDK_INT >= 28
                    ? modernSignatures(item) : item.signatures;
            if (signatures.length == 0) return null;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] value = digest.digest(signatures[0].toByteArray());
            StringBuilder result = new StringBuilder(64);
            for (byte part : value) result.append(String.format(Locale.ROOT, "%02x", part));
            return result.toString();
        } catch (Exception ignored) {
            return null;
        }
    }

    @android.annotation.TargetApi(28)
    private android.content.pm.Signature[] modernSignatures(PackageInfo item) {
        if (item.signingInfo == null) return new android.content.pm.Signature[0];
        return item.signingInfo.hasMultipleSigners()
                ? item.signingInfo.getApkContentsSigners()
                : item.signingInfo.getSigningCertificateHistory();
    }

    private void requireAdmin() {
        if (!policy.isAdminActive(admin)) {
            throw new SecurityException("Device Administrator access is required");
        }
    }

    private void requireDeviceOwner() {
        if (!policy.isDeviceOwnerApp(context.getPackageName())) {
            throw new SecurityException("Device Owner provisioning is required");
        }
    }

    private void requireOwner() {
        if (!policy.isDeviceOwnerApp(context.getPackageName()) &&
                !policy.isProfileOwnerApp(context.getPackageName())) {
            throw new SecurityException("Device Owner or Profile Owner provisioning is required");
        }
    }
}
