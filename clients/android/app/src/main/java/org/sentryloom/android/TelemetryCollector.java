package org.sentryloom.android;

import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import android.os.UserManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

final class TelemetryCollector {
    private final Context context;
    private final EndpointState state;
    private final DevicePolicyManager policy;
    private final ComponentName admin;
    private final SecurityEventStore events;
    private final AndroidProtectionEngine protection;

    TelemetryCollector(Context context) {
        this.context = context;
        this.state = new EndpointState(context);
        this.policy = context.getSystemService(DevicePolicyManager.class);
        this.admin = new ComponentName(context, SentryDeviceAdminReceiver.class);
        this.events = new SecurityEventStore(context);
        this.protection = new AndroidProtectionEngine(context);
    }

    JSONObject collect() throws Exception {
        boolean deviceOwner = policy.isDeviceOwnerApp(context.getPackageName());
        boolean profileOwner = policy.isProfileOwnerApp(context.getPackageName());
        boolean adminActive = policy.isAdminActive(admin);
        JSONArray features = features(deviceOwner, profileOwner, adminActive);
        JSONArray commands = commands(deviceOwner, profileOwner, adminActive);
        JSONObject system = system(deviceOwner, profileOwner, adminActive);
        JSONObject security = security(deviceOwner, profileOwner, adminActive);
        JSONArray history = events.scanHistory(20);
        JSONObject lastScan = history.length() > 0 ? history.getJSONObject(0) : null;
        JSONArray recentEvents = events.recentEvents(100);

        return new JSONObject()
                .put("schemaVersion", 3)
                .put("sentAt", isoNow())
                .put("device", new JSONObject()
                        .put("installationId", state.installationId())
                        .put("name", Build.MANUFACTURER + " " + Build.MODEL)
                        .put("hostname", Build.DEVICE)
                        .put("platform", "Android " + Build.VERSION.RELEASE +
                                " (API " + Build.VERSION.SDK_INT + ")")
                        .put("appVersion", EndpointState.VERSION)
                        .put("family", "android")
                        .put("architecture", Build.SUPPORTED_ABIS.length > 0
                                ? Build.SUPPORTED_ABIS[0] : "unknown")
                        .put("capabilities", features)
                        .put("supportedCommands", commands))
                .put("capabilities", new JSONObject()
                        .put("features", features)
                        .put("commands", commands))
                .put("system", system)
                .put("security", security)
                .put("policy", new JSONObject()
                        .put("ownership", system.getJSONObject("management"))
                        .put("backgroundServiceEnabled", state.serviceEnabled())
                        .put("controls", controls(deviceOwner, profileOwner, adminActive)))
                .put("protection", new JSONObject()
                        .put("running", state.serviceEnabled())
                        .put("android", protection.status()
                                .put("packageInventory", true)
                                .put("apkHashAndSignerScanning", true)
                                .put("applicationChangeMonitoring", true)
                                .put("networkChangeMonitoring", true)
                                .put("securityPostureMonitoring", true)
                                .put("usageVisibility", usageAccess())
                                .put("arbitraryFileAccess", false)
                                .put("note", "Personal files remain protected by Android scoped storage")))
                .put("signatures", new JSONObject()
                        .put("version", "android-package-integrity-v2")
                        .put("hashCount", 0)
                        .put("patternCount", 0)
                        .put("networkIocCount", 0)
                        .put("analysis", "APK SHA-256, signing certificate, installer, permissions and risk signals"))
                .put("scan", new JSONObject()
                        .put("active", JSONObject.NULL)
                        .put("progress", JSONObject.NULL)
                        .put("last", lastScan == null ? JSONObject.NULL : lastScan)
                        .put("history", history))
                .put("controls", controls(deviceOwner, profileOwner, adminActive))
                .put("quarantine", new JSONArray())
                .put("runtime", new JSONObject()
                        .put("uptimeSeconds", SystemClock.elapsedRealtime() / 1000)
                        .put("rssBytes", Runtime.getRuntime().totalMemory() -
                                Runtime.getRuntime().freeMemory())
                        .put("heapUsedBytes", Runtime.getRuntime().totalMemory() -
                                Runtime.getRuntime().freeMemory())
                        .put("lastTelemetryAt", state.lastTelemetryAt())
                        .put("lastCommandAt", state.lastCommandAt())
                        .put("lastError", state.lastError()))
                .put("clientUpdate", new JSONObject()
                        .put("state", "managed-by-android-package-installer")
                        .put("currentVersion", EndpointState.VERSION))
                .put("events", recentEvents)
                .put("audit", recentEvents);
    }

    private JSONArray features(boolean deviceOwner, boolean profileOwner, boolean adminActive) {
        JSONArray result = new JSONArray()
                .put("management.verified-enrollment")
                .put("management.allowlisted-commands")
                .put("telemetry.system")
                .put("telemetry.network")
                .put("telemetry.security")
                .put("telemetry.application-usage")
                .put("inventory.applications")
                .put("monitor.application-changes")
                .put("monitor.network-changes")
                .put("monitor.security-posture")
                .put("audit.hash-chain")
                .put("scan.installed-packages");
        if (adminActive) result.put("control.device-lock");
        if (deviceOwner || profileOwner) {
            result.put("control.bluetooth-sharing")
                    .put("control.camera")
                    .put("control.screen-capture")
                    .put("control.unknown-sources")
                    .put("android.enterprise-owner");
        }
        if (deviceOwner) {
            result.put("control.device-reboot")
                    .put("control.usb-data")
                    .put("control.safe-boot")
                    .put("control.factory-reset")
                    .put("android.device-owner");
        }
        return result;
    }

    private JSONArray commands(boolean deviceOwner, boolean profileOwner, boolean adminActive) {
        JSONArray result = new JSONArray()
                .put("scan.quick")
                .put("scan.apps")
                .put("inventory.refresh")
                .put("protection.restart");
        if (adminActive) result.put("device.lock");
        if (deviceOwner || profileOwner) {
            result.put("policy.bluetooth-sharing.block")
                    .put("policy.bluetooth-sharing.allow")
                    .put("policy.camera.block")
                    .put("policy.camera.allow")
                    .put("policy.screen-capture.block")
                    .put("policy.screen-capture.allow")
                    .put("policy.unknown-sources.block")
                    .put("policy.unknown-sources.allow");
        }
        if (deviceOwner) {
            result.put("device.reboot")
                    .put("policy.usb-data.block")
                    .put("policy.usb-data.allow")
                    .put("policy.safe-boot.block")
                    .put("policy.safe-boot.allow")
                    .put("policy.factory-reset.block")
                    .put("policy.factory-reset.allow");
        }
        return result;
    }

    private JSONObject security(boolean deviceOwner, boolean profileOwner, boolean adminActive)
            throws Exception {
        int score = 100;
        JSONArray issues = new JSONArray();
        if (!adminActive) {
            score -= 15;
            issues.put(issue("device-admin-inactive", "medium",
                    "Device administrator is not enabled",
                    "Remote lock requires Device Administrator access."));
        }
        if (!deviceOwner && !profileOwner) {
            score -= 10;
            issues.put(issue("not-enterprise-owned", "info",
                    "App is not an Android Enterprise owner",
                    "Advanced policy controls require Device Owner or Profile Owner provisioning."));
        }
        if (!state.serviceEnabled()) {
            score -= 20;
            issues.put(issue("management-service-stopped", "high",
                    "Background protection is stopped",
                    "Start protection to restore monitoring, telemetry and remote actions."));
        }
        if (!usageAccess()) {
            score -= 3;
            issues.put(issue("usage-access", "info",
                    "Application usage access is not granted",
                    "Grant Usage Access to report recently active applications."));
        }
        JSONObject platform = protection.securityPosture();
        score = Math.min(score, platform.optInt("score", score));
        JSONArray platformIssues = platform.optJSONArray("issues");
        if (platformIssues != null) {
            for (int index = 0; index < platformIssues.length(); index++) {
                issues.put(platformIssues.optJSONObject(index));
            }
        }
        return new JSONObject()
                .put("score", Math.max(0, score))
                .put("grade", score >= 90 ? "Excellent" : score >= 75 ? "Good" : "Needs attention")
                .put("state", score >= 90 ? "good" : score >= 60 ? "warning" : "critical")
                .put("issues", issues)
                .put("quarantineCount", 0)
                .put("platform", platform)
                .put("audit", events.auditStatus());
    }

    private JSONObject issue(String id, String severity, String title, String detail)
            throws Exception {
        return new JSONObject().put("id", id).put("severity", severity)
                .put("title", title).put("detail", detail).put("fixable", false);
    }

    private JSONObject system(boolean deviceOwner, boolean profileOwner, boolean adminActive)
            throws Exception {
        ActivityManager activity = context.getSystemService(ActivityManager.class);
        ActivityManager.MemoryInfo memory = new ActivityManager.MemoryInfo();
        activity.getMemoryInfo(memory);
        BatteryManager battery = context.getSystemService(BatteryManager.class);
        StatFs internal = new StatFs(Environment.getDataDirectory().getAbsolutePath());

        return new JSONObject()
                .put("operatingSystem", new JSONObject()
                        .put("description", "Android " + Build.VERSION.RELEASE)
                        .put("apiLevel", Build.VERSION.SDK_INT)
                        .put("securityPatch", Build.VERSION.SECURITY_PATCH)
                        .put("buildId", Build.ID)
                        .put("baseOs", Build.VERSION.BASE_OS)
                        .put("bootloader", Build.BOOTLOADER)
                        .put("fingerprint", Build.FINGERPRINT))
                .put("hardware", new JSONObject()
                        .put("manufacturer", Build.MANUFACTURER)
                        .put("brand", Build.BRAND)
                        .put("model", Build.MODEL)
                        .put("device", Build.DEVICE)
                        .put("product", Build.PRODUCT)
                        .put("board", Build.BOARD)
                        .put("hardware", Build.HARDWARE)
                        .put("abis", new JSONArray(Build.SUPPORTED_ABIS))
                        .put("logicalProcessors", Runtime.getRuntime().availableProcessors())
                        .put("totalMemoryBytes", memory.totalMem)
                        .put("availableMemoryBytes", memory.availMem)
                        .put("lowMemory", memory.lowMemory))
                .put("storage", new JSONArray().put(new JSONObject()
                        .put("mount", Environment.getDataDirectory().getAbsolutePath())
                        .put("totalBytes", internal.getTotalBytes())
                        .put("availableBytes", internal.getAvailableBytes())
                        .put("usedBytes", internal.getTotalBytes() - internal.getAvailableBytes())))
                .put("battery", new JSONObject()
                        .put("percentage", battery.getIntProperty(
                                BatteryManager.BATTERY_PROPERTY_CAPACITY))
                        .put("charging", battery.isCharging())
                        .put("chargeCounterMicroAh", battery.getLongProperty(
                                BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER))
                        .put("currentNowMicroA", battery.getLongProperty(
                                BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)))
                .put("network", network())
                .put("management", new JSONObject()
                        .put("deviceAdmin", adminActive)
                        .put("deviceOwner", deviceOwner)
                        .put("profileOwner", profileOwner)
                        .put("organizationOwned", Build.VERSION.SDK_INT >= 30 &&
                                policy.isOrganizationOwnedDeviceWithManagedProfile())
                        .put("encryptionStatus", policy.getStorageEncryptionStatus())
                        .put("securityLoggingEnabled", deviceOwner &&
                                policy.isSecurityLoggingEnabled(admin)))
                .put("usageAccess", usageAccess())
                .put("recentApplicationUsage", recentUsage())
                .put("applications", applications());
    }

    private JSONObject network() throws Exception {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        Network active = manager.getActiveNetwork();
        NetworkCapabilities capabilities = active == null
                ? null : manager.getNetworkCapabilities(active);
        LinkProperties links = active == null ? null : manager.getLinkProperties(active);
        JSONArray addresses = new JSONArray();
        JSONArray dns = new JSONArray();
        if (links != null) {
            links.getLinkAddresses().forEach(item -> addresses.put(item.toString()));
            for (InetAddress address : links.getDnsServers()) dns.put(address.getHostAddress());
        }
        boolean privateDnsActive = Build.VERSION.SDK_INT >= 28 &&
                links != null && links.isPrivateDnsActive();
        Object privateDnsServer = Build.VERSION.SDK_INT >= 28 && links != null
                ? links.getPrivateDnsServerName() : JSONObject.NULL;
        return new JSONObject()
                .put("connected", capabilities != null)
                .put("validated", capabilities != null && capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED))
                .put("metered", manager.isActiveNetworkMetered())
                .put("vpn", capabilities != null && capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_VPN))
                .put("wifi", capabilities != null && capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_WIFI))
                .put("cellular", capabilities != null && capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_CELLULAR))
                .put("interface", links == null ? JSONObject.NULL : links.getInterfaceName())
                .put("privateDnsActive", privateDnsActive)
                .put("privateDnsServer", privateDnsServer)
                .put("httpProxy", links == null || links.getHttpProxy() == null
                        ? JSONObject.NULL : links.getHttpProxy().toString())
                .put("addresses", addresses)
                .put("dnsServers", dns);
    }

    private JSONObject controls(boolean deviceOwner, boolean profileOwner, boolean adminActive)
            throws Exception {
        boolean owner = deviceOwner || profileOwner;
        android.os.Bundle restrictions = owner ? policy.getUserRestrictions(admin) : new android.os.Bundle();
        return new JSONObject()
                .put("deviceAdmin", adminActive)
                .put("deviceOwner", deviceOwner)
                .put("profileOwner", profileOwner)
                .put("cameraDisabled", owner ? policy.getCameraDisabled(admin) : JSONObject.NULL)
                .put("screenCaptureDisabled", owner
                        ? policy.getScreenCaptureDisabled(admin) : JSONObject.NULL)
                .put("bluetoothSharingRestricted", owner
                        ? restrictions.getBoolean(UserManager.DISALLOW_BLUETOOTH_SHARING, false)
                        : JSONObject.NULL)
                .put("unknownSourcesRestricted", owner
                        ? restrictions.getBoolean(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, false)
                        : JSONObject.NULL)
                .put("safeBootRestricted", deviceOwner
                        ? restrictions.getBoolean(UserManager.DISALLOW_SAFE_BOOT, false)
                        : JSONObject.NULL)
                .put("factoryResetRestricted", deviceOwner
                        ? restrictions.getBoolean(UserManager.DISALLOW_FACTORY_RESET, false)
                        : JSONObject.NULL)
                .put("usbDataSignalingEnabled", deviceOwner && Build.VERSION.SDK_INT >= 31
                        ? policy.isUsbDataSignalingEnabled() : JSONObject.NULL);
    }

    private JSONArray applications() throws Exception {
        PackageManager manager = context.getPackageManager();
        long flags = PackageManager.GET_PERMISSIONS |
                (Build.VERSION.SDK_INT >= 28
                        ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        List<PackageInfo> packages = Build.VERSION.SDK_INT >= 33
                ? manager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
                : manager.getInstalledPackages((int) flags);
        List<PackageInfo> sorted = new ArrayList<>(packages);
        sorted.sort(Comparator.comparing(item -> item.packageName));
        JSONArray result = new JSONArray();
        for (PackageInfo item : sorted.subList(0, Math.min(250, sorted.size()))) {
            ApplicationInfo application = item.applicationInfo;
            boolean system = application != null &&
                    (application.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            boolean debuggable = application != null &&
                    (application.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            long versionCode = Build.VERSION.SDK_INT >= 28
                    ? item.getLongVersionCode() : item.versionCode;
            String installer = Build.VERSION.SDK_INT >= 30
                    ? manager.getInstallSourceInfo(item.packageName).getInstallingPackageName()
                    : manager.getInstallerPackageName(item.packageName);
            JSONArray permissions = new JSONArray();
            if (item.requestedPermissions != null) {
                for (String permission : item.requestedPermissions) {
                    permissions.put(permission);
                    if (permissions.length() >= 40) break;
                }
            }
            JSONArray risks = new JSONArray();
            if (debuggable && !system) risks.put("debuggable-release");
            if (!system && installer == null) risks.put("unknown-installer");
            if (application != null && application.targetSdkVersion < 28) {
                risks.put("legacy-target-sdk");
            }
            result.put(new JSONObject()
                    .put("package", item.packageName)
                    .put("name", application == null ? item.packageName :
                            String.valueOf(manager.getApplicationLabel(application)))
                    .put("versionName", item.versionName)
                    .put("versionCode", versionCode)
                    .put("firstInstalledAt", item.firstInstallTime)
                    .put("lastUpdatedAt", item.lastUpdateTime)
                    .put("system", system)
                    .put("debuggable", debuggable)
                    .put("targetSdk", application == null
                            ? JSONObject.NULL : application.targetSdkVersion)
                    .put("signerSha256", signingCertificateSha256(item))
                    .put("requestedPermissions", permissions)
                    .put("riskSignals", risks)
                    .put("enabled", application == null || application.enabled)
                    .put("installer", installer));
        }
        return result;
    }

    private boolean usageAccess() {
        AppOpsManager operations = context.getSystemService(AppOpsManager.class);
        int mode = Build.VERSION.SDK_INT >= 29
                ? operations.unsafeCheckOpNoThrow(
                        AppOpsManager.OPSTR_GET_USAGE_STATS,
                        android.os.Process.myUid(),
                        context.getPackageName())
                : operations.checkOpNoThrow(
                        AppOpsManager.OPSTR_GET_USAGE_STATS,
                        android.os.Process.myUid(),
                        context.getPackageName());
        return mode == AppOpsManager.MODE_ALLOWED;
    }

    private JSONArray recentUsage() throws Exception {
        JSONArray result = new JSONArray();
        if (!usageAccess()) return result;
        UsageStatsManager manager = context.getSystemService(UsageStatsManager.class);
        long end = System.currentTimeMillis();
        List<UsageStats> records = manager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY, end - 24 * 60 * 60 * 1000, end
        );
        records.sort((left, right) -> Long.compare(
                right.getTotalTimeInForeground(), left.getTotalTimeInForeground()
        ));
        for (UsageStats record : records) {
            if (record.getTotalTimeInForeground() <= 0) continue;
            result.put(new JSONObject()
                    .put("package", record.getPackageName())
                    .put("foregroundMs", record.getTotalTimeInForeground())
                    .put("lastUsedAt", record.getLastTimeUsed()));
            if (result.length() >= 25) break;
        }
        return result;
    }

    private String signingCertificateSha256(PackageInfo item) {
        try {
            android.content.pm.Signature[] signatures = Build.VERSION.SDK_INT >= 28
                    ? modernSignatures(item) : item.signatures;
            if (signatures.length == 0) return null;
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(signatures[0].toByteArray());
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest) {
                result.append(String.format(Locale.ROOT, "%02x", value));
            }
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

    static String isoNow() {
        return java.time.Instant.now().toString();
    }
}
