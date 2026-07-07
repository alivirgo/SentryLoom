package org.sentryloom.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

final class AndroidProtectionEngine {
    private static final String PREFS = "sentryloom_protection";
    private final Context context;
    private final SecurityEventStore events;
    private final SharedPreferences preferences;
    private ConnectivityManager.NetworkCallback networkCallback;

    AndroidProtectionEngine(Context context) {
        this.context = context;
        this.events = new SecurityEventStore(context);
        this.preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    void start() {
        if (networkCallback != null) return;
        if (!preferences.getBoolean("initialized", false)) {
            events.record(
                    "android.protection-started", "info",
                    "Android protection engine initialized",
                    object("version", EndpointState.VERSION)
            );
            preferences.edit().putBoolean("initialized", true).apply();
        } else {
            events.record(
                    "android.protection-resumed", "info",
                    "Android protection engine resumed", new JSONObject()
            );
        }
        registerNetworkMonitoring();
        runProtectionCycle();
    }

    void stop() {
        if (networkCallback != null) {
            try {
                context.getSystemService(ConnectivityManager.class)
                        .unregisterNetworkCallback(networkCallback);
            } catch (Exception ignored) {}
            networkCallback = null;
        }
        preferences.edit().putBoolean("networkMonitoring", false).apply();
        events.record(
                "android.protection-stopped", "warning",
                "Android protection engine stopped", new JSONObject()
        );
    }

    JSONObject runProtectionCycle() {
        int packageChanges = checkPackageBaseline();
        JSONObject posture = securityPosture();
        String postureHash = sha256(posture.toString());
        String previousPosture = preferences.getString("postureHash", "");
        if (!postureHash.equals(previousPosture)) {
            events.record(
                    "android.posture-changed",
                    posture.optJSONArray("issues").length() > 0 ? "warning" : "info",
                    "Android security posture changed",
                    object(
                            "score", posture.optInt("score"),
                            "issues", posture.optJSONArray("issues")
                    )
            );
            preferences.edit().putString("postureHash", postureHash).apply();
        }
        long cycles = preferences.getLong("cycles", 0) + 1;
        preferences.edit()
                .putLong("cycles", cycles)
                .putString("lastCycleAt", TelemetryCollector.isoNow())
                .apply();
        return object(
                "cycle", cycles,
                "packageChanges", packageChanges,
                "postureScore", posture.optInt("score"),
                "completedAt", TelemetryCollector.isoNow()
        );
    }

    JSONObject status() {
        return object(
                "running", new EndpointState(context).serviceEnabled(),
                "cycles", preferences.getLong("cycles", 0),
                "lastCycleAt", preferences.getString("lastCycleAt", null),
                "networkMonitoring", preferences.getBoolean("networkMonitoring", false),
                "packageChangeMonitoring", true,
                "applicationIntegrityBaseline", preferences.contains("packageBaseline"),
                "scopedStorage", true
        );
    }

    JSONObject securityPosture() {
        int score = 100;
        JSONArray issues = new JSONArray();
        boolean adbEnabled = setting(Settings.Global.ADB_ENABLED) == 1;
        boolean developerOptions = setting(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == 1;
        boolean encrypted = android.app.admin.DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ==
                context.getSystemService(android.app.admin.DevicePolicyManager.class)
                        .getStorageEncryptionStatus();
        boolean rooted = rootIndicators().length() > 0;
        if (adbEnabled) {
            score -= 10;
            issues.put(issue("adb-enabled", "medium", "USB/Wireless debugging is enabled"));
        }
        if (developerOptions) {
            score -= 5;
            issues.put(issue("developer-options", "low", "Developer options are enabled"));
        }
        if (!encrypted) {
            score -= 20;
            issues.put(issue("storage-encryption", "high", "Storage encryption is not reported active"));
        }
        if (rooted) {
            score -= 30;
            issues.put(issue("root-indicators", "critical", "Root-management indicators were found"));
        }
        if (Build.VERSION.SECURITY_PATCH == null || Build.VERSION.SECURITY_PATCH.isEmpty()) {
            score -= 10;
            issues.put(issue("patch-level", "medium", "Security patch level is unavailable"));
        }
        return object(
                "score", Math.max(0, score),
                "issues", issues,
                "adbEnabled", adbEnabled,
                "developerOptionsEnabled", developerOptions,
                "storageEncrypted", encrypted,
                "rootIndicators", rootIndicators(),
                "securityPatch", Build.VERSION.SECURITY_PATCH
        );
    }

    private int checkPackageBaseline() {
        JSONObject current = packageBaseline();
        JSONObject previous;
        try { previous = new JSONObject(preferences.getString("packageBaseline", "{}")); }
        catch (Exception ignored) { previous = new JSONObject(); }
        int changes = 0;
        java.util.Iterator<String> currentNames = current.keys();
        while (currentNames.hasNext()) {
            String packageName = currentNames.next();
            String value = current.optString(packageName);
            if (!previous.has(packageName)) {
                if (previous.length() > 0) {
                    changes++;
                    events.record("android.app-installed", "info", "Application discovered",
                            object("package", packageName, "version", value));
                }
            } else if (!value.equals(previous.optString(packageName))) {
                changes++;
                events.record("android.app-updated", "info", "Application version changed",
                        object(
                                "package", packageName,
                                "previous", previous.optString(packageName),
                                "current", value
                        ));
            }
        }
        java.util.Iterator<String> previousNames = previous.keys();
        while (previousNames.hasNext()) {
            String packageName = previousNames.next();
            if (!current.has(packageName)) {
                changes++;
                events.record("android.app-removed", "info", "Application no longer installed",
                        object("package", packageName));
            }
        }
        preferences.edit().putString("packageBaseline", current.toString()).apply();
        return changes;
    }

    private JSONObject packageBaseline() {
        JSONObject result = new JSONObject();
        PackageManager manager = context.getPackageManager();
        List<PackageInfo> packages = Build.VERSION.SDK_INT >= 33
                ? manager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
                : manager.getInstalledPackages(0);
        for (PackageInfo item : packages) {
            long version = Build.VERSION.SDK_INT >= 28
                    ? item.getLongVersionCode() : item.versionCode;
            try {
                result.put(item.packageName, version + ":" + item.lastUpdateTime);
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
        }
        return result;
    }

    private void registerNetworkMonitoring() {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) {
                events.record("android.network-available", "info", "Network became available",
                        object("network", network.toString()));
            }

            @Override public void onLost(Network network) {
                events.record("android.network-lost", "warning", "Network connection was lost",
                        object("network", network.toString()));
            }

            @Override public void onCapabilitiesChanged(
                    Network network, NetworkCapabilities capabilities
            ) {
                String key = capabilitiesKey(capabilities);
                String prior = preferences.getString("networkCapabilities", "");
                if (key.equals(prior)) return;
                preferences.edit().putString("networkCapabilities", key).apply();
                events.record("android.network-changed", "info", "Network capabilities changed",
                        object(
                                "validated", capabilities.hasCapability(
                                        NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                                "vpn", capabilities.hasTransport(
                                        NetworkCapabilities.TRANSPORT_VPN),
                                "wifi", capabilities.hasTransport(
                                        NetworkCapabilities.TRANSPORT_WIFI),
                                "cellular", capabilities.hasTransport(
                                        NetworkCapabilities.TRANSPORT_CELLULAR)
                        ));
            }
        };
        try {
            manager.registerDefaultNetworkCallback(networkCallback);
            preferences.edit().putBoolean("networkMonitoring", true).apply();
        } catch (Exception error) {
            networkCallback = null;
            preferences.edit().putBoolean("networkMonitoring", false).apply();
            events.record(
                    "android.network-monitoring-failed", "warning",
                    "Network monitoring could not be started",
                    object("error", error.getMessage())
            );
        }
    }

    private String capabilitiesKey(NetworkCapabilities capabilities) {
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) + "|" +
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) + "|" +
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) + "|" +
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
    }

    private int setting(String name) {
        try { return Settings.Global.getInt(context.getContentResolver(), name, 0); }
        catch (Exception ignored) { return 0; }
    }

    private JSONArray rootIndicators() {
        JSONArray result = new JSONArray();
        String[] candidates = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/data/adb/magisk", "/system/app/Superuser.apk"
        };
        for (String candidate : candidates) {
            if (new File(candidate).exists()) result.put(candidate);
        }
        return result;
    }

    private JSONObject issue(String id, String severity, String title) {
        return object("id", id, "severity", severity, "title", title);
    }

    private JSONObject object(Object... values) {
        JSONObject result = new JSONObject();
        try {
            for (int index = 0; index + 1 < values.length; index += 2) {
                result.put(String.valueOf(values[index]), values[index + 1]);
            }
            return result;
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) result.append(String.format(Locale.ROOT, "%02x", item));
            return result.toString();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }
}
