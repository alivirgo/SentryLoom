package org.sentryloom.android;

import android.Manifest;
import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refresher = new Runnable() {
        @Override public void run() {
            refresh();
            handler.postDelayed(this, 3000);
        }
    };
    private EndpointState state;
    private TextView connectionCard;
    private TextView protectionCard;
    private TextView postureCard;
    private TextView scanCard;
    private TextView eventCard;
    private EditText server;
    private EditText fingerprint;
    private Button scanButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        state = new EndpointState(this);
        setContentView(content());
        if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                        PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 10);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.removeCallbacks(refresher);
        handler.post(refresher);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(refresher);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private View content() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, dp(40));
        root.setBackgroundColor(Color.rgb(244, 247, 246));

        root.addView(title("SentryLoom Android", 28));
        TextView subtitle = text(
                "Application integrity, posture, network monitoring and certificate-pinned HQ management.",
                14, Color.DKGRAY
        );
        subtitle.setPadding(0, 0, 0, dp(10));
        root.addView(subtitle);

        connectionCard = card();
        protectionCard = card();
        postureCard = card();
        scanCard = card();
        eventCard = card();
        root.addView(connectionCard);
        root.addView(protectionCard);
        root.addView(postureCard);

        root.addView(section("HQ ENROLLMENT"));
        server = input("https://HQ-address:32110");
        server.setText(state.lastServerUrl());
        fingerprint = input("Certificate SHA-256 fingerprint (optional)");
        root.addView(server);
        root.addView(fingerprint);

        Button enroll = button("Request HQ enrollment");
        enroll.setOnClickListener(view -> enroll());
        root.addView(enroll);

        root.addView(section("PROTECTION"));
        scanButton = button("Scan installed applications now");
        scanButton.setOnClickListener(view -> scanApplications());
        root.addView(scanButton);

        Button refreshPosture = button("Run protection check now");
        refreshPosture.setOnClickListener(view -> runProtectionCheck());
        root.addView(refreshPosture);

        Button sync = button("Send telemetry to HQ now");
        sync.setOnClickListener(view -> {
            Intent intent = new Intent(this, ManagementService.class)
                    .setAction(ManagementService.ACTION_SYNC_NOW);
            startForegroundService(intent);
            Toast.makeText(this, "HQ synchronization requested", Toast.LENGTH_SHORT).show();
        });
        root.addView(sync);

        Button start = button("Start background protection");
        start.setOnClickListener(view -> {
            state.setServiceEnabled(true);
            startForegroundService(new Intent(this, ManagementService.class));
            new SecurityEventStore(this).record(
                    "android.protection-enabled", "info",
                    "Background protection enabled by the local user", new JSONObject()
            );
            refresh();
        });
        root.addView(start);

        Button stop = button("Stop background protection");
        stop.setOnClickListener(view -> {
            stopService(new Intent(this, ManagementService.class));
            state.setServiceEnabled(false);
            refresh();
        });
        root.addView(stop);

        root.addView(scanCard);
        root.addView(section("ANDROID ACCESS"));

        Button admin = button("Enable Device Administrator");
        admin.setOnClickListener(view -> {
            Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
            intent.putExtra(
                    DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                    new ComponentName(this, SentryDeviceAdminReceiver.class)
            );
            intent.putExtra(
                    DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Enables only the permission-gated SentryLoom lock command."
            );
            startActivity(intent);
        });
        root.addView(admin);

        Button usage = button("Grant application Usage Access");
        usage.setOnClickListener(view -> startActivity(
                new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
        ));
        root.addView(usage);

        Button settings = button("Open Android app security settings");
        settings.setOnClickListener(view -> startActivity(new Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:" + getPackageName())
        )));
        root.addView(settings);

        root.addView(section("RECENT SECURITY ACTIVITY"));
        root.addView(eventCard);

        Button disconnect = button("Disconnect from HQ");
        disconnect.setOnClickListener(view -> {
            state.clearEnrollment();
            state.setStatus("Not enrolled");
            new SecurityEventStore(this).record(
                    "hq.disconnected", "warning",
                    "Endpoint disconnected from HQ by the local user", new JSONObject()
            );
            refresh();
        });
        root.addView(disconnect);

        TextView owner = text(
                "Advanced camera, screen-capture, USB, safe-boot, reboot and policy controls " +
                        "appear in HQ only when Android reports Device Owner or Profile Owner privileges. " +
                        "Personal files remain protected by Android scoped storage.",
                13, Color.DKGRAY
        );
        owner.setPadding(0, dp(20), 0, 0);
        root.addView(owner);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        return scroll;
    }

    private void enroll() {
        String url = server.getText().toString().trim();
        String pin = fingerprint.getText().toString().trim();
        if (url.isEmpty()) {
            connectionCard.setText("Enter the HTTPS address of SentryLoom HQ.");
            server.requestFocus();
            return;
        }
        connectionCard.setText("Submitting enrollment request…");
        executor.execute(() -> {
            try {
                String code = new EnrollmentManager(this).request(url, pin);
                runOnUiThread(() -> {
                    connectionCard.setText("Waiting for HQ approval\nVerification code: " + code);
                    state.setServiceEnabled(true);
                    startForegroundService(new Intent(this, ManagementService.class));
                    Toast.makeText(this, "HQ verification code: " + code,
                            Toast.LENGTH_LONG).show();
                });
            } catch (Exception error) {
                String detail = error.getMessage() == null
                        ? error.getClass().getSimpleName() : error.getMessage();
                JSONObject details = new JSONObject();
                try { details.put("error", detail); } catch (Exception ignored) {}
                new SecurityEventStore(this).record(
                        "hq.enrollment-failed", "error",
                        "HQ enrollment request failed",
                        details
                );
                runOnUiThread(() -> {
                    connectionCard.setText("Enrollment failed\n" + detail);
                    Toast.makeText(this, detail, Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void scanApplications() {
        scanButton.setEnabled(false);
        scanCard.setText("APPLICATION SCAN\nHashing APKs and reviewing signers, installers and permissions…");
        executor.execute(() -> {
            try {
                JSONObject result = new CommandExecutor(this).execute(
                        new JSONObject().put("type", "scan.apps")
                );
                runOnUiThread(() -> {
                    scanButton.setEnabled(true);
                    renderScan(result);
                    Intent sync = new Intent(this, ManagementService.class)
                            .setAction(ManagementService.ACTION_SYNC_NOW);
                    startForegroundService(sync);
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    scanButton.setEnabled(true);
                    scanCard.setText("APPLICATION SCAN FAILED\n" + error.getMessage());
                });
            }
        });
    }

    private void runProtectionCheck() {
        executor.execute(() -> {
            JSONObject result = new AndroidProtectionEngine(this).runProtectionCycle();
            runOnUiThread(() -> {
                Toast.makeText(this, "Protection check complete", Toast.LENGTH_SHORT).show();
                refresh();
            });
        });
    }

    private void refresh() {
        DevicePolicyManager policy = getSystemService(DevicePolicyManager.class);
        boolean owner = policy.isDeviceOwnerApp(getPackageName());
        boolean profile = policy.isProfileOwnerApp(getPackageName());
        boolean admin = policy.isAdminActive(
                new ComponentName(this, SentryDeviceAdminReceiver.class)
        );
        AndroidProtectionEngine engine = new AndroidProtectionEngine(this);
        JSONObject protection = engine.status();
        JSONObject posture = engine.securityPosture();
        JSONArray history = new SecurityEventStore(this).scanHistory(1);
        JSONArray recent = new SecurityEventStore(this).recentEvents(12);

        connectionCard.setText(
                "HQ CONNECTION\n" + state.status() +
                        "\nLast telemetry: " + label(state.lastTelemetryAt()) +
                        (state.lastError() == null ? "" : "\nLast error: " + state.lastError())
        );
        protectionCard.setText(
                "PROTECTION " + (state.serviceEnabled() ? "ACTIVE" : "STOPPED") +
                        "\nChecks completed: " + protection.optLong("cycles") +
                        "\nLast check: " + label(protection.optString("lastCycleAt", null)) +
                        "\nApp changes: monitored · Network changes: monitored" +
                        "\nAdmin: " + admin + " · Device owner: " + owner +
                        " · Profile owner: " + profile
        );
        JSONArray issues = posture.optJSONArray("issues");
        postureCard.setText(
                "SECURITY POSTURE  " + posture.optInt("score") + "/100" +
                        "\nPatch: " + Build.VERSION.SECURITY_PATCH +
                        "\nStorage encrypted: " + posture.optBoolean("storageEncrypted") +
                        " · ADB: " + posture.optBoolean("adbEnabled") +
                        "\nIssues: " + (issues == null || issues.length() == 0
                        ? "None detected" : issueTitles(issues))
        );
        if (history.length() > 0) renderScan(history.optJSONObject(0));
        else scanCard.setText("APPLICATION SCAN\nNo completed application scan yet.");
        eventCard.setText(renderEvents(recent));
    }

    private void renderScan(JSONObject result) {
        if (result == null) return;
        scanCard.setText(
                "LAST APPLICATION SCAN\n" +
                        result.optInt("scanned") + " APKs hashed · " +
                        result.optInt("riskSignals") + " risk signals · " +
                        result.optInt("errors") + " errors\nCompleted: " +
                        label(result.optString("endedAt", null))
        );
    }

    private String renderEvents(JSONArray events) {
        if (events.length() == 0) return "No security activity recorded yet.";
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < events.length(); index++) {
            JSONObject event = events.optJSONObject(index);
            if (event == null) continue;
            if (result.length() > 0) result.append("\n\n");
            result.append(event.optString("severity", "info").toUpperCase())
                    .append(" · ").append(event.optString("message", event.optString("type")))
                    .append("\n").append(label(event.optString("at", null)));
        }
        return result.toString();
    }

    private String issueTitles(JSONArray issues) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < issues.length(); index++) {
            JSONObject issue = issues.optJSONObject(index);
            if (issue == null) continue;
            if (result.length() > 0) result.append(", ");
            result.append(issue.optString("title", issue.optString("id")));
        }
        return result.toString();
    }

    private String label(String value) {
        return value == null || value.isEmpty() || "null".equals(value) ? "Not yet" : value;
    }

    private TextView card() {
        TextView view = text("Loading…", 14, Color.rgb(14, 30, 36));
        view.setBackgroundColor(Color.WHITE);
        view.setPadding(dp(14), dp(13), dp(14), dp(13));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        );
        params.setMargins(0, dp(7), 0, dp(4));
        view.setLayoutParams(params);
        return view;
    }

    private TextView section(String value) {
        TextView view = text(value, 12, Color.rgb(24, 107, 90));
        view.setPadding(0, dp(22), 0, dp(5));
        return view;
    }

    private TextView title(String value, int size) {
        TextView view = text(value, size, Color.rgb(14, 30, 36));
        view.setPadding(0, 0, 0, dp(5));
        return view;
    }

    private Button button(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        );
        params.setMargins(0, dp(5), 0, 0);
        button.setLayoutParams(params);
        return button;
    }

    private EditText input(String hint) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setSingleLine(true);
        input.setTextSize(14);
        input.setPadding(dp(12), dp(11), dp(12), dp(11));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        );
        params.setMargins(0, dp(5), 0, 0);
        input.setLayoutParams(params);
        return input;
    }

    private TextView text(String value, int size, int color) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextSize(size);
        text.setTextColor(color);
        text.setLineSpacing(0, 1.15f);
        return text;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
