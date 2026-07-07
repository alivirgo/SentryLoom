package org.sentryloom.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.atomic.AtomicBoolean;

public final class ManagementService extends Service {
    static final String ACTION_SYNC_NOW = "org.sentryloom.android.SYNC_NOW";
    private static final String CHANNEL = "sentryloom_management";
    private static final int NOTIFICATION_ID = 1001;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean forceTelemetry = new AtomicBoolean(false);
    private Thread worker;
    private EndpointState state;
    private SecurityEventStore events;
    private AndroidProtectionEngine protection;

    @Override
    public void onCreate() {
        super.onCreate();
        state = new EndpointState(this);
        events = new SecurityEventStore(this);
        protection = new AndroidProtectionEngine(this);
        NotificationChannel channel = new NotificationChannel(
                CHANNEL, "SentryLoom protection", NotificationManager.IMPORTANCE_LOW
        );
        channel.setDescription("Shows when endpoint telemetry and management are active");
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_SYNC_NOW.equals(intent.getAction())) {
            forceTelemetry.set(true);
        }
        state.setServiceEnabled(true);
        protection.start();
        startForeground(NOTIFICATION_ID, notification(state.status()));
        if (running.compareAndSet(false, true)) {
            worker = new Thread(this::loop, "sentryloom-management");
            worker.start();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running.set(false);
        if (worker != null) worker.interrupt();
        protection.stop();
        state.setServiceEnabled(false);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void loop() {
        long lastTelemetry = 0;
        long lastProtectionCycle = 0;
        long delay = 5_000;
        while (running.get()) {
            try {
                if (state.credentials() == null) {
                    if (state.pending() != null) {
                        new EnrollmentManager(this).poll();
                    }
                } else {
                    JSONObject credentials = state.credentials();
                    PinnedHqClient client = client(credentials);
                    long now = SystemClock.elapsedRealtime();
                    if (forceTelemetry.getAndSet(false) || now - lastTelemetry >= 30_000) {
                        if (now - lastProtectionCycle >= 60_000) {
                            JSONObject cycle = protection.runProtectionCycle();
                            lastProtectionCycle = now;
                            Log.i("SentryLoom", "Protection cycle " + cycle);
                        }
                        client.post(
                                "/api/v1/device/telemetry",
                                new TelemetryCollector(this).collect(),
                                credentials
                        );
                        lastTelemetry = now;
                        String sentAt = TelemetryCollector.isoNow();
                        state.setLastTelemetryAt(sentAt);
                        state.setLastError(null);
                    }
                    processCommands(client, credentials);
                    state.setStatus("Enrolled and connected · " + TelemetryCollector.isoNow());
                }
                updateNotification();
                delay = 10_000;
            } catch (Exception error) {
                String message = error.getMessage() == null
                        ? error.getClass().getSimpleName() : error.getMessage();
                state.setStatus("Connection error · " + message);
                state.setLastError(message);
                Log.e("SentryLoom", "Management loop failed", error);
                JSONObject details = new JSONObject();
                try { details.put("error", message); } catch (Exception ignored) {}
                events.record(
                        "hq.connection-error", "error",
                        "HQ connection or telemetry failed",
                        details
                );
                updateNotification();
                delay = Math.min(5 * 60_000, Math.max(10_000, delay * 2));
            }
            try {
                Thread.sleep(delay);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void processCommands(PinnedHqClient client, JSONObject credentials) throws Exception {
        JSONArray commands = client.get("/api/v1/device/commands", credentials, null)
                .body.optJSONArray("commands");
        if (commands == null) return;
        CommandExecutor executor = new CommandExecutor(this);
        for (int index = 0; index < commands.length(); index++) {
            JSONObject command = commands.getJSONObject(index);
            String id = command.getString("id");
            result(client, credentials, id, "running",
                    new JSONObject().put("startedAt", TelemetryCollector.isoNow()));
            events.record(
                    "hq.command-started", "info",
                    "Remote action started",
                    new JSONObject().put("commandId", id)
                            .put("commandType", command.optString("type"))
            );
            try {
                JSONObject output = executor.execute(command);
                result(client, credentials, id, "completed", output);
                state.setLastCommandAt(TelemetryCollector.isoNow());
                events.record(
                        "hq.command-completed", "info",
                        "Remote action completed",
                        new JSONObject().put("commandId", id)
                                .put("commandType", command.optString("type"))
                                .put("result", output)
                );
                if (executor.shouldReboot(command, output)) {
                    Thread.sleep(500);
                    executor.reboot();
                }
            } catch (Exception error) {
                result(client, credentials, id, "failed", new JSONObject()
                        .put("error", String.valueOf(error.getMessage()))
                        .put("failedAt", TelemetryCollector.isoNow()));
                events.record(
                        "hq.command-failed", "error",
                        "Remote action failed",
                        new JSONObject().put("commandId", id)
                                .put("commandType", command.optString("type"))
                                .put("error", String.valueOf(error.getMessage()))
                );
            }
        }
    }

    private void result(
            PinnedHqClient client,
            JSONObject credentials,
            String id,
            String status,
            JSONObject result
    ) throws Exception {
        client.post(
                "/api/v1/device/commands/" + id + "/result",
                new JSONObject().put("status", status).put("result", result),
                credentials
        );
    }

    private PinnedHqClient client(JSONObject credentials) throws Exception {
        return new PinnedHqClient(
                credentials.getString("serverUrl"),
                credentials.getString("fingerprint256")
        );
    }

    private Notification notification(String text) {
        Intent launch = new Intent(this, MainActivity.class);
        PendingIntent pending = PendingIntent.getActivity(
                this, 0, launch, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(org.sentryloom.android.R.drawable.ic_shield)
                .setContentTitle("SentryLoom protection is active")
                .setContentText(text)
                .setContentIntent(pending)
                .setOngoing(true)
                .build();
    }

    private void updateNotification() {
        getSystemService(NotificationManager.class)
                .notify(NOTIFICATION_ID, notification(state.status()));
    }
}
