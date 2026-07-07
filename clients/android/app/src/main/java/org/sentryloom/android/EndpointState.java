package org.sentryloom.android;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.UUID;

final class EndpointState {
    static final String VERSION = "0.2.0";
    private static final String CREDENTIALS = "credentials";
    private static final String PENDING = "pending";
    private final SharedPreferences preferences;
    private final SecretStore secrets;

    EndpointState(Context context) {
        preferences = context.getSharedPreferences("sentryloom_state", Context.MODE_PRIVATE);
        secrets = new SecretStore(context);
    }

    String installationId() {
        String value = preferences.getString("installationId", null);
        if (value != null) return value;
        value = UUID.randomUUID().toString();
        preferences.edit().putString("installationId", value).apply();
        return value;
    }

    JSONObject credentials() {
        return secrets.get(CREDENTIALS);
    }

    void setCredentials(JSONObject value) throws Exception {
        secrets.put(CREDENTIALS, value);
        secrets.remove(PENDING);
    }

    JSONObject pending() {
        return secrets.get(PENDING);
    }

    void setPending(JSONObject value) throws Exception {
        secrets.put(PENDING, value);
        secrets.remove(CREDENTIALS);
    }

    void clearEnrollment() {
        secrets.remove(CREDENTIALS);
        secrets.remove(PENDING);
    }

    boolean serviceEnabled() {
        return preferences.getBoolean("serviceEnabled", false);
    }

    void setServiceEnabled(boolean enabled) {
        preferences.edit().putBoolean("serviceEnabled", enabled).apply();
    }

    String status() {
        return preferences.getString("status", "Not enrolled");
    }

    void setStatus(String value) {
        preferences.edit().putString("status", value).apply();
    }

    String lastTelemetryAt() {
        return preferences.getString("lastTelemetryAt", null);
    }

    void setLastTelemetryAt(String value) {
        preferences.edit().putString("lastTelemetryAt", value).apply();
    }

    String lastCommandAt() {
        return preferences.getString("lastCommandAt", null);
    }

    void setLastCommandAt(String value) {
        preferences.edit().putString("lastCommandAt", value).apply();
    }

    String lastError() {
        return preferences.getString("lastError", null);
    }

    void setLastError(String value) {
        preferences.edit().putString("lastError", value).apply();
    }

    String lastServerUrl() {
        return preferences.getString("lastServerUrl", "");
    }

    void setLastServerUrl(String value) {
        preferences.edit().putString("lastServerUrl", value).apply();
    }

    static String verificationCode() {
        return String.format(Locale.ROOT, "%06d", new SecureRandom().nextInt(1_000_000));
    }
}
