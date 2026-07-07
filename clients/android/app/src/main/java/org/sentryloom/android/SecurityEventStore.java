package org.sentryloom.android;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;

final class SecurityEventStore extends SQLiteOpenHelper {
    private static final String DATABASE = "security-events.db";
    private static final int VERSION = 1;

    SecurityEventStore(Context context) {
        super(context, DATABASE, null, VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase database) {
        database.execSQL(
                "CREATE TABLE events (" +
                        "sequence INTEGER PRIMARY KEY AUTOINCREMENT," +
                        "id TEXT NOT NULL UNIQUE," +
                        "at TEXT NOT NULL," +
                        "type TEXT NOT NULL," +
                        "severity TEXT NOT NULL," +
                        "message TEXT NOT NULL," +
                        "details TEXT NOT NULL," +
                        "previous_hash TEXT NOT NULL," +
                        "hash TEXT NOT NULL)"
        );
        database.execSQL("CREATE INDEX events_at ON events(at DESC)");
        database.execSQL(
                "CREATE TABLE scans (" +
                        "id TEXT PRIMARY KEY," +
                        "type TEXT NOT NULL," +
                        "started_at TEXT NOT NULL," +
                        "ended_at TEXT," +
                        "status TEXT NOT NULL," +
                        "scanned INTEGER NOT NULL DEFAULT 0," +
                        "detections INTEGER NOT NULL DEFAULT 0," +
                        "errors INTEGER NOT NULL DEFAULT 0," +
                        "result TEXT NOT NULL)"
        );
    }

    @Override
    public void onUpgrade(SQLiteDatabase database, int oldVersion, int newVersion) {}

    synchronized JSONObject record(
            String type,
            String severity,
            String message,
            JSONObject details
    ) {
        String id = UUID.randomUUID().toString();
        String at = TelemetryCollector.isoNow();
        String cleanType = clean(type, 100);
        String cleanSeverity = clean(severity, 20);
        String cleanMessage = clean(message, 1000);
        String serializedDetails = details == null ? "{}" : details.toString();
        if (serializedDetails.length() > 16_384) {
            serializedDetails = object(
                    "truncated", true,
                    "originalLength", serializedDetails.length()
            ).toString();
        }
        SQLiteDatabase database = getWritableDatabase();
        String previousHash = lastHash(database);
        String hash = hash(previousHash, id, at, cleanType, cleanSeverity, cleanMessage, serializedDetails);
        ContentValues values = new ContentValues();
        values.put("id", id);
        values.put("at", at);
        values.put("type", cleanType);
        values.put("severity", cleanSeverity);
        values.put("message", cleanMessage);
        values.put("details", serializedDetails);
        values.put("previous_hash", previousHash);
        values.put("hash", hash);
        database.insertOrThrow("events", null, values);
        return event(id, at, cleanType, cleanSeverity, cleanMessage, serializedDetails, hash);
    }

    synchronized JSONArray recentEvents(int maximum) {
        JSONArray result = new JSONArray();
        try (Cursor cursor = getReadableDatabase().query(
                "events",
                new String[]{"id", "at", "type", "severity", "message", "details", "hash"},
                null, null, null, null,
                "sequence DESC",
                String.valueOf(Math.max(1, Math.min(500, maximum)))
        )) {
            while (cursor.moveToNext()) {
                result.put(event(
                        cursor.getString(0), cursor.getString(1), cursor.getString(2),
                        cursor.getString(3), cursor.getString(4), cursor.getString(5),
                        cursor.getString(6)
                ));
            }
        }
        return result;
    }

    synchronized JSONObject auditStatus() {
        int records = 0;
        String expectedPrevious = "";
        boolean valid = true;
        Integer failedAt = null;
        try (Cursor cursor = getReadableDatabase().query(
                "events",
                new String[]{"id", "at", "type", "severity", "message", "details", "previous_hash", "hash"},
                null, null, null, null, "sequence ASC"
        )) {
            while (cursor.moveToNext()) {
                records++;
                String previous = cursor.getString(6);
                String expectedHash = hash(
                        previous,
                        cursor.getString(0), cursor.getString(1), cursor.getString(2),
                        cursor.getString(3), cursor.getString(4), cursor.getString(5)
                );
                if (!previous.equals(expectedPrevious) || !expectedHash.equals(cursor.getString(7))) {
                    valid = false;
                    failedAt = records;
                    break;
                }
                expectedPrevious = cursor.getString(7);
            }
        }
        return object(
                "valid", valid,
                "records", records,
                "failedAt", failedAt == null ? JSONObject.NULL : failedAt,
                "algorithm", "SHA-256 hash chain",
                "verifiedAt", TelemetryCollector.isoNow()
        );
    }

    synchronized void startScan(String id, String type) {
        ContentValues values = new ContentValues();
        values.put("id", id);
        values.put("type", type);
        values.put("started_at", TelemetryCollector.isoNow());
        values.put("status", "running");
        values.put("result", "{}");
        getWritableDatabase().insertOrThrow("scans", null, values);
    }

    synchronized void finishScan(String id, JSONObject result, String status) {
        ContentValues values = new ContentValues();
        values.put("ended_at", TelemetryCollector.isoNow());
        values.put("status", status);
        values.put("scanned", result.optInt("scanned"));
        values.put("detections", result.optInt("detections"));
        values.put("errors", result.optInt("errors"));
        values.put("result", result.toString());
        getWritableDatabase().update("scans", values, "id=?", new String[]{id});
        getWritableDatabase().delete("scans", "id NOT IN (" +
                "SELECT id FROM scans ORDER BY started_at DESC LIMIT 100)", null);
    }

    synchronized JSONArray scanHistory(int maximum) {
        JSONArray result = new JSONArray();
        try (Cursor cursor = getReadableDatabase().query(
                "scans",
                new String[]{"id", "type", "started_at", "ended_at", "status",
                        "scanned", "detections", "errors", "result"},
                null, null, null, null,
                "started_at DESC",
                String.valueOf(Math.max(1, Math.min(100, maximum)))
        )) {
            while (cursor.moveToNext()) {
                JSONObject item;
                try { item = new JSONObject(cursor.getString(8)); }
                catch (Exception ignored) { item = new JSONObject(); }
                try {
                    item.put("id", cursor.getString(0))
                            .put("type", cursor.getString(1))
                            .put("startedAt", cursor.getString(2))
                            .put("endedAt", cursor.isNull(3) ? JSONObject.NULL : cursor.getString(3))
                            .put("status", cursor.getString(4))
                            .put("scanned", cursor.getInt(5))
                            .put("detections", cursor.getInt(6))
                            .put("errors", cursor.getInt(7));
                } catch (Exception error) {
                    throw new IllegalStateException(error);
                }
                result.put(item);
            }
        }
        return result;
    }

    private String lastHash(SQLiteDatabase database) {
        try (Cursor cursor = database.rawQuery(
                "SELECT hash FROM events ORDER BY sequence DESC LIMIT 1", null
        )) {
            return cursor.moveToFirst() ? cursor.getString(0) : "";
        }
    }

    private JSONObject event(
            String id, String at, String type, String severity,
            String message, String details, String hash
    ) {
        JSONObject parsed;
        try { parsed = new JSONObject(details); }
        catch (Exception ignored) { parsed = new JSONObject(); }
        return object(
                "id", id, "at", at, "type", type,
                "severity", severity, "message", message,
                "details", parsed, "hash", hash
        );
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

    private String hash(String... values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String value : values) {
                digest.update(String.valueOf(value).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
            }
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest.digest()) {
                result.append(String.format(Locale.ROOT, "%02x", value));
            }
            return result.toString();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private String clean(String value, int maximum) {
        String cleaned = String.valueOf(value == null ? "" : value)
                .replace("\0", "").trim();
        return cleaned.substring(0, Math.min(maximum, cleaned.length()));
    }
}
