package org.sentryloom.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import org.json.JSONObject;

public final class PackageChangeReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getData() == null) return;
        String action = intent.getAction();
        String packageName = intent.getData().getSchemeSpecificPart();
        boolean replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
        String type;
        String message;
        if (Intent.ACTION_PACKAGE_ADDED.equals(action)) {
            type = replacing ? "android.app-updated" : "android.app-installed";
            message = replacing ? "Application updated" : "Application installed";
        } else if (Intent.ACTION_PACKAGE_REMOVED.equals(action)) {
            if (replacing) return;
            type = "android.app-removed";
            message = "Application removed";
        } else if (Intent.ACTION_PACKAGE_REPLACED.equals(action)) {
            type = "android.app-updated";
            message = "Application updated";
        } else {
            return;
        }
        JSONObject details = new JSONObject();
        try { details.put("package", packageName); } catch (Exception ignored) {}
        new SecurityEventStore(context).record(
                type, "info", message,
                details
        );
    }
}
