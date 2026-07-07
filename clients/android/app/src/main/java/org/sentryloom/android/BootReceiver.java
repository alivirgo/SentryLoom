package org.sentryloom.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action) &&
                !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) return;
        EndpointState state = new EndpointState(context);
        org.json.JSONObject details = new org.json.JSONObject();
        try { details.put("action", action); } catch (Exception ignored) {}
        new SecurityEventStore(context).record(
                "android.boot", "info", "Device boot or application update completed",
                details
        );
        if (state.serviceEnabled()) {
            context.startForegroundService(new Intent(context, ManagementService.class));
        }
    }
}
