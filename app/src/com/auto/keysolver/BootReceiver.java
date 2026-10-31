package com.auto.keysolver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Re-arm the daily renewal alarm after a reboot. */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        if (Scheduler.automationEnabled(context)) {
            Scheduler.scheduleNextDaily(context);
        }
    }
}
