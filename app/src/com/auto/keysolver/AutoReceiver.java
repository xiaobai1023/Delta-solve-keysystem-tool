package com.auto.keysolver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import android.widget.Toast;

/**
 * Alarm trigger for the automatic renewals (daily time, key-expiry moment and
 * the 30-minute validity watchdog). Reschedules FIRST — the alarms are
 * one-shot, so the chain must stay alive even when the solve fails — then:
 *  - daily/expiry: start AutoService via a plain startService(). This is
 *    allowed from the alarm's temporary allowlist and, unlike
 *    startForegroundService(), carries no mandatory startForeground() contract,
 *    so an Android 12+ background-FGS veto cannot crash the solve (the old
 *    startForegroundService path died silently exactly there). If even
 *    startService is vetoed, solve inline via goAsync() + wakelock.
 *  - watchdog: cheap server-side validity check; a full solve runs only when
 *    the key is really expired (or absent). Offline -> skip, next tick retries.
 */
public class AutoReceiver extends BroadcastReceiver {

    static final String EXTRA_KIND = "kind";
    static final String KIND_WATCHDOG = "watchdog";

    private static final String CHANNEL_ID = "solve";
    private static final int RESULT_NOTIF_ID = 2002;

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Scheduler.automationEnabled(context)) return;
        Scheduler.scheduleNextDaily(context);
        if (KIND_WATCHDOG.equals(intent.getStringExtra(EXTRA_KIND))) {
            runWatchdog(context);
        } else {
            solve(context);
        }
    }

    /** Watchdog tick: solve only when the cached key is verifiably no longer valid. */
    private void runWatchdog(Context context) {
        BroadcastReceiver.PendingResult pr = goAsync();
        PowerManager.WakeLock wl = wakeLock(context, 120_000L);
        new Thread(() -> {
            try {
                String key = KeyRunner.lastKey(context);
                boolean valid = false;
                if (key != null) {
                    String hwid = DeltaStore.extractHwid(context, null);
                    if (hwid != null) {
                        valid = Solver.whitelistValid(Solver.identifierFor(hwid), key);
                    }
                }
                if (!valid) solve(context);
            } catch (Exception ignore) {
                // offline / rate limited: retry on the next watchdog tick
            } finally {
                wl.release();
                pr.finish();
            }
        }, "aks-watchdog").start();
    }

    /** One renewal attempt: AutoService when the system allows it, else inline. */
    private void solve(Context context) {
        try {
            context.startService(new Intent(context, AutoService.class));
            Toast.makeText(context, "Auto Key Solver: renewing...", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            final BroadcastReceiver.PendingResult pr = goAsync();
            final PowerManager.WakeLock wl = wakeLock(context, 180_000L);
            new Thread(() -> {
                String result;
                try {
                    result = "Solved: " + KeyRunner.run(context, s -> { });
                } catch (Exception e2) {
                    result = "Failed: " + e2.getMessage();
                }
                notifyDone(context, result);
                wl.release();
                pr.finish();
            }, "aks-inline").start();
        }
    }

    private static PowerManager.WakeLock wakeLock(Context c, long timeoutMs) {
        PowerManager.WakeLock wl = ((PowerManager) c.getSystemService(Context.POWER_SERVICE))
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "autokeysolver:solve");
        wl.acquire(timeoutMs);
        return wl;
    }

    private static void notifyDone(Context ctx, String text) {
        try {
            NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID,
                    "Auto solve", NotificationManager.IMPORTANCE_DEFAULT);
            nm.createNotificationChannel(ch);
            Notification n = new Notification.Builder(ctx, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle("Auto Key Solver")
                    .setContentText(text)
                    .setAutoCancel(true)
                    .build();
            nm.notify(RESULT_NOTIF_ID, n);
        } catch (Exception ignore) {}
    }

    static boolean dailyEnabled(Context ctx) {
        return Scheduler.automationEnabled(ctx);
    }
}
