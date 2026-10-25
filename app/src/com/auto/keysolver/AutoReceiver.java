package com.auto.keysolver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.PowerManager;
import android.widget.Toast;

/**
 * Daily alarm trigger: start the foreground service, then reschedule for tomorrow.
 * On Android 12+ a background foreground-service start requires the exact-alarm
 * exemption; if the exact-alarm permission is denied we fall back to solving
 * inline via goAsync() while holding a wakelock, so the job always runs.
 */
public class AutoReceiver extends BroadcastReceiver {

    private static final String CHANNEL_ID = "solve";
    private static final int RESULT_NOTIF_ID = 2002;

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!dailyEnabled(context)) return;
        android.content.BroadcastReceiver.PendingResult pr = goAsync();
        PowerManager.WakeLock wl = ((PowerManager) context.getSystemService(Context.POWER_SERVICE))
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "autokeysolver:solve");
        wl.acquire(120_000L);
        boolean fgs = false;
        try {
            Intent svc = new Intent(context, AutoService.class);
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(svc);
            } else {
                context.startService(svc);
            }
            fgs = true;
        } catch (Exception e) {
            // No exact-alarm exemption (Android 12+ background FGS restriction) -> inline fallback
            fgs = false;
        }
        if (fgs) {
            Toast.makeText(context, "Auto Key Solver: renewing...", Toast.LENGTH_SHORT).show();
            Scheduler.scheduleNextDaily(context); // roll over to tomorrow
            wl.release();
            pr.finish();
        } else {
            final Context ctx = context;
            final android.content.BroadcastReceiver.PendingResult fpr = pr;
            final PowerManager.WakeLock fw = wl;
            new Thread(() -> {
                String result;
                try {
                    String key = KeyRunner.run(ctx, s -> { });
                    result = "Solved: " + key;
                } catch (Exception e) {
                    result = "Failed: " + e.getMessage();
                }
                notifyDone(ctx, result);
                Scheduler.scheduleNextDaily(ctx);
                fw.release();
                fpr.finish();
            }, "auto-solve-fallback").start();
        }
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
        return ctx.getSharedPreferences("state", Context.MODE_PRIVATE)
                .getBoolean("daily", false);
    }
}
