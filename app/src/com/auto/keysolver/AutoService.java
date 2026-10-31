package com.auto.keysolver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.PowerManager;

/**
 * Renewal worker started by AutoReceiver from the alarm. Started with a plain
 * startService() (no Android 12+ startForeground contract), so a vetoed
 * foreground promotion is caught and the solve simply runs as a plain service
 * under the wakelock.
 */
public class AutoService extends Service {

    private static final String CHANNEL_ID = "solve";
    private static final int NOTIF_ID = 1001;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel ch = new NotificationChannel(CHANNEL_ID, "Auto solve",
                NotificationManager.IMPORTANCE_DEFAULT);
        nm.createNotificationChannel(ch);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        try {
            startForeground(NOTIF_ID, buildNotification("Auto-renewing Delta key ..."));
        } catch (Exception e) {
            // Foreground promotion vetoed (Android 12+ background restriction):
            // keep solving as a plain service under the wakelock below
        }
        new Thread(this::solve, "auto-solve").start();
        return START_NOT_STICKY;
    }

    private void solve() {
        PowerManager.WakeLock wl = ((PowerManager) getSystemService(Context.POWER_SERVICE))
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "autokeysolver:solve");
        wl.acquire(180_000L);
        String result;
        try {
            String key = KeyRunner.run(this, s -> { });
            result = "Solved: " + key;
        } catch (Exception e) {
            result = "Failed: " + e.getMessage();
        } finally {
            wl.release();
        }
        try {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            nm.notify(2001, buildNotification(result));
        } catch (Exception ignore) {}
        stopForeground(true);
        stopSelf();
    }

    private Notification buildNotification(String text) {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Auto Key Solver")
                .setContentText(text)
                .setAutoCancel(true)
                .build();
    }
}
