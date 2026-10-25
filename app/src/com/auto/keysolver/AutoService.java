package com.auto.keysolver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;

/** Daily renewal foreground service: alarm -> solve -> notify the result -> stop. */
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
        startForeground(NOTIF_ID, buildNotification("Auto-renewing Delta key ..."));
        new Thread(this::solve, "auto-solve").start();
        return START_NOT_STICKY;
    }

    private void solve() {
        String result;
        try {
            String key = KeyRunner.run(this, s -> { });
            result = "Solved: " + key;
        } catch (Exception e) {
            result = "Failed: " + e.getMessage();
        }
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.notify(2001, buildNotification(result));
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
