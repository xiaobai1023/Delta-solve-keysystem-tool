package com.auto.keysolver;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/** Daily solve scheduling with a user-configurable time; fires even in Doze (inexact is fine). */
public final class Scheduler {

    private static final int REQUEST_CODE = 1001;
    private static final String PREF = "state";
    private static final String KEY_HOUR = "hour";
    private static final String KEY_MINUTE = "minute";

    private Scheduler() {}

    static PendingIntent pending(Context ctx) {
        Intent i = new Intent(ctx, AutoReceiver.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) flags |= PendingIntent.FLAG_IMMUTABLE;
        return PendingIntent.getBroadcast(ctx, REQUEST_CODE, i, flags);
    }

    /** Configured trigger time {hour, minute} (default 08:00). */
    public static int[] getTime(Context ctx) {
        android.content.SharedPreferences p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        return new int[]{p.getInt(KEY_HOUR, 8), p.getInt(KEY_MINUTE, 0)};
    }

    /** Set the daily trigger time and reschedule immediately. */
    public static void setTime(Context ctx, int hour, int minute) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putInt(KEY_HOUR, hour).putInt(KEY_MINUTE, minute).apply();
        if (isDaily(ctx)) scheduleNextDaily(ctx);
    }

    /** Schedule the next trigger (today if not yet reached, otherwise tomorrow). */
    static void scheduleNextDaily(Context ctx) {
        int[] t = getTime(ctx);
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(java.util.Calendar.HOUR_OF_DAY, t[0]);
        cal.set(java.util.Calendar.MINUTE, t[1]);
        cal.set(java.util.Calendar.SECOND, 0);
        cal.set(java.util.Calendar.MILLISECOND, 0);
        if (cal.getTimeInMillis() <= System.currentTimeMillis()) {
            cal.add(java.util.Calendar.DAY_OF_YEAR, 1);
        }
        try {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, cal.getTimeInMillis(), pending(ctx));
        } catch (SecurityException e) {
            // No exact-alarm permission (Android 12+ not granted) -> degrade to inexact
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, cal.getTimeInMillis(), pending(ctx));
        }
    }

    /** Enable/disable the daily job. */
    public static void setDaily(Context ctx, boolean enable) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putBoolean("daily", enable).apply();
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        if (enable) {
            scheduleNextDaily(ctx);
        } else {
            am.cancel(pending(ctx));
        }
    }

    public static boolean isDaily(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getBoolean("daily", false);
    }
}
