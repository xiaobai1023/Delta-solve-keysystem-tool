package com.auto.keysolver;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

/**
 * Automatic renewal scheduling. While the daily switch is on, two alarms run:
 *  - main trigger: the earliest of the user's daily time and the moment the
 *    current key expires (minus a small lead). Scheduled with setAlarmClock(),
 *    which is always exact, fires in Doze, needs no exact-alarm permission
 *    (unlike setExactAndAllowWhileIdle on Android 12+) and is what OEM battery
 *    managers respect;
 *  - watchdog: every 30 min a cheap server-side validity check that starts a
 *    full solve only when the key has really expired — covers main alarms
 *    missed to Doze/OEM throttling.
 * KeyRunner.run() rewrites the cache and returns immediately when the key is
 * still valid, so extra firings are cheap and safe.
 */
public final class Scheduler {

    private static final int RC_MAIN = 1001;
    private static final int RC_WATCHDOG = 1002;
    private static final String PREF = "state";
    private static final String KEY_HOUR = "hour";
    private static final String KEY_MINUTE = "minute";
    private static final long WATCHDOG_MS = 30 * 60_000L;
    private static final long EXPIRY_LEAD_MS = 10 * 60_000L;
    private static final long KEY_PERIOD_MS = 24L * 3600_000L;

    private Scheduler() {}

    private static PendingIntent pending(Context ctx, int rc, boolean watchdog) {
        Intent i = new Intent(ctx, AutoReceiver.class);
        if (watchdog) i.putExtra(AutoReceiver.EXTRA_KIND, AutoReceiver.KIND_WATCHDOG);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) flags |= PendingIntent.FLAG_IMMUTABLE;
        return PendingIntent.getBroadcast(ctx, rc, i, flags);
    }

    private static PendingIntent tapPending(Context ctx) {
        Intent i = new Intent(ctx, MainActivity.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) flags |= PendingIntent.FLAG_IMMUTABLE;
        return PendingIntent.getActivity(ctx, RC_MAIN, i, flags);
    }

    /** Configured trigger time {hour, minute} (default 08:00). */
    public static int[] getTime(Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        return new int[]{p.getInt(KEY_HOUR, 8), p.getInt(KEY_MINUTE, 0)};
    }

    /** Set the daily trigger time and reschedule immediately. */
    public static void setTime(Context ctx, int hour, int minute) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putInt(KEY_HOUR, hour).putInt(KEY_MINUTE, minute).apply();
        if (isDaily(ctx)) scheduleNextDaily(ctx);
    }

    /**
     * (Re)schedule both alarms. One-shot alarms: call after every firing,
     * after boot, on every app open and setting change (self-healing).
     * The main trigger is the earliest of the daily time (when the daily
     * switch is on) and the key-expiry moment (when expiry auto-renewal is on).
     */
    public static void scheduleNextDaily(Context ctx) {
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        long now = System.currentTimeMillis();
        long main = Long.MAX_VALUE;
        if (isDaily(ctx)) main = nextDailyMillis(ctx);
        if (isAutoExpiry(ctx)) {
            long expiry = nextExpiryMillis(ctx);
            if (expiry > now && expiry < main) main = expiry;
        }
        if (main == Long.MAX_VALUE) {
            // both switches produce no near-term trigger (no key yet): the
            // watchdog alone keeps checking and re-arms once a key exists
            main = now + WATCHDOG_MS;
        }
        try {
            am.setAlarmClock(new AlarmManager.AlarmClockInfo(main, tapPending(ctx)),
                    pending(ctx, RC_MAIN, false));
        } catch (Exception e) {
            // setAlarmClock never needs a permission; keep a fallback anyway
            try {
                am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, main,
                        pending(ctx, RC_MAIN, false));
            } catch (SecurityException e2) {
                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, main,
                        pending(ctx, RC_MAIN, false));
            }
        }
        try {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, now + WATCHDOG_MS,
                    pending(ctx, RC_WATCHDOG, true));
        } catch (SecurityException e) {
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, now + WATCHDOG_MS,
                    pending(ctx, RC_WATCHDOG, true));
        }
    }

    /** Next firing of the user's configured daily time. */
    private static long nextDailyMillis(Context ctx) {
        int[] t = getTime(ctx);
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(java.util.Calendar.HOUR_OF_DAY, t[0]);
        cal.set(java.util.Calendar.MINUTE, t[1]);
        cal.set(java.util.Calendar.SECOND, 0);
        cal.set(java.util.Calendar.MILLISECOND, 0);
        if (cal.getTimeInMillis() <= System.currentTimeMillis()) {
            cal.add(java.util.Calendar.DAY_OF_YEAR, 1);
        }
        return cal.getTimeInMillis();
    }

    /** Key expiry moment (minus the renewal lead), 0 when unknown. */
    private static long nextExpiryMillis(Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        long st = p.getLong("key_status_time", 0);
        long ml = p.getLong("key_minutes_left", -1);
        long expiry = (ml >= 0 && st > 0) ? st + ml * 60_000L : p.getLong("expiry_at", 0);
        if (expiry <= 0) {
            long last = p.getLong("last_time", 0);
            if (last <= 0) return 0;
            expiry = last + KEY_PERIOD_MS;
        }
        return expiry - EXPIRY_LEAD_MS;
    }

    /** Enable/disable the fixed daily time. */
    public static void setDaily(Context ctx, boolean enable) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putBoolean("daily", enable).apply();
        applyAlarms(ctx);
    }

    /** Enable/disable renewal when the key expires (default on). */
    public static void setAutoExpiry(Context ctx, boolean enable) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putBoolean("auto_expiry", enable).apply();
        applyAlarms(ctx);
    }

    public static boolean isDaily(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getBoolean("daily", false);
    }

    public static boolean isAutoExpiry(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getBoolean("auto_expiry", true);
    }

    /** Any automatic renewal enabled at all. */
    public static boolean automationEnabled(Context ctx) {
        return isDaily(ctx) || isAutoExpiry(ctx);
    }

    /** Re-arm or cancel the alarms to match the two switches. */
    private static void applyAlarms(Context ctx) {
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        if (automationEnabled(ctx)) {
            scheduleNextDaily(ctx);
        } else {
            am.cancel(pending(ctx, RC_MAIN, false));
            am.cancel(pending(ctx, RC_WATCHDOG, true));
        }
    }
}
