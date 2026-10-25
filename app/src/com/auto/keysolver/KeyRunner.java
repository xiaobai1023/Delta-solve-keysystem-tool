package com.auto.keysolver;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Shared solve flow, used by MainActivity (manual) and AutoService (daily job).
 */
public final class KeyRunner {

    public interface Log {
        void log(String s);
    }

    private KeyRunner() {}

    /** Run one full solve cycle and write the key back. Returns the key. */
    public static String run(Context ctx, Log log) throws Exception {
        log.log("=== Auto Key Solver ===");

        // 1) HWID
        log.log("[1/4] Reading device HWID ...");
        String hwid = DeltaStore.extractHwid(s -> log.log(s));
        if (hwid == null) {
            throw new Exception("No HWID found (check file-access permission / has Delta ever launched?)");
        }
        log.log("[hwid] " + hwid);

        String ident = Solver.identifierFor(hwid);

        // 2) Fast path: if the cached key is still valid, skip solving but rewrite cache files
        log.log("[2/4] Checking existing key ...");
        String existing = DeltaStore.findExistingKey();
        if (existing != null && Solver.whitelistValid(ident, existing)) {
            log.log("[+] Existing key still valid, rewriting cache files: " + existing);
            java.util.List<String> w = DeltaStore.writeKey(existing, s -> log.log(s));
            if (w.isEmpty()) {
                log.log("[!] Failed to write cache files (see errors above)");
            }
            saveLast(ctx, existing);
            return existing;
        }
        if (existing != null) {
            log.log("[i] Existing key expired, renewing");
        } else {
            log.log("[i] No cached key found, solving directly");
        }

        // 3) Solve
        log.log("[3/4] Solving via Platoboost (about 5-15s) ...");
        long t0 = android.os.SystemClock.elapsedRealtime();
        String key = Solver.solveForHwid(hwid, s -> log.log(s));
        log.log("[+] Solved (" + (android.os.SystemClock.elapsedRealtime() - t0) / 1000 + "s)");

        // 4) Write back
        log.log("[4/4] Writing key cache ...");
        java.util.List<String> written = DeltaStore.writeKey(key, s -> log.log(s));
        if (written.isEmpty()) {
            log.log("[!] Failed to write cache files (see errors above), key only: " + key);
        } else {
            log.log("[+] Written: " + android.text.TextUtils.join(", ", written));
        }
        saveLast(ctx, key);
        return key;
    }

    public static void saveLast(Context ctx, String key) {
        SharedPreferences p = ctx.getSharedPreferences("state", Context.MODE_PRIVATE);
        p.edit()
                .putString("last_key", key)
                .putLong("last_time", System.currentTimeMillis())
                .apply();
        // Also fetch the session's real remaining minutes (idempotent start + status.minutesLeft)
        try {
            String hwid = DeltaStore.extractHwid(null);
            if (hwid != null) {
                Solver.SessionInfo si = Solver.sessionStatus(hwid, s -> { });
                if (si != null && key.equals(si.key) && si.minutesLeft >= 0) {
                    p.edit()
                            .putLong("key_minutes_left", si.minutesLeft)
                            .putLong("key_status_time", System.currentTimeMillis())
                            .apply();
                }
            }
        } catch (Exception ignore) {}
    }

    public static String lastKey(Context ctx) {
        return ctx.getSharedPreferences("state", Context.MODE_PRIVATE).getString("last_key", null);
    }

    public static long lastTime(Context ctx) {
        return ctx.getSharedPreferences("state", Context.MODE_PRIVATE).getLong("last_time", 0);
    }

    /** Remaining minutes captured from the last session status (-1 = unknown). */
    public static long keyMinutesLeft(Context ctx) {
        return ctx.getSharedPreferences("state", Context.MODE_PRIVATE).getLong("key_minutes_left", -1);
    }

    /** When key_minutes_left was captured. */
    public static long keyStatusTime(Context ctx) {
        return ctx.getSharedPreferences("state", Context.MODE_PRIVATE).getLong("key_status_time", 0);
    }
}
