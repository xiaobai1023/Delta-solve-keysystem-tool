package com.auto.keysolver;

import android.Manifest;
import android.app.Activity;
import android.app.TimePickerDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.TimePicker;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/**
 * Auto Key Solver: read HWID -> solve key -> write it back to Delta's cache.
 * Pure native Android APIs, no third-party dependencies.
 */
public class MainActivity extends Activity {

    private TextView statusView;
    private TextView validityView;
    private TextView logView;
    private Switch dailySwitch;
    private boolean solving = false;
    private boolean checking = false;
    private final ArrayDeque<String> logLines = new ArrayDeque<>();
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        refreshStatus();
        ensurePermissions();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Self-heal: swiping the app away (force-stop) cancels all alarms on
        // some ROMs; re-arm the alarm every time the app is opened.
        if (Scheduler.isDaily(this)) {
            Scheduler.scheduleNextDaily(this);
        }
        refreshStatus();
    }

    // ------------------------------------------------------------------
    // UI (built in code, no layout XML)
    // ------------------------------------------------------------------

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Auto Key Solver");
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        statusView = new TextView(this);
        statusView.setTextSize(13);
        statusView.setPadding(0, pad / 2, 0, 0);
        root.addView(statusView);

        validityView = new TextView(this);
        validityView.setTextSize(13);
        validityView.setPadding(0, pad / 4, 0, pad / 2);
        root.addView(validityView);

        dailySwitch = new Switch(this);
        dailySwitch.setText(dailyText());
        dailySwitch.setChecked(Scheduler.isDaily(this));
        dailySwitch.setOnCheckedChangeListener((b, on) -> {
            Scheduler.setDaily(this, on);
            toast(on ? "Daily renewal enabled" : "Daily renewal disabled");
        });
        dailySwitch.setOnClickListener(v -> showTimePicker());
        root.addView(dailySwitch);

        Button solve = new Button(this);
        solve.setText("SOLVE NOW");
        solve.setOnClickListener(v -> startSolve());
        root.addView(solve, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        logView = new TextView(this);
        logView.setTextSize(12);
        logView.setTextIsSelectable(true);
        ScrollView sc = new ScrollView(this);
        sc.addView(logView);
        root.addView(sc, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    private String dailyText() {
        int[] t = Scheduler.getTime(this);
        return String.format(Locale.US, "Daily auto-renew at %02d:%02d (tap to change)", t[0], t[1]);
    }

    private void showTimePicker() {
        int[] t = Scheduler.getTime(this);
        TimePickerDialog dlg = new TimePickerDialog(this, (TimePicker tp, int h, int m) -> {
            Scheduler.setTime(this, h, m);
            dailySwitch.setText(dailyText());
            toast(String.format(Locale.US, "Changed to %02d:%02d daily", h, m));
        }, t[0], t[1], true);
        dlg.show();
    }

    private void refreshStatus() {
        StringBuilder sb = new StringBuilder();
        boolean ok = hasStorage();
        sb.append("File access: ").append(ok ? "granted" : "denied").append('\n');
        if (ok) {
            String hwid = DeltaStore.extractHwid(null);
            if (hwid != null) {
                sb.append("HWID: ").append(hwid).append('\n');
                try {
                    sb.append("identifier: ").append(Solver.identifierFor(hwid)).append('\n');
                } catch (Exception ignore) {}
            } else {
                sb.append("HWID not found (launch the Delta executor first)\n");
            }
            String key = DeltaStore.findExistingKey();
            if (key != null) sb.append("Cached key: ").append(key).append('\n');
        }
        long t = KeyRunner.lastTime(this);
        if (t > 0) {
            sb.append("Last run: ")
                    .append(new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date(t)))
                    .append("  (").append(KeyRunner.lastKey(this)).append(")");
            long ml = KeyRunner.keyMinutesLeft(this);
            long st = KeyRunner.keyStatusTime(this);
            if (ml >= 0 && st > 0) {
                // Ground truth: session status minutesLeft, adjusted to now
                long remainMin = ml - (System.currentTimeMillis() - st) / 60000L;
                long expiryAt = st + ml * 60000L;
                sb.append("\nKey expiry: ")
                        .append(new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                                .format(new Date(expiryAt)));
                if (remainMin > 0) {
                    sb.append(String.format(Locale.US, " (%dh %02dm left)",
                            remainMin / 60, remainMin % 60));
                } else {
                    sb.append(" (expired)");
                }
            } else {
                // No ground truth yet: 24h estimate
                sb.append("\nEstimated expiry: ")
                        .append(new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                                .format(new Date(t + 24L * 3600_000L)))
                        .append(" (24h estimate, see live key status)");
            }
        }
        statusView.setText(sb.toString());
        checkValidityAsync();
    }

    /** Live session query (idempotent start -> status): validity + real remaining minutes. */
    private void checkValidityAsync() {
        if (checking) return;
        final String key = KeyRunner.lastKey(this);
        if (key == null) {
            validityView.setText("");
            return;
        }
        checking = true;
        validityView.setTextColor(0xFF666666);
        validityView.setText("key status: checking...");
        new Thread(() -> {
            boolean valid = false;
            long minutesLeft = -1;
            try {
                String hwid = DeltaStore.extractHwid(null);
                if (hwid != null) {
                    Solver.SessionInfo si = Solver.sessionStatus(hwid, s -> { });
                    if (si != null && key.equals(si.key)) {
                        valid = true;
                        minutesLeft = si.minutesLeft;
                    }
                }
            } catch (Exception e) {
                // Session query failed (rate limited / offline) -> light whitelist check
                try {
                    String hwid = DeltaStore.extractHwid(null);
                    valid = hwid != null
                            && Solver.whitelistValid(Solver.identifierFor(hwid), key);
                } catch (Exception ignore) {}
            }
            final boolean v = valid;
            final long ml = minutesLeft;
            runOnUiThread(() -> {
                checking = false;
                if (isFinishing() || isDestroyed()) return;
                if (v) {
                    if (ml >= 0) {
                        // Store ground truth for offline display
                        getSharedPreferences("state", MODE_PRIVATE).edit()
                                .putLong("key_minutes_left", ml)
                                .putLong("key_status_time", System.currentTimeMillis())
                                .apply();
                        validityView.setText(String.format(Locale.US,
                                "key status: VALID (%dh %02dm left)", ml / 60, ml % 60));
                    } else {
                        validityView.setText("key status: VALID");
                    }
                    validityView.setTextColor(0xFF1B7E3C);
                } else {
                    validityView.setText("key status: EXPIRED (tap SOLVE NOW to renew)");
                    validityView.setTextColor(0xFFB3261E);
                }
            });
        }, "validity").start();
    }

    private void ensurePermissions() {
        if (hasStorage()) {
            if (Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
            }
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            toast("\"All files access\" permission is required to read/write the Delta folder");
            try {
                Intent i = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName()));
                startActivity(i);
            } catch (Exception e) {
                try {
                    startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                } catch (Exception ignore) {}
            }
        } else {
            requestPermissions(new String[]{
                    Manifest.permission.WRITE_EXTERNAL_STORAGE,
                    Manifest.permission.READ_EXTERNAL_STORAGE}, 2);
        }
    }

    private boolean hasStorage() {
        if (Build.VERSION.SDK_INT >= 30) {
            return Environment.isExternalStorageManager();
        }
        return checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    // ------------------------------------------------------------------
    // Solve
    // ------------------------------------------------------------------

    private void startSolve() {
        if (solving) {
            toast("Solving...");
            return;
        }
        if (!hasStorage()) {
            toast("Grant file access first");
            ensurePermissions();
            return;
        }
        solving = true;
        new Thread(() -> {
            try {
                KeyRunner.run(this, s -> appendLog(s));
            } catch (Exception e) {
                appendLog("[-] " + e.getMessage());
            } finally {
                solving = false;
                runOnUiThread(this::refreshStatus);
            }
        }, "solve").start();
    }

    private void appendLog(String s) {
        runOnUiThread(() -> {
            logLines.addLast(fmt.format(new Date()) + ' ' + s);
            while (logLines.size() > 200) logLines.removeFirst();
            logView.setText(TextUtils.join("\n", logLines));
        });
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
