package com.auto.keysolver;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Delta local storage access: HWID extraction + key cache read/write.
 */
public final class DeltaStore {

    private static final File DELTA =
            new File(android.os.Environment.getExternalStorageDirectory(), "Delta");

    private static final String PREF = "state";

    // Key write-back targets (confirmed on a real device)
    private static final String KEY_LICENSE = "Internals/Cache/license";
    private static final String KEY_DELTAKEY = "Internals/Settings/delta_key";
    private static final String[] HWID_FALLBACKS = {
            // confirmed on a real device 2026-10-25 (layout drift: mirror lives in Cache/)
            "Internals/Cache/.license",
            "Internals/.license",
            ".license",
    };

    private static final Pattern HWID_RE = Pattern.compile("[0-9a-f]{64}");
    // Keys look like FREE_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx / KEY_... (UPPERCASE prefix + 32+ hex)
    private static final Pattern KEY_TOKEN_RE = Pattern.compile("[A-Z][A-Z0-9]{1,15}_[0-9a-fA-F]{16,64}");

    private DeltaStore() {}

    // ------------------------------------------------------------------
    // HWID extraction
    // ------------------------------------------------------------------

    /**
     * HWID resolution order:
     *  1. manually entered HWID (user-asserted, survives everything);
     *  2. live .license mirrors (freshest; every fresh read is arbitrated
     *     against the saved value and the raw file is backed up privately);
     *  3. the saved private copy of .license (Delta deletes the file once the
     *     key expires — the copy keeps solving possible afterwards);
     *  4. Crashes (plain-text hwid);
     *  5. the saved HWID string.
     * Fresh reads go through rememberHwid so a wrong HWID can never poison the
     * cache. Returns lowercase 64-hex or null.
     */
    public static String extractHwid(Context ctx, Consumer<String> log) {
        // 0) manually entered HWID
        String manual = manualHwid(ctx);
        if (manual != null) {
            if (log != null) log.accept("[hwid] using manually entered HWID");
            return manual;
        }
        // 0b) Delta root sanity, so a "no hit" is never silent about the cause
        if (!DELTA.exists()) {
            if (log != null) log.accept("[hwid] " + DELTA.getPath()
                    + " does not exist (install and open Delta once first)");
        } else if (!DELTA.isDirectory() || !DELTA.canRead()) {
            if (log != null) log.accept("[hwid] " + DELTA.getPath()
                    + " not readable (All files access not granted?)");
        }
        // 1) .license (the HWID mirror written by the engine itself)
        for (String p : HWID_FALLBACKS) {
            String hwid = tryMirror(ctx, new File(DELTA, p), log);
            if (hwid != null) {
                if (log != null) log.accept("[hwid] from " + p);
                return hwid;
            }
        }
        // 2) layout drift across Delta versions/devices: any mirror-named file under Delta
        for (File f : findLicenseFiles(DELTA, 0)) {
            if (f.equals(new File(DELTA, "Internals/.license"))
                    || f.equals(new File(DELTA, ".license"))) continue;
            String hwid = tryMirror(ctx, f, log);
            if (hwid != null) {
                if (log != null) log.accept("[hwid] from " + f.getPath());
                return hwid;
            }
        }
        if (log != null) log.accept("[hwid] no hit in live .license, trying saved backup");
        // 3) the saved private copy of .license (survives Delta's expiry wipe)
        byte[] backup = readLicenseBackup(ctx);
        if (backup != null) {
            boolean[] fromHead = new boolean[1];
            String hwid = hwidFromMirror(backup, log, fromHead);
            if (hwid != null) {
                if (log != null) log.accept("[hwid] decoded from saved .license backup");
                ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                        .edit().putString("last_hwid", hwid).apply();
                return hwid;
            }
        }
        if (log != null) log.accept("[hwid] no backup hit, trying Crashes");
        // 4) newest 5 files in Crashes (plain-text hwid)
        String hw = crashesHwid(log);
        if (hw != null) {
            if (log != null) log.accept("[hwid] from Crashes");
            return rememberHwid(ctx, hw, "Crashes", log);
        }
        // 5) the saved HWID string
        String saved = savedHwid(ctx, log);
        if (saved != null) {
            if (log != null) log.accept("[hwid] using saved HWID (mirror files deleted)");
            return saved;
        }
        if (log != null) log.accept("[hwid] no hwid found on this device");
        return null;
    }

    /** Read + decode one mirror file, logging exactly why it failed. Returns lowercase 64-hex or null. */
    private static String tryMirror(Context ctx, File f, Consumer<String> log) {
        String p = f.getPath();
        if (!f.exists()) {
            if (log != null) log.accept("[hwid] " + p + ": not found");
            return null;
        }
        if (!f.isFile()) {
            if (log != null) log.accept("[hwid] " + p + ": not a regular file");
            return null;
        }
        byte[] raw = readBytes(f, 1 << 20);
        if (raw == null) {
            if (log != null) log.accept("[hwid] " + p + ": read failed (no permission?)");
            return null;
        }
        if (raw.length == 0) {
            if (log != null) log.accept("[hwid] " + p + ": empty (0 bytes)");
            return null;
        }
        boolean[] fromHead = new boolean[1];
        String hwid = hwidFromMirror(raw, log, fromHead);
        if (hwid == null) {
            if (log != null) log.accept("[hwid] " + p + ": unrecognized (" + raw.length
                    + " bytes, head=" + headHex(raw, 24) + ")");
            return null;
        }
        saveLicenseBackup(ctx, raw);
        return rememberHwid(ctx, hwid, fromHead[0] ? "delta-head" : "mirror", log);
    }

    /** Keep a private copy of the raw .license so solving survives Delta's expiry wipe. */
    private static void saveLicenseBackup(Context ctx, byte[] raw) {
        if (ctx == null) return;
        try (FileOutputStream o = ctx.openFileOutput("license_backup.bin", Context.MODE_PRIVATE)) {
            o.write(raw);
        } catch (Exception ignore) {}
    }

    private static byte[] readLicenseBackup(Context ctx) {
        try (FileInputStream in = ctx.openFileInput("license_backup.bin")) {
            byte[] buf = new byte[1 << 20];
            int n = 0, r;
            while (n < buf.length && (r = in.read(buf, n, buf.length - n)) > 0) n += r;
            return n > 0 ? java.util.Arrays.copyOf(buf, n) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Manual HWID override entered by the user (null clears it). */
    public static void setManualHwid(Context ctx, String hwid) {
        SharedPreferences p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        if (hwid == null) {
            p.edit().remove("manual_hwid").apply();
        } else {
            p.edit().putString("manual_hwid", hwid).putString("last_hwid", hwid).apply();
        }
    }

    static String manualHwid(Context ctx) {
        if (ctx == null) return null;
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getString("manual_hwid", null);
    }

    /**
     * Save a freshly read HWID and arbitrate against the saved one. The saved
     * copy is what keeps solving possible after Delta deletes .license (key
     * expiry), so a wrong overwrite must never happen: when the fresh value
     * differs, decide with the live key (the identifier must validate); with
     * no usable key, only an authoritative delta-XOR head decode may win.
     */
    private static String rememberHwid(Context ctx, String hwid, String source,
                                       Consumer<String> log) {
        if (ctx == null) return hwid;
        SharedPreferences p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        String manual = p.getString("manual_hwid", null);
        if (manual != null) {
            // user-asserted override: arbitration must never overwrite it
            if (!manual.equals(hwid) && log != null) {
                log.accept("[hwid] NOTE: fresh " + source + " hwid differs from the manual override, keeping manual");
            }
            return manual;
        }
        String saved = p.getString("last_hwid", null);
        if (saved == null || saved.equals(hwid)) {
            p.edit().putString("last_hwid", hwid).apply();
            return hwid;
        }
        String key = p.getString("last_key", null);
        if (key != null) {
            boolean freshOk = quietWhitelist(hwid, key);
            boolean savedOk = quietWhitelist(saved, key);
            if (freshOk && !savedOk) {
                if (log != null) log.accept("[hwid] mismatch: fresh " + source
                        + " verified against the live key -> updating saved");
                p.edit().putString("last_hwid", hwid).apply();
                return hwid;
            }
            if (savedOk && !freshOk) {
                if (log != null) log.accept("[hwid] mismatch: fresh from " + source
                        + " REJECTED by the live key, keeping saved");
                return saved;
            }
        }
        if ("delta-head".equals(source)) {
            if (log != null) log.accept("[hwid] mismatch: trusting authoritative delta-head decode");
            p.edit().putString("last_hwid", hwid).apply();
            return hwid;
        }
        if (log != null) log.accept("[hwid] mismatch: fresh from " + source
                + " not verifiable, keeping saved");
        return saved;
    }

    /** Live-key arbitration: identifier(hwid) + key must validate server-side. */
    private static boolean quietWhitelist(String hwid, String key) {
        try {
            return Solver.whitelistValid(Solver.identifierFor(hwid), key);
        } catch (Exception e) {
            return false;
        }
    }

    /** HWID saved from an earlier fresh read (survives Delta's .license wipe). */
    static String savedHwid(Context ctx, Consumer<String> log) {
        if (ctx == null) return null;
        String s = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getString("last_hwid", null);
        if (s != null && !HWID_RE.matcher(s).matches()) {
            if (log != null) log.accept("[hwid] saved HWID malformed, ignored");
            return null;
        }
        return s;
    }

    private static String headHex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n && i < b.length; i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    /** Mirror-named files (".license" / "license" / ".license*") under Delta, depth <= 3, max 50. */
    private static List<File> findLicenseFiles(File dir, int depth) {
        List<File> out = new ArrayList<>();
        if (depth > 3 || !dir.canRead()) return out;
        File[] kids = dir.listFiles();
        if (kids == null) return out;
        for (File f : kids) {
            if (out.size() >= 50) break;
            String n = f.getName();
            if (f.isFile() && (n.equals(".license") || n.equals("license")
                    || n.startsWith(".license"))) {
                out.add(f);
            } else if (f.isDirectory()) {
                out.addAll(findLicenseFiles(f, depth + 1));
            }
        }
        return out;
    }

    /**
     * Decode the engine's HWID mirror. Three layouts exist:
     *  (a) current format with head (verified 2026-10-25 on a real device file):
     *      the file starts with a delta-XOR chain — stream[i] = raw[i] ^ stream[i-1]
     *      with an unknown seed byte — whose first 65 decoded bytes are the plain
     *      HWID plus a repeat of its own first char; the rest of the file is a
     *      plain repetition of the HWID rotated by 6 hex chars. The head is
     *      authoritative, so decode it (no phase assumption needed).
     *  (b) legacy format: the plain HWID repeated from byte 0 — the repeating
     *      unit already is the HWID, use it as-is (resolveMirror's fixed
     *      de-rotation would corrupt this layout).
     *  (c) current format without a decodable head: only the rotated repetition —
     *      occurrence counts cannot decide the phase (N vs N-1), so hand the
     *      unit to resolveMirror (Crashes cross-check, else fixed de-rotation).
     */
    private static String hwidFromMirror(byte[] raw, Consumer<String> log, boolean[] fromHead) {
        if (raw == null || raw.length == 0) return null;
        String head = deltaHeadHwid(raw);
        if (head != null) {
            if (log != null) log.accept("[hwid] delta-XOR head decoded");
            fromHead[0] = true;
            return head;
        }
        String text = new String(raw, StandardCharsets.UTF_8);
        String unit = modeHex(text);
        if (unit == null) return null;
        if (isPureTiling(text, unit)) return unit;
        return resolveMirror(unit, log);
    }

    /**
     * Legacy mirror layout test: optional BOM/leading whitespace, then the unit
     * repeated back-to-back, then optional trailing whitespace. The head-less
     * current format fails this (its repetition starts after the '9' marker or
     * after binary garbage), so it falls through to resolveMirror.
     */
    private static boolean isPureTiling(String text, String unit) {
        int i = 0;
        if (text.startsWith("\uFEFF")) i = 1;
        while (i < text.length() && Character.isWhitespace(text.charAt(i))) i++;
        for (; i + 64 <= text.length(); i += 64) {
            if (!text.regionMatches(i, unit, 0, 64)) return false;
        }
        for (; i < text.length(); i++) {
            if (!Character.isWhitespace(text.charAt(i))) return false;
        }
        return true;
    }

    /**
     * Restore the true HWID phase from the .license mirror unit. The mirror is the
     * same 32-byte block repeated N times, and the block is a ROTATION of the HWID
     * (confirmed 2026-10-25: each copy = last 3 bytes first). In a periodic file all
     * 64 rotations occur almost equally often (N vs N-1), so the phase cannot be
     * decided by counts. Strategy:
     *   1) if a plain hwid from Crashes is a rotation of the mirror unit -> use it
     *      (cross-validated, no phase assumption)
     *   2) otherwise undo the fixed mirror layout: move the first 6 hex chars to the end
     */
    private static String resolveMirror(String unit, Consumer<String> log) {
        String plain = crashesHwid(null);
        if (plain != null) {
            for (int k = 0; k < 64; k++) {
                if (rotate(unit, k).equals(plain)) {
                    if (log != null) log.accept("[hwid] cross-checked with Crashes");
                    return plain;
                }
            }
        }
        if (log != null) log.accept("[hwid] mirror de-rotated (3 bytes)");
        return unit.substring(6) + unit.substring(0, 6);
    }

    private static String rotate(String s, int k) {
        return s.substring(k) + s.substring(0, k);
    }

    /**
     * Delta-XOR head decode: brute-force the 256 possible seed bytes; the real
     * seed is the only one whose first 65 decoded bytes are all hex with byte 64
     * repeating byte 0. Returns lowercase 64-hex, or null when the head is absent.
     */
    private static String deltaHeadHwid(byte[] raw) {
        if (raw == null || raw.length < 65) return null;
        for (int seed = 0; seed < 256; seed++) {
            char[] out = new char[65];
            int prev = seed;
            boolean hex = true;
            for (int i = 0; i < 65; i++) {
                int cur = (raw[i] & 0xFF) ^ prev;
                char c = (char) cur;
                if (c >= 'A' && c <= 'F') c = (char) (c + 32);
                if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                    hex = false;
                    break;
                }
                out[i] = c;
                prev = cur;
            }
            if (hex && out[64] == out[0]) return new String(out, 0, 64);
        }
        return null;
    }

    /** Most frequent 64-hex across the newest 5 files in Crashes (plain hwid). */
    private static String crashesHwid(Consumer<String> log) {
        File[] files = new File(DELTA, "Crashes").listFiles();
        if (files == null) {
            if (log != null) log.accept("[hwid] Crashes unreadable");
            return null;
        }
        Arrays.sort(files, (a, b) -> Long.compare(b.lastModified(), a.lastModified()));
        int checked = 0;
        for (File f : files) {
            if (checked >= 5) break;
            if (!f.isFile()) continue;
            checked++;
            String hwid = modeHex(readText(f, 1 << 20));
            if (hwid != null) {
                if (log != null) log.accept("[hwid] from Crashes/" + f.getName());
                return hwid;
            }
        }
        if (log != null && checked > 0) {
            log.accept("[hwid] Crashes: no plain hwid in newest " + checked + " file(s)");
        }
        return null;
    }

    /**
     * Most frequent 64-char lowercase hex string in the text. Inside a periodic
     * mirror (.license) this is the repeating unit itself (its phase may be a
     * rotated value, restored by hwidFromMirror/resolveMirror); in plain text
     * (Crashes logs) it is the plain hwid (rotations occur 0 times, rot_0 wins).
     */
    private static String modeHex(String text) {
        if (text == null || text.isEmpty()) return null;
        Matcher m = HWID_RE.matcher(text);
        Map<String, Integer> count = new HashMap<>();
        while (m.find()) {
            String k = m.group();
            Integer c = count.get(k);
            count.put(k, c == null ? 1 : c + 1);
        }
        if (count.isEmpty()) return null;
        List<String> candidates = new ArrayList<>(count.keySet());
        candidates.sort((a, b) -> count.get(b) - count.get(a));
        String best = null;
        int bestN = -1;
        int checked = 0;
        for (String run : candidates) {
            if (checked++ >= 3) break; // only examine the top few candidates
            for (int k = 0; k < 64; k++) {
                String rot = run.substring(k) + run.substring(0, k);
                int n = countOccurrences(text, rot);
                if (n > bestN) {
                    bestN = n;
                    best = rot;
                }
            }
        }
        return best;
    }

    private static int countOccurrences(String text, String pat) {
        int n = 0;
        int i = 0;
        while ((i = text.indexOf(pat, i)) >= 0) {
            n++;
            i++;
        }
        return n;
    }

    // ------------------------------------------------------------------
    // key read/write (two targets only:
    // Internals/Cache/license + Internals/Settings/delta_key)
    // ------------------------------------------------------------------

    /** Existing key: read both target paths, return the first key token. */
    public static String findExistingKey() {
        String[] paths = {KEY_LICENSE, KEY_DELTAKEY};
        for (String p : paths) {
            String token = firstKeyToken(readText(new File(DELTA, p), 1 << 20));
            if (token != null) return token;
        }
        return null;
    }

    /**
     * Write the key back to Delta's two key cache files so Delta opens already
     * verified (on startup Delta reads delta_key/license, re-validates against
     * the server, and unlocks when valid). Files are always created if missing;
     * content is the bare key on a single line, no newline, no spaces.
     * Never touches .license (the HWID state file) or user scripts.
     */
    public static List<String> writeKey(String key, Consumer<String> log) {
        List<String> written = new ArrayList<>();
        writeKeyPath(KEY_LICENSE, key, written, log);
        writeKeyPath(KEY_DELTAKEY, key, written, log);
        return written;
    }

    private static void writeKeyPath(String rel, String key, List<String> written,
                                     Consumer<String> log) {
        File f = new File(DELTA, rel);
        File parent = f.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            if (log != null) log.accept("[!] cannot create directory: " + rel);
            return;
        }
        // Light guard: leave pre-existing large files without a key token alone
        String content = readText(f, 1 << 20);
        if (content != null && content.length() > 4096
                && firstKeyToken(content) == null) {
            if (log != null) log.accept("[!] " + rel
                    + " is an unknown large file, skipped");
            return;
        }
        try (FileOutputStream o = new FileOutputStream(f, false)) {
            o.write(key.getBytes(StandardCharsets.UTF_8)); // bare key, no newline
            written.add(rel);
            if (log != null) log.accept("[write] " + rel + " <- " + key);
        } catch (Exception e) {
            if (log != null) log.accept("[!] write failed " + rel + ": " + e);
        }
    }

    static String firstKeyToken(String text) {
        if (text == null || text.isEmpty()) return null;
        Matcher m = KEY_TOKEN_RE.matcher(text);
        return m.find() ? m.group() : null;
    }

    // ------------------------------------------------------------------
    // File IO
    // ------------------------------------------------------------------

    private static String readText(File f, int max) {
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[max];
            int n = in.read(buf);
            if (n <= 0) return "";
            return new String(buf, 0, n, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readBytes(File f, int max) {
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[max];
            int n = 0;
            while (n < max) {
                int r = in.read(buf, n, max - n);
                if (r < 0) break;
                n += r;
            }
            if (n <= 0) return null;
            return Arrays.copyOf(buf, n);
        } catch (Exception e) {
            return null;
        }
    }
}
