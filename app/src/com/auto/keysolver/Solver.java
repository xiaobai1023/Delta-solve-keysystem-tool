package com.auto.keysolver;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Delta key solver (ported from delta_bypass_real/auth_client.py + main.py, verified on device).
 *
 * Flow:
 *   identifier = SHA-256(HWID lowercase 64-hex)
 *   POST {api}/public/start {"service":6,"identifier":ident} -> data.url = auth.platorelay.com/a?d=<ticket>
 *   GET  auth/api/session/metadata?ticket=  -> service + checkpointCount
 *   PUT  auth/api/session/step?ticket=&service=N  body={captcha:null,meta:hex,stream:hex,resolved:true}
 *        - meta/stream = browser-fingerprint JSON encrypted with AES-CTR (ticket slices as key/iv), hex encoded
 *   data.url == "about:blank" -> poll GET session/status for data.key
 *   data.url with r= param -> base64url-decode callback URL -> new ticket -> next round
 *   GET {api}/public/whitelist/6?identifier=&key= -> data.valid == true
 */
public final class Solver {

    public interface Log {
        void log(String s);
    }

    public static class SolverException extends Exception {
        SolverException(String msg) { super(msg); }
    }

    private static final String API_MAIN = "https://api.platorelay.com";
    private static final String API_FALLBACK = "https://api.platoboost.net";
    private static final String AUTH_API = "https://auth.platorelay.com/api";

    // Client UA for the public/* endpoints (same as renew.py)
    private static final String UA_PUBLIC = "Platoboost Android Client/1.0";
    // Browser UA for step requests (auth_client.py FALLBACK_UA; proven fallback when
    // fake_useragent is unavailable)
    private static final String UA_BROWSER =
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) "
                    + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.1";
    private static final String SCREEN = "390x844"; // SCREENS_IPHONE[0], bound to the UA

    private static final String CLIENT_VERSION = "8.2.0"; // known-good x-client-version
    private static final int MIN_TICKET_LEN = 33;
    private static final int POLL_MAX_ATTEMPTS = 10;
    private static final long POLL_INTERVAL_MS = 100;
    private static final int STEP_HTTP_RETRIES = 3;
    private static final long STEP_RETRY_SLEEP_MS = 500;
    private static final int STEP_THROTTLE_RETRIES = 2;
    private static final long STEP_THROTTLE_SLEEP_MS = 2000;
    private static final int[] FALLBACK_SERVICES = {3, 6, 8, 7, 5, 2, 1};
    private static final String[] INVALID_MARKERS = {
            "invalid payload", "expired", "not found", "invalid session",
            "invalid ticket", "does not exist"
    };

    private static volatile String sVersion = CLIENT_VERSION;
    private static final SecureRandom RNG = new SecureRandom();

    private Solver() {}

    // ------------------------------------------------------------------
    // Public entry points
    // ------------------------------------------------------------------

    /** HWID -> identifier (lowercase sha256 hex). */
    public static String identifierFor(String hwid) throws Exception {
        return sha256Hex(hwid.trim().toLowerCase());
    }

    /** Full solve: start -> solve chain -> whitelist verification. Returns a verified key. */
    public static String solveForHwid(String hwid, Consumer<String> log) throws Exception {
        String ident = identifierFor(hwid);
        log.accept("[ident] " + ident);
        String base = pickApiBase(log);

        JSONObject start = httpJsonApi("POST", base + "/public/start",
                "{\"service\":6,\"identifier\":\"" + ident + "\"}");
        if (!start.optBoolean("success", false)) {
            throw new SolverException("start failed: " + clip(start.toString(), 160));
        }
        String url = start.optJSONObject("data").optString("url", "");
        if (url.isEmpty()) throw new SolverException("no url in start response");
        String ticket = queryParam(url, "d");
        if (ticket == null || ticket.length() < MIN_TICKET_LEN) {
            throw new SolverException("invalid ticket (len=" + (ticket == null ? 0 : ticket.length()) + ")");
        }
        log.accept("[ticket] " + clip(ticket, 24) + "... (" + ticket.length() + " chars)");

        String key = solveChain(ticket, log);
        if (key == null) throw new SolverException("solve chain produced no key");
        log.accept("[key] " + key);

        // Final whitelist verification
        String wl = httpGetApi(base + "/public/whitelist/6?identifier=" + quote(ident)
                + "&key=" + quote(key));
        JSONObject wj = tryParse(wl);
        boolean valid = wj != null && wj.optJSONObject("data") != null
                && wj.optJSONObject("data").optBoolean("valid", false);
        log.accept("[whitelist] valid=" + valid);
        if (!valid) throw new SolverException("whitelist check failed: " + clip(wl, 160));
        return key;
    }

    /** Standalone whitelist check (is an existing key still valid?). */
    public static boolean whitelistValid(String ident, String key) {
        try {
            String base = pickApiBase(null);
            String body = httpGetApi(base + "/public/whitelist/6?identifier=" + quote(ident)
                    + "&key=" + quote(key));
            JSONObject wj = tryParse(body);
            return wj != null && wj.optJSONObject("data") != null
                    && wj.optJSONObject("data").optBoolean("valid", false);
        } catch (Exception e) {
            return false;
        }
    }

    public static class SessionInfo {
        public String key = "";
        public long minutesLeft = -1; // -1 = not provided by the server
    }

    /**
     * Query the current session's key and remaining minutes (ground truth).
     * /public/start is idempotent per identifier -> session/status returns
     * {"key": "...", "minutesLeft": N}.
     */
    public static SessionInfo sessionStatus(String hwid, Consumer<String> log) throws Exception {
        String ident = identifierFor(hwid);
        String base = pickApiBase(log);
        JSONObject start = httpJsonApi("POST", base + "/public/start",
                "{\"service\":6,\"identifier\":\"" + ident + "\"}");
        if (!start.optBoolean("success", false)) {
            throw new SolverException("start failed: " + clip(start.toString(), 120));
        }
        String url = start.optJSONObject("data").optString("url", "");
        String ticket = queryParam(url, "d");
        if (ticket == null || ticket.length() < MIN_TICKET_LEN) {
            throw new SolverException("invalid ticket");
        }
        JSONObject st = tryParse(getJson("session/status?ticket=" + quote(ticket)));
        JSONObject d = st == null ? null : st.optJSONObject("data");
        if (d == null) d = st;
        SessionInfo si = new SessionInfo();
        if (d != null) {
            si.key = d.optString("key", "");
            si.minutesLeft = d.optLong("minutesLeft", -1L);
        }
        return si;
    }

    // ------------------------------------------------------------------
    // Solve chain (port of main.solve_chain)
    // ------------------------------------------------------------------

    private static String solveChain(String ticket, Consumer<String> log) throws Exception {
        int maxRounds = 3;
        String currentTicket = ticket;
        int service = -1; // service reported by metadata
        int round = 0;
        String lastExit = "round-exhausted";

        while (round < maxRounds) {
            log.accept("[round " + (round + 1) + "/" + maxRounds + "]");

            // Round 0: check status first; public/start is idempotent, so a completed
            // session hands us the key immediately
            if (round == 0) {
                String early = checkKey(currentTicket);
                if (early != null) {
                    log.accept("[early] session already completed, KEY obtained");
                    return early;
                }
            }

            // metadata: service + checkpointCount
            int cpc = -1;
            JSONObject meta = tryParse(getJson("session/metadata?ticket=" + quote(currentTicket)));
            if (meta != null && !meta.optBoolean("success", true)
                    && !meta.optBoolean("transient", false)) {
                String msg = (meta.optString("message") + " " + meta.optString("error")).toLowerCase();
                for (String m : INVALID_MARKERS) {
                    if (msg.contains(m)) {
                        throw new SolverException("link invalid/expired: " + clip(msg, 120));
                    }
                }
            }
            JSONObject data = meta == null ? null : meta.optJSONObject("data");
            if (data == null) data = meta;
            if (data != null) {
                JSONObject profile = data.optJSONObject("activeRevenueProfile");
                if (profile != null && profile.has("service")) {
                    service = profile.optInt("service", -1);
                    cpc = profile.optInt("checkpointCount", 0);
                    log.accept("[meta] service=" + service + " checkpointCount=" + cpc);
                }
            }
            if (cpc > 0 && cpc + 1 > maxRounds) {
                maxRounds = Math.min(cpc + 1, 12);
                log.accept("[rounds] checkpointCount=" + cpc + " -> need " + (cpc + 1) + " rounds");
            }

            // step (with service fallback / throttle backoff / version probing)
            StepResult sr = doStepWithRetry(currentTicket, service, log);
            if (sr.key != null) return sr.key;
            if (!sr.ok) {
                log.accept("[-] step failed on all services: " + clip(sr.error, 120));
                lastExit = "step-failed";
                round++;
                continue;
            }
            service = sr.service;

            String url = sr.url;
            if (url == null || url.isEmpty()) {
                log.accept("[-] no URL in response");
                lastExit = "no-url";
                round++;
                continue;
            }
            log.accept("[url] " + clip(url, 80));

            if ("about:blank".equals(url)) {
                log.accept("[poll] polling for key (max " + POLL_MAX_ATTEMPTS + " tries)...");
                String key = pollForKey(currentTicket);
                if (key != null) return key;
                log.accept("[-] key not ready after polling");
                lastExit = "poll-timeout";
                round++;
                continue;
            }

            // decode r= param -> next ticket
            String callback = decodeCallbackUrl(url);
            if (callback != null) {
                String next = queryParam(callback, "d");
                if (next != null && next.length() > 50) {
                    log.accept("[next] new ticket " + clip(next, 24) + "... (" + next.length() + " chars)");
                    currentTicket = next;
                    round++;
                    continue;
                }
            }

            // no r= callback -> query the session key directly
            log.accept("[info] no r= callback, querying session key...");
            String key = checkKey(currentTicket);
            if (key != null) return key;
            lastExit = "no-callback-no-key";
            break;
        }

        String key = checkKey(currentTicket);
        if (key != null) return key;
        throw new SolverException("solve failed (reason: " + lastExit + ")");
    }

    private static class StepResult {
        boolean ok;
        int service = -1;
        String url;
        String key;
        String error = "unknown";
    }

    private static StepResult doStepWithRetry(String ticket, int serviceHint, Consumer<String> log) throws Exception {
        List<Integer> services = new ArrayList<>();
        if (serviceHint > 0) services.add(serviceHint);
        for (int s : FALLBACK_SERVICES) if (!services.contains(s)) services.add(s);

        StepResult last = new StepResult();
        for (int svc : services) {
            for (int attempt = 0; attempt <= STEP_THROTTLE_RETRIES; attempt++) {
                HttpResult r = stepHttp(ticket, svc, sVersion);
                if (r.code != 200) {
                    last.error = "http " + r.code + " " + clip(r.body, 80);
                    sleep(STEP_RETRY_SLEEP_MS);
                    continue;
                }
                if (r.body.contains("outdated client")) {
                    log.accept("[ver] " + sVersion + " outdated, probing upward...");
                    String fresh = probeVersionUpward(log);
                    if (fresh != null && !fresh.equals(sVersion)) {
                        sVersion = fresh;
                        log.accept("[ver] updated to " + fresh);
                        continue; // retry the same service
                    }
                    last.error = "no working client version";
                    break;
                }
                JSONObject resp = tryParse(r.body);
                if (resp == null) {
                    last.error = "non-json";
                    sleep(STEP_RETRY_SLEEP_MS);
                    continue;
                }
                if (resp.optString("message", "").toLowerCase().contains("account-unlock-required")
                        || r.body.contains("account-unlock-required")) {
                    throw new SolverException("Server requires Discord unlock (unsupported in this APK)");
                }
                String low = resp.optString("message", "").toLowerCase();
                if (isThrottled(resp)) {
                    log.accept("[step] service=" + svc + " throttled, backing off");
                    sleep(STEP_THROTTLE_SLEEP_MS);
                    continue;
                }
                if (low.contains("incorrect service") || low.contains("service (advertiser) not found")
                        || low.contains("service not found")) {
                    last.error = clip(low, 80);
                    break; // try the next service
                }
                if (resp.optBoolean("success", false)) {
                    last.ok = true;
                    last.service = svc;
                    JSONObject d = resp.optJSONObject("data");
                    last.url = d == null ? "" : d.optString("url", "");
                    return last;
                }
                last.error = clip(resp.toString(), 160);
                break;
            }
        }
        return last;
    }

    private static boolean isThrottled(JSONObject r) {
        String msg = (r.optString("message") + " " + r.optString("error") + " "
                + r.optString("detail")).toLowerCase();
        return msg.contains("too fast") || msg.contains("slow down") || msg.contains("too many");
    }

    // ------------------------------------------------------------------
    // step HTTP (port of auth_client.do_step + build_meta_stream)
    // ------------------------------------------------------------------

    private static class HttpResult {
        int code;
        String body = "";
    }

    private static HttpResult stepHttp(String ticket, int service, String version) throws Exception {
        if (ticket.length() < MIN_TICKET_LEN) {
            throw new SolverException("ticket too short");
        }
        String meta = aesCtrHex(metaPlain(), ticket.substring(0, 16), ticket.substring(16, 32));
        String stream = aesCtrHex(streamPlain(), ticket.substring(1, 17), ticket.substring(17, 33));
        String body = new JSONObject()
                .put("captcha", JSONObject.NULL)
                .put("meta", meta)
                .put("stream", stream)
                .put("resolved", true)
                .toString();

        String url = AUTH_API + "/session/step?ticket=" + quote(ticket) + "&service=" + service;
        Exception lastErr = null;
        for (int attempt = 0; attempt <= STEP_HTTP_RETRIES; attempt++) {
            try {
                return httpRaw("PUT", url, body, browserHeaders(version));
            } catch (Exception e) {
                lastErr = e;
                sleep(STEP_RETRY_SLEEP_MS);
            }
        }
        HttpResult r = new HttpResult();
        r.code = -1;
        r.body = String.valueOf(lastErr);
        return r;
    }

    private static Map<String, String> browserHeaders(String version) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", UA_BROWSER);
        h.put("Content-Type", "application/json");
        h.put("Accept", "application/json, text/plain, */*");
        h.put("x-client-name", "platoboost webclient");
        h.put("x-client-version", version);
        return h;
    }

    private static String metaPlain() throws Exception {
        return new JSONObject()
                .put("browserInfo", new JSONArray().put(new JSONObject()
                        .put("screen", SCREEN)
                        .put("ua", UA_BROWSER)
                        .put("time", System.currentTimeMillis())))
                .toString();
    }

    private static String streamPlain() throws Exception {
        return new JSONObject()
                .put("events", new JSONArray().put(new JSONObject()
                        .put("event", 1)
                        .put("data", new JSONObject().put("time", System.currentTimeMillis()))))
                .toString();
    }

    /** AES-CTR(NoPadding) then lowercase hex. Java's 16-byte big-endian counter
     *  increment matches the hand-rolled CTR in the Python original. */
    private static String aesCtrHex(String plain, String keyStr, String ivStr) throws Exception {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyStr.getBytes(StandardCharsets.UTF_8), "AES"),
                new IvParameterSpec(ivStr.getBytes(StandardCharsets.UTF_8)));
        return hex(c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }

    // ------------------------------------------------------------------
    // Version probing (simplified port of auth_client._probe_version_upward)
    // ------------------------------------------------------------------

    private static String probeVersionUpward(Consumer<String> log) throws Exception {
        int major = 8;
        try {
            major = Integer.parseInt(sVersion.split("\\.")[0]);
        } catch (Exception ignore) {}
        for (int m = major; m <= 40; m++) {
            String cand = m + ".0.0";
            if (versionWorks(cand)) return cand;
            for (int minor = 1; minor <= 3; minor++) {
                cand = m + "." + minor + ".0";
                if (versionWorks(cand)) return cand;
            }
        }
        return sVersion;
    }

    /** Fake-ticket probe: the server checks the version before the ticket,
     *  so "outdated client" means the version is no good. */
    private static boolean versionWorks(String version) throws Exception {
        String fake = randomToken(64);
        String meta = aesCtrHex(metaPlain(), fake.substring(0, 16), fake.substring(16, 32));
        String stream = aesCtrHex(streamPlain(), fake.substring(1, 17), fake.substring(17, 33));
        String body = new JSONObject()
                .put("captcha", JSONObject.NULL)
                .put("meta", meta)
                .put("stream", stream)
                .put("resolved", true)
                .toString();
        HttpResult r = httpRaw("PUT",
                AUTH_API + "/session/step?ticket=" + quote(fake) + "&service=3",
                body, browserHeaders(version));
        return r.code == 200 && !r.body.contains("outdated client");
    }

    // ------------------------------------------------------------------
    // Status polling
    // ------------------------------------------------------------------

    private static String pollForKey(String ticket) {
        for (int i = 0; i < POLL_MAX_ATTEMPTS; i++) {
            String key = checkKey(ticket);
            if (key != null) return key;
            sleep(POLL_INTERVAL_MS);
        }
        return null;
    }

    private static String checkKey(String ticket) {
        try {
            JSONObject st = tryParse(getJson("session/status?ticket=" + quote(ticket)));
            if (st == null) return null;
            JSONObject d = st.optJSONObject("data");
            if (d == null) d = st;
            String key = d.optString("key", "");
            if (!key.isEmpty() && !"KEY_NOT_FOUND".equals(key)) return key;
        } catch (Exception ignore) {}
        return null;
    }

    // ------------------------------------------------------------------
    // API domain probing
    // ------------------------------------------------------------------

    private static String pickApiBase(Consumer<String> log) {
        try {
            HttpResult r = httpRaw("GET", API_MAIN + "/public/connectivity", null, publicHeaders());
            if (r.code == 200 || r.code == 429) return API_MAIN;
        } catch (Exception e) {
            if (log != null) log.accept("[net] primary API unreachable: " + e);
        }
        return API_FALLBACK;
    }

    private static Map<String, String> publicHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", UA_PUBLIC);
        h.put("Accept", "application/json");
        return h;
    }

    private static String getJson(String pathQs) throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                HttpResult r = httpRaw("GET", AUTH_API + "/" + pathQs, null, publicHeaders());
                if (r.code != 200) {
                    JSONObject o = new JSONObject();
                    o.put("success", false);
                    o.put("error", "http " + r.code);
                    o.put("transient", true);
                    return o.toString();
                }
                return r.body;
            } catch (Exception e) {
                last = e;
                sleep(250);
            }
        }
        JSONObject o = new JSONObject();
        o.put("success", false);
        o.put("error", String.valueOf(last));
        o.put("transient", true);
        return o.toString();
    }

    private static JSONObject httpJsonApi(String method, String url, String body) throws Exception {
        HttpResult r = httpRaw(method, url, body, publicHeaders());
        JSONObject o = tryParse(r.body);
        return o == null ? new JSONObject() : o;
    }

    private static String httpGetApi(String url) throws Exception {
        return httpRaw("GET", url, null, publicHeaders()).body;
    }

    // ------------------------------------------------------------------
    // HTTP base
    // ------------------------------------------------------------------

    private static HttpResult httpRaw(String method, String url, String body,
                                      Map<String, String> headers) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(8000);
        conn.setReadTimeout(10000);
        conn.setInstanceFollowRedirects(false);
        for (Map.Entry<String, String> e : headers.entrySet()) {
            conn.setRequestProperty(e.getKey(), e.getValue());
        }
        if (body != null) {
            conn.setRequestMethod(method);
            conn.setDoOutput(true);
            // HttpURLConnection defaults to application/x-www-form-urlencoded for
            // request bodies, which the API rejects with Unsupported Media Type.
            if (!headers.containsKey("Content-Type")) {
                conn.setRequestProperty("Content-Type", "application/json");
            }
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(b.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(b);
            }
        } else {
            conn.setRequestMethod(method);
        }
        int code = conn.getResponseCode();
        InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String text = readAll(in);
        conn.disconnect();
        HttpResult r = new HttpResult();
        r.code = code;
        r.body = text == null ? "" : text;
        return r;
    }

    private static String readAll(InputStream in) throws Exception {
        if (in == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // Small utilities
    // ------------------------------------------------------------------

    /** URL-encoding equivalent to Python urllib.parse.quote(safe='/'). */
    static String quote(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    /** Parse a query parameter (equivalent to Python parse_qs single-value access;
     *  both '+' and %20 decode to a space). */
    static String queryParam(String url, String name) {
        try {
            String q = url;
            int hash = q.indexOf('#');
            if (hash >= 0) q = q.substring(0, hash);
            int qi = q.indexOf('?');
            if (qi < 0) return null;
            q = q.substring(qi + 1);
            for (String kv : q.split("&")) {
                int eq = kv.indexOf('=');
                if (eq < 0) continue;
                if (java.net.URLDecoder.decode(kv.substring(0, eq), "UTF-8").equals(name)) {
                    return java.net.URLDecoder.decode(kv.substring(eq + 1), "UTF-8");
                }
            }
        } catch (Exception ignore) {}
        return null;
    }

    /** loot.link r= param -> base64url-decoded callback URL (port of decode_callback_url). */
    static String decodeCallbackUrl(String lootUrl) {
        String r = queryParam(lootUrl, "r");
        if (r == null || r.isEmpty()) return null;
        String b64 = r.replace('-', '+').replace('_', '/');
        int pad = (4 - b64.length() % 4) % 4;
        try {
            byte[] dec = Base64.getMimeDecoder().decode(b64 + "=".repeat(pad));
            String s = new String(dec, StandardCharsets.UTF_8);
            return s.startsWith("http") ? s : null;
        } catch (Exception e) {
            return null;
        }
    }

    static String sha256Hex(String s) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        return hex(d);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String randomToken(int len) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(alphabet.charAt(RNG.nextInt(alphabet.length())));
        return sb.toString();
    }

    private static JSONObject tryParse(String s) {
        try {
            return new JSONObject(s);
        } catch (Exception e) {
            return null;
        }
    }

    private static String clip(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
