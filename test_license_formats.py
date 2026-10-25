# Regression tests for .license HWID extraction (no external dependencies).
#
# Pure-Python port of the extraction logic in
# app/src/com/auto/keysolver/DeltaStore.java. All samples are SYNTHETIC and
# generated on the fly from known HWIDs; no real device data is included.
#
# Run:  python test_license_formats.py
import hashlib
import re
import sys

HWID_RE = re.compile(r"[0-9a-f]{64}")

# synthetic hwids (sha256 of fixed phrases), aperiodic on purpose so that a
# wrong mirror phase can never accidentally match
HWID_A = hashlib.sha256(b"auto-key-solver-sample-a").hexdigest()
HWID_B = hashlib.sha256(b"auto-key-solver-sample-b").hexdigest()


# ---------------------------------------------------------------------------
# DeltaStore.java port (hwidFromMirror and its helpers)
# ---------------------------------------------------------------------------

def count_occurrences(text, pat):
    n, i = 0, 0
    while True:
        i = text.find(pat, i)
        if i < 0:
            return n
        n += 1
        i += 1


def rotate(s, k):
    return s[k:] + s[:k]


def delta_head_hwid(raw):
    """Brute-force the 256 seed bytes; the real seed decodes 65 hex chars with
    byte 64 repeating byte 0."""
    if raw is None or len(raw) < 65:
        return None
    for seed in range(256):
        out, prev = [], seed
        for i in range(65):
            cur = raw[i] ^ prev
            c = chr(cur)
            if "A" <= c <= "F":
                c = c.lower()
            if not (("0" <= c <= "9") or ("a" <= c <= "f")):
                out = None
                break
            out.append(c)
            prev = cur
        if out is not None and out[64] == out[0]:
            return "".join(out[:64])
    return None


def mode_hex(text):
    if not text:
        return None
    count = {}
    for m in HWID_RE.finditer(text):
        count[m.group()] = count.get(m.group(), 0) + 1
    if not count:
        return None
    candidates = sorted(count.keys(), key=lambda k: -count[k])
    best, best_n = None, -1
    for run in candidates[:3]:
        for k in range(64):
            rot = rotate(run, k)
            n = count_occurrences(text, rot)
            if n > best_n:
                best_n, best = n, rot
    return best


def is_pure_tiling(text, unit):
    i = 1 if text.startswith("\ufeff") else 0
    while i < len(text) and text[i].isspace():
        i += 1
    while i + 64 <= len(text):
        if text[i : i + 64] != unit:
            return False
        i += 64
    while i < len(text):
        if not text[i].isspace():
            return False
        i += 1
    return True


def resolve_mirror(unit, crashes):
    if crashes:
        for k in range(64):
            if rotate(unit, k) == crashes:
                return crashes
    return unit[6:] + unit[:6]


def hwid_from_mirror(raw, crashes=None):
    hw = delta_head_hwid(raw)
    if hw is not None:
        return hw
    text = raw.decode("utf-8", errors="replace")
    unit = mode_hex(text)
    if unit is None:
        return None
    if is_pure_tiling(text, unit):
        return unit
    return resolve_mirror(unit, crashes)


# ---------------------------------------------------------------------------
# synthetic .license generators (mirror the engine's observed formats)
# ---------------------------------------------------------------------------

def gen_current_format(hwid, seed=0x01):
    """Binary delta-XOR head (stream[i] = raw[i] ^ stream[i-1]) carrying the
    hwid + its first char, then junk, then a '9' marker and the hwid tiled
    right-rotated by 6 hex chars."""
    stream = (hwid + hwid[0]).encode("ascii")
    raw, prev = bytearray(), seed
    for b in stream:
        raw.append(b ^ prev)
        prev = b
    raw += b"'6}!i_\x0cS\x0bQ\r\x07WP"          # junk between head and body
    unit = hwid[58:] + hwid[:58]                  # right rotation by 6
    raw += b"9" + unit.encode("ascii") * 16 + unit[:10].encode("ascii")
    return bytes(raw)


def gen_legacy_format(hwid, times=17):
    return (hwid * times).encode("ascii")


def gen_headless_format(hwid):
    unit = hwid[58:] + hwid[:58]
    return b"\x92" + b"9" + unit.encode("ascii") * 16 + unit[:10].encode("ascii")


# ---------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------

def cases():
    return [
        ("current format, delta head (A)", gen_current_format(HWID_A), None, HWID_A),
        ("current format, delta head (B)", gen_current_format(HWID_B), None, HWID_B),
        ("legacy pure tiling", gen_legacy_format(HWID_A), None, HWID_A),
        ("legacy tiling + trailing newline", gen_legacy_format(HWID_A) + b"\n", None, HWID_A),
        ("headless current format (fixed de-rotation)", gen_headless_format(HWID_A), None, HWID_A),
        ("headless + Crashes cross-check", gen_headless_format(HWID_A), HWID_A, HWID_A),
        ("plain hwid only", HWID_A.encode(), None, HWID_A),
        ("garbage", b"hello world, no license here !!", None, None),
        ("empty", b"", None, None),
        ("key cache file", b"FREE_0123456789abcdef0123456789abcdef", None, None),
    ]


def main():
    fails = 0
    for name, raw, crashes, want in cases():
        got = hwid_from_mirror(raw, crashes)
        ok = got == want
        if not ok:
            fails += 1
        print(f"{name:<45} -> {str(got)[:32]:<34} [{'PASS' if ok else 'FAIL'}]")
    print()
    print("RESULT:", "ALL PASS" if fails == 0 else f"{fails} FAIL")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
