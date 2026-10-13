"""Independent check of spec/vectors/ against spec/format.md.

Re-derives every value from the inputs with argon2-cffi, PyNaCl, ada-url (a WHATWG URL parser),
and the standard library, and implements the body rules, the merge rule, local edits, the sync
decisions, and autofill matching from the spec text.
It shares no code with vault-core. Run from the repository root:

    python3 -I tools/vectors-check/check.py
"""

import hashlib
import hmac
import ipaddress
import json
import pathlib
import re
import sys
import unicodedata

import ada_url
from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt as xc_open,
    crypto_aead_xchacha20poly1305_ietf_encrypt as xc_seal,
)
from nacl.exceptions import CryptoError

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = ROOT / "spec" / "vectors"

DAY = 86_400_000
TOMBSTONE_LIFETIME = 15_552_000_000
FLOOR = (65_536, 3, 1)
CEILING = (262_144, 10, 4)
TEST = (64, 1, 1)
MAX_GENERATION = 1 << 48
MAX_FILE = 16 * 1024 * 1024
HEADER_LEN = 133
MAX_PASSWORD_BYTES = 4096


class Fail(Exception):
    """An error with its stable code, as spec/vectors/README.md names it."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def outcome(fn, *args):
    """The result of fn as "ok" or an error code, and the value."""
    try:
        return "ok", fn(*args)
    except Fail as e:
        return e.code, None


def h(s):
    return bytes.fromhex(s)


def sha256(*parts):
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


def hkdf(ikm, salt, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


# Text forms

CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def crock(b):
    bits = "".join(f"{x:08b}" for x in b)
    bits += "0" * (-len(bits) % 5)
    return "".join(CROCK[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))


def crock_decode(s, nbytes):
    out = []
    for c in s.upper():
        if c in "- ":
            continue
        c = {"O": "0", "I": "1", "L": "1"}.get(c, c)
        if c not in CROCK:
            return None
        out.append(CROCK.index(c))
    if len(out) != (nbytes * 8 + 4) // 5:
        return None
    bits = "".join(f"{v:05b}" for v in out)
    return bytes(int(bits[i : i + 8], 2) for i in range(0, nbytes * 8, 8))


def check_value(sk):
    return sha256(b"vlt/v1/secret-key-check", sk)[:4]


def sk_encode(sk):
    enc = crock(sk + check_value(sk))
    return "VLT1-" + "-".join(enc[i : i + 4] for i in range(0, 32, 4))


def sk_decode(text):
    t = text.strip()
    if t[:5].upper() != "VLT1-":
        raise Fail("secret_key_typo")
    b = crock_decode(t[5:], 20)
    if b is None or check_value(b[:16]) != b[16:]:
        raise Fail("secret_key_typo")
    return b[:16]


def token_decode(text):
    b = crock_decode(text.strip(), 20)
    if b is None:
        raise Fail("input.token")
    return b


def etag(b):
    return '"' + sha256(b).hex() + '"'


# Passwords and keys


def nfkc(pw):
    return unicodedata.normalize("NFKC", pw)


def check_length(pw):
    if len(pw.encode()) > MAX_PASSWORD_BYTES:
        raise Fail("input.password_too_long")


def validate_new_password(pw):
    check_length(pw)
    if len(nfkc(pw)) < 12:
        raise Fail("input.password_too_short")
    if any(unicodedata.category(c) == "Cn" for c in pw):
        raise Fail("input.password_unassigned")


def check_params(p, test_kdf, test_build):
    """The bounds check: a release build refuses test_kdf; a test build accepts only the test
    set with it; otherwise the parameters lie within the floor and the ceiling."""
    if test_kdf:
        if not test_build:
            raise Fail("integrity.test_kdf_in_release")
        if tuple(p) != TEST:
            raise Fail("integrity.kdf_params")
        return
    if not all(lo <= x <= hi for x, lo, hi in zip(p, FLOOR, CEILING)):
        raise Fail("integrity.kdf_params")


def pw_key(pw, p, test_kdf, salt, test_build=True):
    check_params(p, test_kdf, test_build)
    check_length(pw)
    m, t, lanes = p
    return hash_secret_raw(
        nfkc(pw).encode(), salt, time_cost=t, memory_cost=m, parallelism=lanes,
        hash_len=32, type=Type.ID, version=0x13,
    )


def kek(pk, sk, vault_id):
    return hkdf(pk + sk, vault_id, b"vault/v1/kek")


def body_key(vk, vault_id):
    return hkdf(vk, vault_id, b"vault/v1/body")


# Header


def header_encode(test_kdf, vault_id, generation, p, salt, wrap_nonce, wrapped_vk):
    return (
        b"VAULT" + (1).to_bytes(2, "big") + (1 if test_kdf else 0).to_bytes(2, "big")
        + vault_id + generation.to_bytes(8, "big")
        + b"".join(x.to_bytes(4, "big") for x in p) + salt + wrap_nonce + wrapped_vk
    )


def wrap_ad(hb):
    return hb[:25] + hb[33:61]


def header_decode(hb, test_build=True):
    if len(hb) < HEADER_LEN:
        raise Fail("integrity.truncated")
    if len(hb) > HEADER_LEN:
        raise Fail("integrity.trailing_bytes")
    if hb[:5] != b"VAULT":
        raise Fail("integrity.bad_magic")
    if int.from_bytes(hb[5:7], "big") != 1:
        raise Fail("integrity.format_version")
    flags = int.from_bytes(hb[7:9], "big")
    if flags & ~1:
        raise Fail("integrity.unknown_flags")
    hd = {
        "test_kdf": bool(flags & 1), "vault_id": hb[9:25],
        "generation": int.from_bytes(hb[25:33], "big"),
        "params": tuple(int.from_bytes(hb[i : i + 4], "big") for i in (33, 37, 41)),
        "salt": hb[45:61], "wrap_nonce": hb[61:85], "wrapped_vk": hb[85:133], "bytes": hb,
    }
    if not 1 <= hd["generation"] <= MAX_GENERATION:
        raise Fail("integrity.generation")
    check_params(hd["params"], hd["test_kdf"], test_build)
    return hd


def read_header(f, test_build=True):
    if len(f) > MAX_FILE:
        raise Fail("integrity.size_limit")
    if len(f) < HEADER_LEN:
        raise Fail("integrity.truncated")
    return header_decode(f[:HEADER_LEN], test_build)


def unwrap(hd, k):
    try:
        return xc_open(hd["wrapped_vk"], wrap_ad(hd["bytes"]), hd["wrap_nonce"], k)
    except CryptoError:
        raise Fail("wrong_credentials")


def open_file(f, vk, test_build=True):
    hd = read_header(f, test_build)
    rest = f[HEADER_LEN:]
    if len(rest) < 24:
        raise Fail("integrity.truncated")
    nonce, ct = rest[:24], rest[24:]
    ptlen = len(ct) - 16
    if ptlen <= 0 or ptlen % 4096:
        raise Fail("integrity.padded_size")
    try:
        pt = xc_open(ct, f[:HEADER_LEN], nonce, body_key(vk, hd["vault_id"]))
    except CryptoError:
        raise Fail("integrity.aead")
    n = int.from_bytes(pt[:4], "big")
    if 4 + n > len(pt):
        raise Fail("integrity.length")
    if any(pt[4 + n :]):
        raise Fail("integrity.padding")
    return hd, parse_body(pt[4 : 4 + n])


def unlock(f, pw, sk, test_build=True):
    hd = read_header(f, test_build)
    vk = unwrap(hd, kek(pw_key(pw, hd["params"], hd["test_kdf"], hd["salt"], test_build), sk, hd["vault_id"]))
    open_file(f, vk, test_build)
    return vk


def seal_file(hb, vk, nonce, body_json):
    padded = -(-(4 + len(body_json)) // 4096) * 4096
    pt = len(body_json).to_bytes(4, "big") + body_json
    pt += bytes(padded - len(pt))
    vid = hb[9:25]
    return hb + nonce + xc_seal(pt, hb, nonce, body_key(vk, vid))


# Strict JSON


def parse_json(b):
    if b.startswith(b"\xef\xbb\xbf"):
        raise Fail("integrity.bom")
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        raise Fail("integrity.json")

    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                raise Fail("integrity.duplicate_key")
            d[k] = v
        return d

    def integer(s):
        if s.startswith("-"):
            raise Fail("integrity.number")
        n = int(s)
        if n >= 1 << 53:
            raise Fail("integrity.number")
        return n

    def reject(_):
        raise Fail("integrity.number")

    try:
        v = json.loads(text, object_pairs_hook=pairs, parse_int=integer, parse_float=reject,
                       parse_constant=reject)
    except ValueError:
        raise Fail("integrity.json")

    def walk(x, depth):
        if isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                raise Fail("integrity.json")
        elif isinstance(x, list):
            if depth > 32:
                raise Fail("integrity.nesting")
            for y in x:
                walk(y, depth + 1)
        elif isinstance(x, dict):
            if depth > 32:
                raise Fail("integrity.nesting")
            for k, y in x.items():
                walk(k, depth)
                walk(y, depth + 1)

    walk(v, 1)
    return v


def dump(v):
    """The writer's form: compact, keys in byte order, non-ASCII kept, and DEL, the C1 controls,
    U+2028, and U+2029 escaped as \\u with lowercase hex. json.dumps leaves those characters raw,
    and they appear only inside strings, so replacing them in its output is exact."""
    text = json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    for c in [chr(x) for x in range(0x7F, 0xA0)] + ["\u2028", "\u2029"]:
        text = text.replace(c, f"\\u{ord(c):04x}")
    return text.encode()


# Body schema

KNOWN_TYPES = ("login", "note")


def is_uuid(s):
    return (
        isinstance(s, str) and len(s) == 36
        and all((c == "-") if i in (8, 13, 18, 23) else c in "0123456789abcdef" for i, c in enumerate(s))
    )


def is_hex(s, n):
    return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)


def need(obj, key, kind):
    if key not in obj:
        raise Fail("integrity.missing_key")
    v = obj[key]
    ok = {
        "string": isinstance(v, str),
        "int": isinstance(v, int) and not isinstance(v, bool),
        "bool": isinstance(v, bool),
        "array": isinstance(v, list),
        "object": isinstance(v, dict),
    }[kind]
    if not ok:
        raise Fail("integrity.wrong_type")
    return v


def bound(ok):
    if not ok:
        raise Fail("integrity.bad_value")


def check_item(it):
    if not isinstance(it, dict):
        raise Fail("integrity.wrong_type")
    bound(is_uuid(need(it, "id", "string")))
    t = need(it, "type", "string")
    need(it, "modified", "int")
    bound(is_hex(need(it, "modified_by", "string"), 32))
    if t not in KNOWN_TYPES:
        return
    if "review" in it:
        need(it, "review", "string")
    if "origin" in it:
        need(it, "origin", "object")
    bound(need(it, "name", "string") != "")
    need(it, "folder", "string")
    need(it, "favourite", "bool")
    need(it, "notes", "string")
    for f in need(it, "fields", "array"):
        if not isinstance(f, dict):
            raise Fail("integrity.wrong_type")
        need(f, "name", "string")
        need(f, "value", "string")
        need(f, "hidden", "bool")
    hist = need(it, "password_history", "array")
    for e in hist:
        if not isinstance(e, dict):
            raise Fail("integrity.wrong_type")
        need(e, "password", "string")
        need(e, "retired", "int")
    bound(len(hist) <= 10)
    need(it, "created", "int")
    if t == "login":
        lg = need(it, "login", "object")
        need(lg, "username", "string")
        need(lg, "password", "string")
        for u in need(lg, "uris", "array"):
            if not isinstance(u, dict):
                raise Fail("integrity.wrong_type")
            need(u, "uri", "string")
            need(u, "match", "string")
        for a in need(lg, "apps", "array"):
            if not isinstance(a, dict):
                raise Fail("integrity.wrong_type")
            need(a, "package", "string")
            bound(is_hex(need(a, "cert_sha256", "string"), 64))
        if "totp" not in lg:
            raise Fail("integrity.missing_key")
        if lg["totp"] is not None and not isinstance(lg["totp"], str):
            raise Fail("integrity.wrong_type")
        need(lg, "passkeys", "array")


def check_body(v):
    if not isinstance(v, dict):
        raise Fail("integrity.wrong_type")
    bound(need(v, "v", "int") >= 1)
    need(v, "horizon", "int")
    items = need(v, "items", "array")
    tombs = need(v, "tombstones", "array")
    for it in items:
        check_item(it)
    for t in tombs:
        if not isinstance(t, dict):
            raise Fail("integrity.wrong_type")
        bound(is_uuid(need(t, "id", "string")))
        need(t, "modified", "int")
        bound(is_hex(need(t, "modified_by", "string"), 32))
    ids = [x["id"] for x in items] + [x["id"] for x in tombs]
    if len(ids) != len(set(ids)):
        raise Fail("integrity.duplicate_id")
    return v


def parse_body(b):
    return check_body(parse_json(b))


# History, edits, and the merge rule, from the spec text


def history_key(e):
    return (-e["retired"], e["password"].encode())


def normalise(item):
    """Normalising a history: drop empty passwords and the item's current login.password,
    deduplicate by password keeping the newest retired, sort in history order, keep 10."""
    current = item["login"]["password"] if item["type"] == "login" else None
    kept = {}
    order = []
    for e in item["password_history"]:
        p = e["password"]
        if p == "" or p == current:
            continue
        if p not in kept:
            kept[p] = e
            order.append(p)
        elif e["retired"] > kept[p]["retired"]:
            kept[p] = e
    item["password_history"] = sorted((kept[p] for p in order), key=history_key)[:10]


def stamp(item, now, device):
    item["modified"] = now
    item["modified_by"] = device
    item.pop("review", None)
    if item["type"] in KNOWN_TYPES:
        normalise(item)


def item_fields(src):
    return {k: v for k, v in src.items() if k not in ("id", "type", "modified", "modified_by", "review")}


def edit(body, action, args, now, device):
    b = json.loads(json.dumps(body))
    items = b["items"]
    find = lambda i: next((x for x in items if x["id"] == i), None)
    if action == "update":
        it = find(args["id"])
        if it is None:
            raise Fail("input.not_found")
        if it["type"] not in KNOWN_TYPES:
            raise Fail("input.unsupported_item")
        new = dict(item_fields(args["item"]), id=it["id"], type=it["type"])
        if it["type"] == "login" and new["login"]["password"] != it["login"]["password"]:
            new["password_history"] = new["password_history"] + [
                {"password": it["login"]["password"], "retired": now}]
        stamp(new, now, device)
        items[items.index(it)] = new
    elif action == "import":
        src = args["item"]
        r = bytearray(h(args["rng"]))
        r[6] = (r[6] & 0x0F) | 0x40
        r[8] = (r[8] & 0x3F) | 0x80
        x = r.hex()
        new_id = f"{x[:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:]}"
        new = dict(item_fields(src), id=new_id, type=src["type"])
        stamp(new, now, device)
        items.append(new)
    elif action == "delete":
        it = find(args["id"])
        if it is None:
            raise Fail("input.not_found")
        items.remove(it)
        b["tombstones"].append({"id": it["id"], "modified": now, "modified_by": device})
    elif action == "restore":
        old = json.loads(json.dumps(args["item"]))
        cur = find(old["id"])
        # When the item exists, the restored history is the union of the revision's history, the
        # existing history, and the existing login.password (retired now) when it differs from
        # the restored one; stamping normalises it, which drops the restored password.
        if cur is not None and cur["type"] in KNOWN_TYPES and old["type"] in KNOWN_TYPES:
            restored = old["login"]["password"] if old["type"] == "login" else None
            extra = []
            if cur["type"] == "login" and cur["login"]["password"] != restored:
                extra = [{"password": cur["login"]["password"], "retired": now}]
            old["password_history"] = old["password_history"] + cur["password_history"] + extra
        b["items"] = [x for x in items if x["id"] != old["id"]]
        b["tombstones"] = [x for x in b["tombstones"] if x["id"] != old["id"]]
        stamp(old, now, device)
        b["items"].append(old)
    else:
        raise AssertionError(action)
    return b


def cutoff(now):
    return max(0, now - TOMBSTONE_LIFETIME)


def clamp(body, now):
    b = json.loads(json.dumps(body))
    limit = now + DAY
    for it in b["items"]:
        if it["modified"] > limit:
            it["modified"] = now
            it["review"] = "clamped"
        if it["type"] in KNOWN_TYPES:
            for e in it["password_history"]:
                if e["retired"] > limit:
                    e["retired"] = now
            normalise(it)
    for t in b["tombstones"]:
        if t["modified"] > limit:
            t["modified"] = now
    if b["horizon"] > cutoff(now) + DAY:
        b["horizon"] = cutoff(now)
    return b


def merge(local, remote, now):
    L, R = clamp(local, now), clamp(remote, now)
    entries = {}
    for side, body in (("L", L), ("R", R)):
        for it in body["items"]:
            entries.setdefault(it["id"], {})[side] = ("item", it)
        for t in body["tombstones"]:
            entries.setdefault(t["id"], {})[side] = ("tomb", t)
    items, tombs, expired = [], [], []
    for _, e in sorted(entries.items()):
        if len(e) == 1:
            side, (kind, x) = next(iter(e.items()))
            other = R if side == "L" else L
            if kind == "item" and x["modified"] < other["horizon"]:
                expired.append(x)
                continue
            winner = (kind, x)
        else:
            lk, lx = e["L"]
            rk, rx = e["R"]
            if (lx["modified"], lx["modified_by"]) > (rx["modified"], rx["modified_by"]):
                winner, loser = (lk, lx), (rk, rx)
            else:
                winner, loser = (rk, rx), (lk, lx)
            wx, lox = winner[1], loser[1]
            if (winner[0] == "item" and loser[0] == "item"
                    and wx["type"] == "login" and lox["type"] == "login"):
                wx["password_history"] = (
                    wx["password_history"] + lox["password_history"]
                    + [{"password": lox["login"]["password"], "retired": lox["modified"]}])
                normalise(wx)
        (items if winner[0] == "item" else tombs).append(winner[1])
    c = cutoff(now)
    kept = [t for t in tombs if t["modified"] >= c]
    horizon = max(L["horizon"], R["horizon"])
    if len(kept) < len(tombs):
        horizon = max(horizon, c)
    out = {k: v for k, v in R.items() if k not in ("v", "horizon", "items", "tombstones")}
    for k, v in L.items():
        if k not in ("v", "horizon", "items", "tombstones") and k not in out:
            out[k] = v
    out.update(v=max(L["v"], R["v"]), horizon=horizon, items=items, tombstones=kept)
    return out, expired


def keyed(body):
    rest = {k: v for k, v in body.items() if k not in ("items", "tombstones")}
    return ({x["id"]: x for x in body["items"]}, {x["id"]: x for x in body["tombstones"]}, rest)


def same_content(a, b):
    return keyed(a) == keyed(b)


# Sync decisions


def state_of(v):
    return {
        "vault_id": h(v["vault_id"]),
        "accepted": None if v["accepted"] is None else (v["accepted"]["generation"], h(v["accepted"]["file_hash"])),
        "wrap_nonce": h(v["wrap_nonce"]),
        "retired": [h(x) for x in v["retired_wrap_nonces"]],
    }


def check_remote(st, f, test_build=True):
    hd = read_header(f, test_build)
    if hd["vault_id"] != st["vault_id"]:
        raise Fail("integrity.vault_id_mismatch")
    if st["accepted"] is not None:
        g, fh = st["accepted"]
        if hd["generation"] < g:
            raise Fail("integrity.generation_rollback")
        if hd["generation"] == g and sha256(f) != fh:
            raise Fail("integrity.generation_fork")
    if hd["wrap_nonce"] in st["retired"]:
        raise Fail("integrity.retired_wrap_nonce")
    return hd, ("current" if hd["wrap_nonce"] == st["wrap_nonce"] else "changed")


# Setup text

UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def pct_encode(s):
    return "".join(chr(b) if b in UNRESERVED else f"%{b:02X}" for b in s.encode())


def pct_decode(s):
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "%":
            hx = s[i + 1 : i + 3]
            if len(hx) != 2 or any(c not in "0123456789abcdefABCDEF" for c in hx):
                raise Fail("input.setup_text")
            out.append(int(hx, 16))
            i += 3
        else:
            out += s[i].encode()
            i += 1
    try:
        return out.decode()
    except UnicodeDecodeError:
        raise Fail("input.setup_text")


def server_url(text):
    """The setup rules for a server URL, after WHATWG parsing with ada-url (which applies the
    UTS 46 host processing): no user information, no fragment, a host that is an IPv4 address,
    an IPv6 address, or a domain whose labels are each 1 to 63 characters from a-z, 0-9, and -,
    and a scheme of https, or http to localhost, 127.0.0.1, or [::1]. Returns the serialised URL
    and the host."""
    try:
        u = ada_url.URL(text)
    except ValueError:
        raise Fail("input.server_url")
    if u.protocol not in ("http:", "https:") or u.username or u.password or "#" in u.href:
        raise Fail("input.server_url")
    host = u.hostname
    # host_type: 0 for a domain, 1 for IPv4, 2 for IPv6. Firefox builds a host permission from a
    # domain, so each of its labels is checked.
    if u.host_type == 0 and not all(
        1 <= len(lb) <= 63 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in lb)
        for lb in host.split(".")
    ):
        raise Fail("input.server_url")
    if u.protocol == "http:" and host not in ("localhost", "127.0.0.1", "[::1]"):
        raise Fail("input.server_url")
    return u.href, host


def parse_setup(text):
    t = text.strip()
    prefix = "vault://setup?"
    if not t.startswith(prefix):
        raise Fail("input.setup_text")
    got = {}
    for pair in filter(None, t[len(prefix) :].split("&")):
        name, _, value = pair.partition("=")
        name = pct_decode(name)
        if name not in ("url", "token", "fp"):
            continue
        if name in got:
            raise Fail("input.setup_text")
        got[name] = pct_decode(value)
    if "url" not in got or "token" not in got:
        raise Fail("input.setup_text")
    url, host = server_url(got["url"])
    tok = token_decode(got["token"])
    fp = None
    if "fp" in got:
        if url.startswith("http:"):
            raise Fail("input.setup_text")
        if not is_hex(got["fp"], 64):
            raise Fail("input.fingerprint")
        fp = got["fp"]
    return url, tok, fp


# Autofill matching


def af_parse(text):
    """A WHATWG URL with scheme http or https, as matching sees it, or None."""
    try:
        u = ada_url.URL(text)
    except ValueError:
        return None
    if u.protocol not in ("http:", "https:") or not u.hostname:
        return None
    kind = {0: "domain", 1: "ipv4", 2: "ipv6"}[u.host_type]
    host = u.hostname
    if kind == "domain" and host.endswith("."):
        host = host[:-1]
    if kind == "domain" and "" in host.split("."):
        return None
    # The query is present when `?` follows the scheme in the URL without its fragment; ada's
    # `search` is empty both for no query and for an empty one.
    rest = u.href.split("#", 1)[0][len(u.protocol) :]
    pq = u.pathname + ("?" + u.search[1:] if "?" in rest else "")
    port = int(u.port) if u.port else None
    scheme = u.protocol[:-1]
    origin = f"{scheme}://{host}" + (f":{port}" if port is not None else "")
    return {"scheme": scheme, "host": host, "kind": kind, "port": port, "path_query": pq,
            "origin": origin}


def af_prepare(uri):
    t = uri.strip(" \t\n\f\r")
    t = t if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", t) else "https://" + t
    try:
        u = ada_url.URL(t)
    except ValueError:
        return None
    if u.username or u.password:
        return None
    return af_parse(t)


def af_view(p):
    if p is None:
        return None
    return {k: p[k] for k in ("scheme", "host", "port", "path_query", "origin")}


class BadSuffix(Exception):
    """A known-suffix answer that is neither the whole host nor its trailing labels."""


def af_suffix(p, lookup):
    if p["kind"] != "domain":
        return None
    s = lookup(p["host"])
    if s is None:
        return None
    if s and (p["host"] == s or p["host"].endswith("." + s)):
        return s
    raise BadSuffix()


def af_registrable(p, lookup):
    s = af_suffix(p, lookup)
    if s is None or s == p["host"]:
        return p["host"]
    label = p["host"][: -len(s) - 1].split(".")[-1]
    return f"{label}.{s}"


def af_local(p, lookup):
    if p["kind"] == "domain":
        h_ = p["host"]
        return af_suffix(p, lookup) is None or h_ == "home.arpa" or h_.endswith(".home.arpa")
    a = ipaddress.ip_address(p["host"].strip("[]"))
    nets = (["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
            if p["kind"] == "ipv4" else ["::1/128", "fc00::/7", "fe80::/10"])
    return any(a in ipaddress.ip_network(n) for n in nets)


def af_match(page, uri, mode, lookup):
    item = af_prepare(uri)
    if item is None:
        return "none"
    try:
        af_suffix(page, lookup)
        af_suffix(item, lookup)
    except BadSuffix:
        return "none"
    same_origin = page["origin"] == item["origin"]
    holds = {
        "base_domain": af_registrable(page, lookup) == af_registrable(item, lookup),
        "host": page["host"] == item["host"] and page["port"] == item["port"],
        "starts_with": same_origin and page["path_query"].startswith(item["path_query"]),
        "exact": same_origin and page["path_query"] == item["path_query"],
    }.get(mode, False)
    if not holds:
        return "none"
    if item["scheme"] == "https" and page["scheme"] == "http":
        return "confirm" if af_local(page, lookup) else "none"
    return "fill"


AF_RANK = {"none": 0, "confirm": 1, "fill": 2}


def af_candidates(page_text, items, lookup):
    page = af_parse(page_text)
    if page is None:
        return []
    out = []
    for it in items:
        best = "none"
        if it["type"] == "login":
            for u in it["uris"]:
                o = af_match(page, u["uri"], u["match"], lookup)
                if AF_RANK[o] > AF_RANK[best]:
                    best = o
        if best != "none":
            out.append((it, best))
    out.sort(key=lambda x: (-AF_RANK[x[1]], x[0]["name"], x[0]["id"]))
    return out


def af_save(page_text, user, password, items, lookup):
    page = af_parse(page_text)
    if page is None or password == "":
        return {"action": "none"}
    same = [it for it, o in af_candidates(page_text, items, lookup)
            if o == "fill" and it["username"] == user]
    if any(it["password"] == password for it in same):
        return {"action": "none"}
    if same:
        return {"action": "update", "id": same[0]["id"]}
    return {"action": "new", "name": page["host"], "uri": page["origin"], "match": "base_domain"}


# File checks


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


class Checker:
    def __init__(self):
        self.failures = []
        self.count = 0

    def eq(self, where, got, want):
        self.count += 1
        if got != want:
            self.failures.append(f"{where}: got {got!r}, want {want!r}")


def pw_of(c):
    return h(c["password_hex"]).decode()


def run(ck):
    for c in load("secret-key.json")["cases"]:
        w = f"secret-key {c['name']}"
        if c["op"] == "encode":
            sk = h(c["secret_key"])
            ck.eq(w, check_value(sk).hex(), c["check"])
            ck.eq(w, sk_encode(sk), c["text"])
        else:
            r, v = outcome(sk_decode, c["input"])
            ck.eq(w, r if "error" in c else v.hex(), c.get("error", c.get("secret_key")))

    for c in load("token.json")["cases"]:
        w = f"token {c['name']}"
        if c["op"] == "encode":
            ck.eq(w, crock(h(c["token"])), c["text"])
            ck.eq(w, sha256(h(c["token"])).hex(), c["stored_hash"])
        else:
            r, v = outcome(token_decode, c["input"])
            if "error" in c:
                ck.eq(w, r, c["error"])
            else:
                ck.eq(w, v.hex(), c["token"])
                ck.eq(w, sha256(v).hex(), c["stored_hash"])

    for c in load("etag.json")["cases"]:
        ck.eq(f"etag {c['name']}", etag(h(c["bytes"])), c["etag"])

    for c in load("kdf.json")["cases"]:
        w = f"kdf {c['name']}"
        op = c["op"]
        if op == "nfkc":
            ck.eq(w, nfkc(c["password"]).encode().hex(), c["nfkc_hex"])
        elif op == "validate_new_password":
            ck.eq(w, outcome(validate_new_password, pw_of(c))[0], c["result"])
        elif op == "derive":
            p = (c["params"]["m_kib"], c["params"]["t"], c["params"]["p"])
            for build in (True, False):
                r, pk = outcome(pw_key, pw_of(c), p, c["test_kdf"], h(c["kdf_salt"]), build)
                want = c.get("error", "ok") if build else c.get("release_error", c.get("error", "ok"))
                ck.eq(f"{w} ({'test' if build else 'release'} build)", r, want)
                if build and r == "ok":
                    ck.eq(w, nfkc(pw_of(c)).encode().hex(), c["nfkc_hex"])
                    ck.eq(w, pk.hex(), c["pw_key"])
                    ck.eq(w, kek(pk, h(c["secret_key"]), h(c["vault_id"])).hex(), c["kek"])
        elif op == "check_params":
            p = (c["params"]["m_kib"], c["params"]["t"], c["params"]["p"])
            ck.eq(w, outcome(check_params, p, c["test_kdf"], True)[0], c["test_build"])
            ck.eq(w, outcome(check_params, p, c["test_kdf"], False)[0], c["release_build"])

    for c in load("vault-file.json")["cases"]:
        w = f"vault-file {c['name']}"
        vk = h(c["vault_key"])
        f = h(c["file"])
        if c["op"] == "seal":
            p = (c["params"]["m_kib"], c["params"]["t"], c["params"]["p"])
            pk = pw_key(pw_of(c), p, c["test_kdf"], h(c["kdf_salt"]))
            ck.eq(w, pk.hex(), c["pw_key"])
            k = kek(pk, h(c["secret_key"]), h(c["vault_id"]))
            ck.eq(w, k.hex(), c["kek"])
            unwrapped = header_encode(c["test_kdf"], h(c["vault_id"]), c["generation"], p,
                                      h(c["kdf_salt"]), h(c["wrap_nonce"]), bytes(48))
            ad = wrap_ad(unwrapped)
            ck.eq(w, ad.hex(), c["wrap_ad"])
            wrapped = xc_seal(vk, ad, h(c["wrap_nonce"]), k)
            ck.eq(w, wrapped.hex(), c["wrapped_vk"])
            hb = unwrapped[:85] + wrapped
            ck.eq(w, hb.hex(), c["header"])
            ck.eq(w, body_key(vk, h(c["vault_id"])).hex(), c["body_key"])
            ck.eq(w, dump(parse_body(c["body_json"].encode())), c["body_json"].encode())
            sealed = seal_file(hb, vk, h(c["body_nonce"]), c["body_json"].encode())
            ck.eq(w, sealed.hex(), c["file"])
            ck.eq(w, len(sealed) - HEADER_LEN - 24 - 16, c["plaintext_len"])
            ck.eq(w, etag(f), c["etag"])
            ck.eq(w, unlock(f, pw_of(c), h(c["secret_key"])), vk)
            ck.eq(f"{w} (release build)", outcome(unlock, f, pw_of(c), h(c["secret_key"]), False)[0],
                  c.get("release_error", "ok"))
        else:
            r, v = outcome(open_file, f, vk)
            ck.eq(w, r, c["result"])
            ck.eq(w, dump(v[1]).decode(), c["body_json"])

    for c in load("merge.json")["cases"]:
        w = f"merge {c['name']}"
        if c["op"] == "merge":
            got, expired = merge(c["local"], c["remote"], c["now"])
            ck.eq(w, keyed(got), keyed(c["result"]))
            ck.eq(w, sorted(expired, key=lambda x: x["id"]), sorted(c["expired"], key=lambda x: x["id"]))
        else:
            r, got = outcome(edit, c["body"], c["action"], c["args"], c["now"], c["device_id"])
            if "error" in c:
                ck.eq(w, r, c["error"])
            else:
                ck.eq(w, keyed(got), keyed(c["result"]))
                check_body(got)

    for c in load("sync.json")["cases"]:
        w = f"sync {c['name']}"
        op = c["op"]
        if op == "check_remote":
            f = h(c["file"])
            r, v = outcome(check_remote, state_of(c["state"]), f)
            if "error" in c:
                ck.eq(w, r, c["error"])
            else:
                ck.eq(w, v[1], c["wrap"])
                ck.eq(w, etag(f), c["etag"])
                ck.eq(w, outcome(open_file, f, h(c["vault_key"]))[0], c["open"])
        elif op == "check_setup":
            def setup_check(f, kit):
                hd = read_header(f)
                if kit is not None and hd["vault_id"] != kit:
                    raise Fail("integrity.vault_id_mismatch")
            kit = None if c["kit_vault_id"] is None else h(c["kit_vault_id"])
            ck.eq(w, outcome(setup_check, h(c["file"]), kit)[0], c["result"])
        elif op == "adopt":
            merged, _ = merge(c["local"], c["remote"], c["now"])
            got = {"action": "adopt"} if same_content(merged, c["remote"]) else {
                "action": "push", "generation": c["remote_generation"] + 1}
            ck.eq(w, got, c["result"])
        elif op == "not_found":
            st = c["state"]
            if st is None:
                got = {"action": "no_vault"}
            elif st["accepted"] is None:
                got = {"action": "push", "generation": 1, "if_none_match": "*"}
            else:
                got = {"action": "push", "generation": st["accepted"]["generation"] + 1, "if_none_match": "*"}
            ck.eq(w, got, c["result"])
        elif op == "recovery":
            st = state_of(c["state"])
            unknown, candidates = [], []
            for rev in c["revisions"]:
                r, hd = outcome(read_header, h(rev["file"]))
                if r != "ok" or hd["vault_id"] != st["vault_id"]:
                    continue
                if hd["wrap_nonce"] == st["wrap_nonce"]:
                    if st["accepted"] is None or hd["generation"] >= st["accepted"][0]:
                        candidates.append((hd["generation"], rev["id"], rev["file"]))
                elif hd["wrap_nonce"] not in st["retired"]:
                    unknown.append((hd["generation"], rev["id"]))
            if unknown and not c["past_unknown_wraps"]:
                ck.eq(w, "credential_change", c["plan"])
                ck.eq(w, [i for _, i in sorted(unknown, reverse=True)], c["plan_revisions"])
            else:
                order = sorted(candidates, reverse=True)
                ck.eq(w, "candidates", c["plan"])
                ck.eq(w, [i for _, i, _ in order], c["plan_revisions"])
                chosen = next(((g, i) for g, i, f in order if outcome(open_file, h(f), h(c["vault_key"]))[0] == "ok"), None)
                ck.eq(w, None if chosen is None else chosen[1], c["chosen"])
                base = chosen[0] if chosen else (st["accepted"][0] if st["accepted"] else 0)
                ck.eq(w, base + 1, c["push_generation"])
        elif op == "clock":
            now, build, date = c["now"], c["build_time"], c["server_date"]
            got = ("clock_before_build_time" if now < build
                   else "clock_skew" if date is not None and abs(now - date) > DAY else "ok")
            ck.eq(w, got, c["result"])
        elif op == "retry":
            total = run_404 = 0
            got = []
            for cond in c["conditions"]:
                total += 1
                run_404 = run_404 + 1 if cond == "if_none_match" else 0
                got.append("give_up" if total >= 5 or run_404 >= 2 else "again")
            ck.eq(w, got, c["decisions"])

    for c in load("credentials.json")["cases"]:
        w = f"credentials {c['name']}"
        op = c["op"]
        p = None if "params" not in c else (c["params"]["m_kib"], c["params"]["t"], c["params"]["p"])
        if op == "create":
            sk, vid, vk, salt, wn, bn = (h(x) for x in c["draws"])
            validate_new_password(pw_of(c))
            k = kek(pw_key(pw_of(c), p, c["test_kdf"], salt), sk, vid)
            hb = header_encode(c["test_kdf"], vid, 1, p, salt, wn, bytes(48))
            hb = hb[:85] + xc_seal(vk, wrap_ad(hb), wn, k)
            body = b'{"horizon":0,"items":[],"tombstones":[],"v":1}'
            ck.eq(w, seal_file(hb, vk, bn, body).hex(), c["file"])
        elif op in ("change", "rekey"):
            base = read_header(h(c["base_file"]))
            vk, salt, wn, bn = (h(x) for x in c["draws"])
            k = kek(pw_key(pw_of(c), p, c["test_kdf"], salt), h(c["secret_key"]), base["vault_id"])
            hb = header_encode(c["test_kdf"], base["vault_id"], base["generation"] + 1, p, salt, wn, bytes(48))
            hb = hb[:85] + xc_seal(vk, wrap_ad(hb), wn, k)
            body = b'{"horizon":0,"items":[],"tombstones":[],"v":1}'
            ck.eq(w, seal_file(hb, vk, bn, body).hex(), c["file"])
            if op == "rekey":
                ck.eq(w, outcome(check_remote, state_of(c["state_after"]), h(c["forged"]))[0], c["forged_check"])
            for x in c["checks"]:
                if x["action"] == "unlock":
                    r = outcome(unlock, h(x["file"]), pw_of(x), h(x["secret_key"]))[0]
                else:
                    r = outcome(open_file, h(x["file"]), h(x["vault_key"]))[0]
                ck.eq(f"{w} {x['action']}", r, x["result"])
        elif op == "passwd_conflict":
            r, v = outcome(check_remote, state_of(c["state"]), h(c["remote"]))
            got = r if r != "ok" else {"current": "retry", "changed": "abort"}[v[1]]
            ck.eq(w, got, c["result"])
        elif op == "pending_secret_key":
            hd = read_header(h(c["remote"]))
            pk = pw_key(pw_of(c), hd["params"], hd["test_kdf"], hd["salt"])
            got = "wrong_credentials"
            for name, key in (("landed", "pending_secret_key"), ("not_landed", "old_secret_key")):
                if outcome(unwrap, hd, kek(pk, h(c[key]), hd["vault_id"]))[0] == "ok":
                    got = name
                    break
            ck.eq(w, got, c["result"])

    top = load("tamper.json")
    base = h(top["file"])
    for c in top["cases"]:
        w = f"tamper {c['name']}"
        if "file" in c:
            f = h(c["file"])
        else:
            f = bytearray(base)
            f[c["offset"]] ^= c["xor"]
            f = bytes(f)
        for build, sfx in ((True, ""), (False, "release_")):
            ck.eq(f"{w} open {sfx}", outcome(open_file, f, h(top["vault_key"]), build)[0], c[sfx + "error_open"])
            ck.eq(f"{w} unlock {sfx}", outcome(unlock, f, pw_of(top), h(top["secret_key"]), build)[0],
                  c[sfx + "error_unlock"])

    top = load("malformed.json")
    for c in top["cases"]:
        ck.eq(f"malformed {c['name']}", outcome(open_file, h(c["file"]), h(top["vault_key"]))[0], c["result"])

    for c in load("setup.json")["cases"]:
        w = f"setup {c['name']}"
        if c["op"] == "format":
            r, v = outcome(server_url, c["url"])
            if "error" in c:
                ck.eq(w, r, c["error"])
                continue
            url, _ = v
            text = f"vault://setup?url={pct_encode(url)}&token={crock(h(c['token']))}"
            if c["fp"] is not None and not url.startswith("http:"):
                text += f"&fp={c['fp']}"
            ck.eq(w, text, c["text"])
        elif c["op"] == "parse":
            r, v = outcome(parse_setup, c["input"])
            if "error" in c:
                ck.eq(w, r, c["error"])
            else:
                ck.eq(w, (v[0], v[1].hex(), v[2]), (c["url"], c["token"], c["fp"]))
        else:
            ck.eq(f"setup {c['name']}", sha256(h(c["cert_der"])).hex() == c["fp"], c["matches"])

    top = load("autofill.json")
    table, answers = top["known_suffixes"], top["suffix_answers"]

    def lookup(host):
        if host in answers:
            return answers[host]
        fits = [t for t in table if host == t or host.endswith("." + t)]
        return max(fits, key=len) if fits else None

    ops = {}
    for c in top["cases"]:
        w, op = f"autofill {c['name']}", c["op"]
        ops[op] = ops.get(op, 0) + 1
        if op == "prepare":
            got = af_view(af_prepare(c["uri"]))
        elif op == "page":
            got = af_view(af_parse(c["url"]))
        elif op == "registrable":
            try:
                got = af_registrable(af_parse(c["url"]), lookup)
            except BadSuffix:
                got = None
        elif op == "match":
            pg = af_parse(c["page"])
            got = "none" if pg is None else af_match(pg, c["uri"], c["match"], lookup)
        elif op == "items":
            got = [{"id": it["id"], "outcome": o} for it, o in af_candidates(c["page"], c["items"], lookup)]
        elif op == "frames":
            top_url = af_parse(c["top"])
            got = [] if top_url is None else [
                f["id"] for f in c["frames"]
                if (fp := af_parse(f["url"])) is not None and fp["origin"] == top_url["origin"]]
        elif op == "save":
            got = af_save(c["page"], c["username"], c["password"], c["items"], lookup)
        else:
            ck.failures.append(f"{w}: unknown op {op!r}")
            continue
        ck.eq(w, got, c["result"])
    print("autofill cases by op:", ", ".join(f"{k} {v}" for k, v in sorted(ops.items())))
    minimums = {"prepare": 40, "page": 8, "registrable": 15, "match": 100, "items": 5, "frames": 3,
                "save": 10}
    for op, least in minimums.items():
        ck.eq(f"autofill has at least {least} {op} cases", ops.get(op, 0) >= least, True)


def main():
    ck = Checker()
    try:
        run(ck)
    except Fail as e:
        ck.failures.append(f"unexpected error {e.code} while checking")
    for f in ck.failures:
        print("FAIL", f)
    files = sorted(p.name for p in VECTORS.glob("*.json"))
    cases = sum(len(load(f)["cases"]) for f in files)
    print(f"{len(files)} files, {cases} cases, {ck.count} checks, {len(ck.failures)} failures")
    sys.exit(1 if ck.failures else 0)


if __name__ == "__main__":
    main()
