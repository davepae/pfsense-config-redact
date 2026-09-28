#!/usr/bin/env python3
"""
pfsense_redact.py - sanitize a pfSense config.xml before sharing.

Runs locally, standard library only. Never prints secret values; the report
contains tag names and line numbers only.

Usage:
    python3 pfsense_redact.py config.xml
    python3 pfsense_redact.py config.xml --mask-network
    python3 pfsense_redact.py config.xml --strict

Outputs (next to the input file):
    <name>.redacted.xml   sanitized config, structure preserved
    <name>.report.txt     what was changed and what to review by hand

Options:
    --mask-network   consistently replace public IPv4 addresses and MAC
                     addresses with placeholders (same input -> same output,
                     so relationships stay readable). RFC1918 space is kept.
    --strict         also redact every long base64 blob found outside known
                     tags (this includes base64-encoded <descr> text and
                     pfBlockerNG custom lists, so it removes useful context).

Email addresses are always redacted (not gated by a flag), anywhere they
appear in the file, and consistently mapped so repeated use of the same
address is still visibly the same address.
"""
import argparse
import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path

# Tags whose contents are always secret (exact names, lowercase).
EXACT_SECRET_TAGS = {
    "password", "passwd", "bcrypt-hash", "md5-hash", "nt-hash", "sha512-hash",
    "password_hash", "prv", "sshdata", "xmldata", "authorizedkeys",
    "tls", "shared_key", "pre-shared-key", "mobilekey", "privatekey",
    "presharedkey", "pkey", "ldap_bindpw", "radius_secret", "radiussecret",
    "secret", "rocommunity", "ddnsdomainkey", "pskey", "passphrase",
    "oinkcode", "etprocode", "snortoinkcode", "apikey", "api_key", "token",
    "licensekey", "license_key", "authtoken", "auth_token", "psk",
    "bindpw", "sharedsecret", "dnsrefreshkey", "accountkey", "account_key",
    "maxmind_geoipdb_key", "otx_key", "voucher_key",
    "dns_cfcf_key", "dns_cfcf_email", "dns_cfcf_account_id", "preauthkey",
    "maxmind_key", "maxmind_account", "redis_password", "redis_passwordagain",
    "device_key", "keypaste", "userkey", "api", "etpro_code",
}

# Catch-all: any tag whose name matches this is treated as secret unless it
# is in BENIGN_TAGS. Matches are listed in the report so you can review them.
HEURISTIC = re.compile(r"(pass|secret|token|psk|community|oink|bindpw|apikey|api_key|privkey|private)", re.I)
BENIGN_TAGS = {
    "passwordmgmt", "password_change", "passwordpolicy", "passthru", "passiveonly",
    "passlist", "passlistname", "pass", "passive", "passwordless",
    "publickey", "pubkey", "secondary", "secondarydomain", "privatenetwork",
    "private", "blockpriv", "blockprivatenetworks", "privileges",
    "authorizedkeys_comment",
}

TAG_RE = re.compile(r"<([A-Za-z0-9_\-]+)(\s[^>]*)?>([^<]*)</\1>", re.S)
# pfSense wraps a lot of free-text/secret fields in CDATA: <tag><![CDATA[...]]></tag>.
# The CDATA opening marker itself contains "<", so TAG_RE's [^<]* body never
# matches these - they need their own pattern or they silently pass through
# un-redacted (this was a real bug: SMTP passwords and DDNS tokens leaked).
CDATA_TAG_RE = re.compile(r"<([A-Za-z0-9_\-]+)(\s[^>]*)?><!\[CDATA\[(.*?)\]\]></\1>", re.S)
BEGIN_RE = re.compile(r"-----BEGIN [A-Z ]+-----")
B64_RE = re.compile(r"[A-Za-z0-9+/=\s]{200,}")
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{60,}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def is_secret_tag(name: str) -> bool:
    n = name.lower()
    if n in BENIGN_TAGS:
        return False
    return n in EXACT_SECRET_TAGS or bool(HEURISTIC.search(n))


class Masker:
    def __init__(self):
        self.ip_map, self.mac_map = {}, {}

    def ip(self, m):
        s = m.group(0)
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return s
        if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved:
            return s
        if s not in self.ip_map:
            n = len(self.ip_map) + 1
            self.ip_map[s] = f"198.51.100.{n % 254 or 254}" if n < 254 else f"203.0.113.{n % 254 or 254}"
        return self.ip_map[s]

    def mac(self, m):
        s = m.group(0).lower()
        if s not in self.mac_map:
            n = len(self.mac_map) + 1
            self.mac_map[s] = f"02:00:00:00:{(n >> 8) & 255:02x}:{n & 255:02x}"
        return self.mac_map[s]


class EmailMasker:
    """Consistently replaces email addresses so repeated use of the same
    address stays visibly the same person without leaking the real one."""
    def __init__(self):
        self.email_map = {}

    def __call__(self, m):
        s = m.group(0)
        key = s.lower()
        if key not in self.email_map:
            n = len(self.email_map) + 1
            self.email_map[key] = f"redacted-email-{n}@example.invalid"
        return self.email_map[key]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config")
    ap.add_argument("--mask-network", action="store_true")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    src = Path(args.config)
    text = src.read_text(encoding="utf-8", errors="replace")

    redacted_tags = defaultdict(list)  # tag -> [line numbers]

    def line_of(pos):
        return text.count("\n", 0, pos) + 1

    # Collect candidate matches from both the plain-text and CDATA-wrapped
    # tag forms, then apply them in document order in a single pass so
    # overlapping/adjacent matches can't corrupt the output.
    candidates = []
    for m in TAG_RE.finditer(text):
        name, inner = m.group(1), m.group(3)
        if not inner.strip():
            continue  # empty leaf
        if is_secret_tag(name):
            candidates.append((m.start(3), m.end(3), name, "REDACTED"))
    for m in CDATA_TAG_RE.finditer(text):
        name, inner = m.group(1), m.group(3)
        if not inner.strip():
            continue
        if is_secret_tag(name):
            candidates.append((m.start(3), m.end(3), name, "REDACTED"))
    candidates.sort(key=lambda c: c[0])

    out, last = [], 0
    for start, end, name, replacement in candidates:
        if start < last:
            continue  # overlapping match, already handled
        redacted_tags[name].append(line_of(start))
        out.append(text[last:start])
        out.append(replacement)
        last = end
    out.append(text[last:])
    result = "".join(out)

    # Second pass: PEM blocks anywhere else (e.g. inside free text or unknown tags).
    pem_hits = []
    def pem_sub(m):
        pem_hits.append(line_of(m.start()))
        return "-----REDACTED PEM BLOCK-----"
    result = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", pem_sub, result, flags=re.S)

    # Optional network masking.
    masker = Masker()
    if args.mask_network:
        result = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", masker.ip, result)
        result = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", masker.mac, result)

    # Email addresses: always redacted, anywhere in the file (not just known
    # tags), since they show up in notify settings, ACME accounts, descr
    # fields, etc. Same address always maps to the same placeholder.
    email_masker = EmailMasker()
    result = EMAIL_RE.sub(email_masker, result)

    # Residual scan: long opaque blobs that survived.
    review, strict_hits = [], []
    lines = result.split("\n")
    for i, ln in enumerate(lines, 1):
        stripped = ln.strip()
        tagm = re.match(r"<([A-Za-z0-9_\-]+)[^>]*>(.*)</\1>$", stripped)
        tag = tagm.group(1) if tagm else "(unknown)"
        body = tagm.group(2) if tagm else stripped
        if tag == "crt":  # public certificate bodies are expected
            continue
        if BEGIN_RE.search(ln):
            review.append((i, tag, "PEM header still present"))
        elif LONG_TOKEN_RE.search(body):
            review.append((i, tag, f"long opaque string ({len(body)} chars)"))
            if args.strict:
                strict_hits.append(i)
    if args.strict:
        for i in strict_hits:
            ln = lines[i - 1]
            lines[i - 1] = LONG_TOKEN_RE.sub("REDACTED_BLOB", ln)
        result = "\n".join(lines)

    out_xml = src.with_suffix(".redacted.xml")
    out_rpt = src.with_suffix(".report.txt")
    out_xml.write_text(result, encoding="utf-8")

    rpt = ["pfSense config redaction report", "=" * 34, ""]
    rpt.append("REDACTED TAGS (values removed; tag -> count, line numbers in ORIGINAL file)")
    if redacted_tags:
        for tag, lns in sorted(redacted_tags.items()):
            heur = "" if tag.lower() in EXACT_SECRET_TAGS else "   [matched by heuristic - verify]"
            shown = ", ".join(map(str, lns[:8])) + (" ..." if len(lns) > 8 else "")
            rpt.append(f"  <{tag}>  x{len(lns)}  lines {shown}{heur}")
    else:
        rpt.append("  (none - unusual for a real config; check the input file)")
    if pem_hits:
        rpt.append(f"\nPEM private key blocks removed outside known tags: {len(pem_hits)}")
    if args.mask_network:
        rpt.append(f"\nNETWORK MASKING: {len(masker.ip_map)} public IPv4 and {len(masker.mac_map)} MAC addresses replaced.")
        rpt.append("  IPv6 addresses and hostnames/domains were NOT masked. Review by hand.")
    rpt.append(f"\nEMAIL ADDRESSES: {len(email_masker.email_map)} unique address(es) replaced with redacted-email-N@example.invalid.")
    rpt.append("\nREVIEW BY HAND (line numbers in the REDACTED file)")
    if review:
        for i, tag, why in review[:200]:
            rpt.append(f"  line {i}: <{tag}>  {why}")
        if len(review) > 200:
            rpt.append(f"  ... and {len(review) - 200} more")
        rpt.append("  Many of these are base64-encoded <descr>/notes fields or package settings.")
        rpt.append("  They can be decoded with `echo '<blob>' | base64 -d` to check for pasted credentials.")
    else:
        rpt.append("  (nothing flagged)")
    rpt += [
        "\nSTILL YOUR RESPONSIBILITY",
        "  - Free-text fields (<descr>, <detail>, notes) can contain pasted passwords.",
        "  - Hostnames, domains, DDNS names, ISP/PPPoE usernames, and internal layout are not removed.",
        "  - Email addresses are auto-redacted; still search the output for your own domain and names before sharing.",
        "  - If a raw config was ever shared or stored somewhere untrusted, rotate the secrets it held.",
    ]
    out_rpt.write_text("\n".join(rpt) + "\n", encoding="utf-8")

    print(f"Wrote {out_xml}")
    print(f"Wrote {out_rpt}")
    print(f"{sum(len(v) for v in redacted_tags.values())} values redacted across {len(redacted_tags)} tag types; "
          f"{len(review)} items need manual review.")


if __name__ == "__main__":
    sys.exit(main())
