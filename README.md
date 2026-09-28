# pfsense-config-redact

A Python script to **redact secrets from a pfSense `config.xml` backup**
before posting it to a forum, pasting it into an LLM for troubleshooting
help, or sharing it with a coworker. Strips passwords, private keys, API
tokens, pre-shared keys, and other credentials pfSense stores in plaintext
in its config export — while keeping the file's structure intact so it's
still useful for debugging.

Runs entirely locally. Standard library only, no dependencies, no network
access, nothing leaves your machine.

## Why this exists

pfSense's `config.xml` backup is one big XML file with everything in it:
your admin password hash, VPN pre-shared keys and private keys, Dynamic DNS
API tokens, ACME/Let's Encrypt provider credentials, SNMP community
strings, SSH host keys, and — if you use it — the encryption password
protecting your Auto Config Backup archive. People regularly post this file
on the Netgate forum, r/PFsense, or paste it into ChatGPT/Claude for help
diagnosing a config issue, without realizing how much of it is live
credentials rather than just settings. This script is meant to make "share
your config for help" safe by default instead of something you have to get
right by hand every time.

## Usage

```
python3 pfsense_redact.py config.xml
python3 pfsense_redact.py config.xml --mask-network
python3 pfsense_redact.py config.xml --strict
```

Produces, next to the input file:

- `config.redacted.xml` — the sanitized config
- `config.report.txt` — what was redacted, plus a manual-review list of
  anything else in the file worth a second look (long opaque strings,
  leftover PEM headers, etc.)

### Options

- `--mask-network` — consistently replaces public IPv4 addresses and MAC
  addresses with placeholders (the same input value always maps to the same
  placeholder, so relationships between fields stay readable). RFC1918
  space is left alone.
- `--strict` — also redacts long base64-looking blobs found outside known
  secret tags. This can strip useful context too (e.g. base64-encoded
  `<descr>` notes or pfBlockerNG custom lists), so it's opt-in rather than
  default.

Email addresses are always redacted, regardless of flags, wherever they
appear in the file — not just inside fields explicitly named for them.

## What it catches

A tag-based pass strips known secret fields (passwords, private keys,
pre-shared keys, API tokens/keys, account IDs for various DNS/ACME
providers, SSH host keys, SNMP community strings, pfSense's Auto Config
Backup device key and encryption password, and more — see
`EXACT_SECRET_TAGS` and the `HEURISTIC` pattern in the script for the full
list), whether the value is stored as plain text or wrapped in pfSense's
`<![CDATA[...]]>` sections (a real gap in early versions of this script —
CDATA-wrapped secrets slipped through a naive "no `<` in the tag body"
check, since the CDATA opening marker itself contains one).

A second pass flags anything else that still looks secret-shaped — PEM
headers, long opaque strings — so you can eyeball it even if it wasn't
caught by tag name.

## What it won't catch

This is a best-effort tool, not a guarantee. In particular it can't reliably
find:

- Secrets pasted into free-text fields (`<descr>`, `<detail>`, notes) rather
  than their own dedicated tag
- Credentials embedded inside a custom URL (e.g. a DDNS "custom" provider's
  update URL with `user:pass@host` baked in)
- Anything in a package's config that doesn't follow a recognizable
  tag-naming pattern

**Always skim the `.redacted.xml` output yourself before sharing it
further, especially the `installedpackages` section for any third-party
package you have installed.** Treat this as a first pass, not a final
answer.

## FAQ

**How do I get my config.xml off pfSense?**
Diagnostics → Backup & Restore → Download configuration. Save it somewhere
on the machine you'll run this script from.

**Does this work with OPNsense too?**
No — OPNsense's config.xml uses a different (though related) tag schema,
and this script's tag list is built specifically from pfSense's field
names. Running it against an OPNsense config would miss most secrets.
Contributions to add OPNsense support are welcome.

**Will this catch everything sensitive in my config?**
No tool can guarantee that for arbitrary free-text fields. It catches every
known pfSense secret tag (including ones wrapped in `<![CDATA[...]]>`,
which earlier versions of this script missed — see CHANGELOG), plus
flags other suspicious-looking values for manual review. Always read the
`.redacted.xml` output yourself before sharing it, especially if you run
third-party packages (pfBlockerNG, ACME, Telegram/Pushover notifications,
Cloudflare DDNS, etc.) with their own credential fields.

**Why not just use `sed`/`grep` to strip out `<password>` tags myself?**
You can, but pfSense wraps many fields in CDATA sections, uses inconsistent
tag names across packages for conceptually similar secrets (API keys,
tokens, account IDs), and some genuinely secret fields don't have "password"
or "secret" in the name at all (an Auto Config Backup `device_key`, for
example). This script encodes that knowledge so you don't have to
rediscover it by leaking something first.

**I found a secret field this script misses. What do I do?**
Please open an issue or a PR — this project exists because that exact
thing has happened before (see CHANGELOG) and each report makes it better
for the next person.

## Disclaimer

This tool is provided as-is, with no warranty of any kind. It is a
best-effort pattern matcher, not a security guarantee — see "What it won't
catch" above. **You are solely responsible for reviewing the output and for
what you choose to share publicly.** The author is not responsible for any
secrets, credentials, or other sensitive information that this tool fails
to redact, or for any consequences of publishing a config file sanitized
(or not) with this tool.

If you're sharing a config publicly, read the redacted file yourself first.

## License

MIT — see [LICENSE](LICENSE). The license's standard "no warranty" clause
covers the software; the disclaimer above is about how you use it.
