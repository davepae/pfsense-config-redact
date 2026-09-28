# pfsense-config-redact

Sanitize a pfSense `config.xml` backup before sharing it — with a forum, an
LLM, a coworker, wherever. Strips passwords, private keys, API tokens, PSKs,
and other secrets pfSense stores in plaintext, while leaving the structure
intact so the file is still useful for troubleshooting or reference.

Runs entirely locally. Standard library only, no dependencies, no network
access.

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

## License

MIT
