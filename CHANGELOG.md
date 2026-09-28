# Changelog

## Unreleased

### Fixed
- **Tag-matching regex matched the entire document as one span.** The
  original leaf-tag pattern used a non-greedy `.*?` between an opening and
  closing tag, but on nested XML this matched from the very first opening
  tag to the very last matching closing tag in the whole file, so nothing
  inside was ever individually redacted. Fixed by requiring leaf tag
  content to contain no `<` characters (or, for CDATA content, to stop at
  `]]>`).
- **CDATA-wrapped secrets were not redacted at all.** pfSense wraps many
  fields as `<tag><![CDATA[value]]></tag>`. The CDATA opening marker itself
  contains a `<` character, which defeated the "no `<` in the leaf body"
  check above and let CDATA-wrapped secrets pass through untouched even
  after the fix above. Added a dedicated pattern for CDATA-wrapped tags,
  matched and redacted in the same pass as plain-text tags.
- **`maxmind_account` / `maxmind_key` were not recognized as secret
  fields.** These MaxMind GeoIP license credentials appear in both the
  ntopng and pfBlockerNG package configs and were missing from the tag
  list entirely (not a CDATA issue — just an omission).
- **`device_key` / `encryption_password` (Auto Config Backup) were not
  recognized as secret fields.** These are, respectively, the key tied to
  pfSense's ACB cloud backup feature and the password encrypting the
  backup archive itself — arguably the most sensitive fields in the whole
  file, since a leaked encryption password combined with the device key
  exposes every other secret in your entire backup history, not just the
  live config. Also affected by the CDATA bug for `encryption_password`.
- Added `keypaste` (a field for pasting a raw private key directly into an
  ACME certificate entry), `userkey` (Pushover), `api` (Telegram bot
  token), and `etpro_code` (alternate spelling of the Snort ET Pro code
  field) after a full audit of every tag name pfSense's config schema
  uses.

### Added
- Always-on email address redaction, independent of tag name, with
  consistent placeholder mapping so repeated use of the same address
  stays visibly the same address without revealing it.
- `dns_cfcf_key`, `dns_cfcf_email`, `dns_cfcf_account_id`, `preauthkey` to
  the secret tag list (Cloudflare ACME DNS-01 fields and Tailscale
  pre-auth key).
- `--mask-network` flag for consistent placeholder substitution of public
  IPv4 and MAC addresses.
- `--strict` flag for redacting long opaque base64-looking strings outside
  known tags.

This history exists because every one of these gaps was found by actually
running the tool against a real, complex pfSense config and manually
auditing the "redacted" output against the original — not by inspecting
the code in isolation. This project isn't actively maintained, so if you
find another gap, the fastest path is to fork the repo and fix it
yourself — contributions back via PR are welcome but not guaranteed a
timely review.
