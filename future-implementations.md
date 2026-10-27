# Future implementations

Ownership proof and the public-host checks are now required by the scan API. Stay-inspect mode is optional and off unless the caller presses override.

## 2. Confirm the target before scanning it

Done in `safety.py` and the scan routes:

- `/verify/url` issues a token that the site must publish at `/.well-known/cyber-risk-verify.txt`.
- `/verify/source` issues a token for `cyber-risk-owner.txt` at the archive root. If that file or another owner label is present, it must match the caller or the scan is refused. Source with no owner label is scanned as theirs.
- Loopback, private, and link-local hosts are refused.
- The ownership file must not redirect. A scan redirect to a forbidden address is refused.
- Uploaded archives are capped by size, file count, and path.

## 6. Stay inspect-only

Done. Stay-inspect mode is optional and off by default.

- A scan keeps the current council command unless `stay_inspect` is true.
- Turning it on also requires `override_command: true`. That flag is the button. Without it the request is refused.
- When both are set, votes outside the preloaded checks are dropped and those commands are not run.
