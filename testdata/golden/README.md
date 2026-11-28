# Golden sessions

Each subdirectory with an `expect.json` is a recorded session. The test
`analyze::golden_tests` runs the real analyzer on it and compares two files:

- `expect.json`: a short summary for review. Episodes per interface, incident counts,
  causes, the Observer Trust level, session-wide blinds, and for every episode
  `(iface, start, end, duration_s, state, cause, origin, attribution, confidence, blinded)`.
- `snapshot.json`: the whole report, floats rounded to 4 decimals. It is the safety net for
  refactors (docs/ARCHITECTURE.md, R0): a refactor step must not change it.

The `-reclassified` variants hold the same views with `--reclassify`.

A change in the classifier or analyzer that changes a verdict on a real night
then shows up as a diff of `expect.json` in review.

The test fails when no fixture with `expect.json` runs.

## Privacy rule

**The repository is public. Review every fixture by eye before you commit it.**
The script removes what it knows about. It cannot know everything.
Real fixtures that you do not want to publish: name the directory `local-<name>`.
Git ignores `testdata/golden/local-*/`. The test still runs them on your machine.

## Make a fixture from a real session

1. Pick a time slice with one or two interesting incidents (a few minutes).
2. Run the script (Python 3, standard library only):

   ```sh
   python3 -I scripts/make-fixture.py <session_dir> testdata/golden/<name> \
       --from 2026-03-01T22:10:00Z --to 2026-03-01T22:25:00Z
   ```

   `--from` is inclusive, `--to` is exclusive. Times without a zone mean UTC.
   `--salt TEXT` makes the fake MACs repeatable between runs. Default: random salt.
3. Read the printed summary. Read every output file. Search it for names, places and numbers you know.
4. Write the expectation:

   ```sh
   LINKWATCH_UPDATE_GOLDEN=1 cargo test golden
   ```

5. Read the diff of `expect.json`. Check that each episode makes sense for that night.
   A diff only in `snapshot.json` means an output field changed: find out which one.
6. Commit the directory.

## Update expectations

When a change of the analyzer is intended:

1. Run `LINKWATCH_UPDATE_GOLDEN=1 cargo test golden`.
2. Read `git diff testdata/golden`. Each changed line is a changed verdict.
3. Explain the change in the commit message.

On mismatch, the test prints the lines that differ (`-` expected, `+` actual).

## What the script replaces

| Data | Replacement |
| --- | --- |
| MAC / BSSID, any separator | `02:xx:xx:xx:xx:xx` (locally administered), HMAC with a salt, same input gives the same output |
| SSID (keys with `ssid`, and `SSID "…"` in text) | `ssid-1`, `ssid-2`, … in order of appearance, also inside free text |
| IPv4 except public probe targets (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222, 208.67.220.220) | `192.0.2.x`, `198.51.100.x`, `203.0.113.x`. A source /24 keeps its host numbers, so the gateway stays distinct from LAN hosts. |
| IPv6 | `2001:db8::…` |
| host name, `host_id`, machine id | `host-redacted`, `hostid-redacted` |
| boot ids, run ids, `point` | `boot-N`, `run-N`, `point-N` |
| `label`, `note`, user and e-mail fields | `redacted` |
| e-mail addresses in text | `user@example.invalid` |
| URLs in text | user info, query and fragment removed |
| `meta.json` `config` | entries with token, secret, password, webhook, url, path, dir, file, key, cert, auth, user, smtp, bot in the name are dropped. Values that look like a path or URL are dropped. |

The script walks all JSON strings and keys, not only known fields.
It writes plain `.jsonl` files (it reads `.gz`). It does not copy `summary.json` or `heartbeat`.

## Self-check

After it writes the files, the script reads them again. It fails (exit code 2) and
deletes the output when it finds:

- a MAC-like string that is not one of its own fakes,
- an IPv4 address that is not a public probe target or one of its own fakes
  (private, link-local and CGNAT addresses are named in the message),
- an e-mail address,
- an original SSID, host name or id (4 characters or more) from the input.

## Limits

- Free text is cleaned only for MAC, IP, e-mail, URL and known SSID patterns.
  A name in a note, a street or a person name in free text stays. Read the files.
- Only three source /24 subnets keep their host numbers. More subnets get free fake addresses in order.
- An SSID shorter than 4 characters is replaced but not checked by the self-check.
- Fake addresses are public-looking (documentation ranges). The recorded path states stay as they were,
  so the analyzer result does not change. Logic that looks at address ranges would see different values.
- The time of the recording stays. The date and time of an incident can identify a night.
- The synthetic fixture `synthetic-dual-path` has no real data. It has a Wi-Fi-only drop,
  a dual-path drop and a drop during a speed test.
