# php2shell-checker

Defensive tooling around **php2shell** (CVE-2026-109618 / CVE-2026-109619 —
a PHP `session.upload_progress` use-after-free). Live instance:
**https://p2s.cheeserobot.org**

## What's in here

| Path | What it is |
|---|---|
| `fleet-service/server.py` | The checker backend: stdlib-only Python service. Probes any URL you submit with **eight inert requests** and reports which defenses against the CVE are observable: version banner vs the patched list (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), multipart reachability on POST/PUT/PATCH, and a session-fixation probe (a random `PHPSESSID` **form field** — never an upload-progress field, never a file part, so the vulnerable code path is never engaged). PoW-gated, one URL at a time, results cached and shared between visitors. |
| `fleet-service/index.html` | The single-page browser UI. |
| `fleet-service/llms.txt` | Verdicts, honest limits, and the JSON API — also served at `/llms.txt`. |

The research POC lives in a separate repo and is not part of this one.

## Verdicts

`PATCHED` · `UNPATCHED` · `BLOCKED` · `ASSUMED VULNERABLE` ·
`NO PHP DETECTED` · `OFFLINE` · `UNKNOWN` — exact meanings and the honesty
limits of remote checking live in
[`fleet-service/llms.txt`](fleet-service/llms.txt).

## Scanned-URL rules

Targets are scanned exactly as submitted, so the front door is strict — the
UI strips query parameters/fragments and asks you to re-submit the cleaned
address; the server refuses them with a 422 regardless. Also refused:
`../` path traversal, backslashes, credentials in the URL, whitespace/control
characters, and single-label hosts (`localhost` & friends). Hosts must be
public dotted DNS names or IP literals; private ranges are blocked by the
per-hop SSRF guard.

## No guarantees

Results are best-effort indications from the outside — banners can lie,
caches can hide the origin, edges behave differently per route. This is not
a vulnerability assessment; verify on the host.

## Self-host

    cd fleet-service
    python3 server.py --port 8971  # then put TLS in front (nginx/caddy)
