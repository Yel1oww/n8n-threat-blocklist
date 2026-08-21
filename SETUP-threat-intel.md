# Threat Intel Aggregator — setup

Collects daily from five feeds, publishes weekly to
`github.com/Yel1oww/n8n-threat-blocklist`.

## 1. Install

```bash
sudo install -m 0755 ti-aggregate.py /usr/local/bin/ti-aggregate.py
sudo mkdir -p /var/lib/n8n-ti /var/cache/n8n-ti
sudo chown -R pedro:pedro /var/lib/n8n-ti /var/cache/n8n-ti
```

## 2. Credentials

The script reads keys from the environment; n8n sources this file before each
run, so nothing sensitive ends up inside a workflow.

```bash
sudo tee /etc/n8n-ti.env >/dev/null <<'EOF'
ABUSE_CH_KEY=your_abuse_ch_auth_key
OTX_KEY=your_otx_key
EOF
sudo chmod 640 /etc/n8n-ti.env
sudo chown root:pedro /etc/n8n-ti.env
```

`root:pedro` with `640` means the n8n user can read it but not modify it.

## 3. Manual allowlist

Domains you never want published, whatever the feeds say. One per line,
`#` for comments. Optional but worth creating empty.

```bash
touch /var/lib/n8n-ti/allowlist.txt
```

## 4. Bootstrap Tranco (required before the first fetch)

Downloads and caches the top 1M domains — about 25 MB compressed.

```bash
set -a; . /etc/n8n-ti.env; set +a
/usr/local/bin/ti-aggregate.py --mode tranco < /dev/null
```

Expect `{"cached": 1000000, ...}`.

## 5. First collection

```bash
set -a; . /etc/n8n-ti.env; set +a
/usr/local/bin/ti-aggregate.py --mode fetch < /dev/null | python3 -m json.tool
```

Check the per-source `accepted` counts. A source reporting `"error": true` is
usually a wrong key or a changed endpoint — the run continues regardless, by
design, so one dead feed never blocks the rest.

## 6. Dry-run the generator

```bash
/usr/local/bin/ti-aggregate.py --mode generate < /dev/null \
  | python3 -c "import json,sys,base64; d=json.load(sys.stdin); print(json.dumps(d['stats'],indent=2)); print(base64.b64decode(d['files'][0]['b64']).decode()[:600])"
```

**Read the first 50 domains before you publish anything.** If you recognise any
of them as legitimate, add them to `allowlist.txt` and regenerate. This is the
one manual review step and it matters — the list is public.

## 7. Import the workflows

| Workflow | Trigger | Placeholders to fill |
|---|---|---|
| `04-ti-collect.json` | daily 03:00 | Influx org ID + token |
| `05-ti-publish.json` | Sunday 08:00 | GitHub PAT |

The GitHub PAT goes in the `Authorization` header of **both** `Get Remote File`
and `Commit File`, as `Bearer ghp_...`.

Create the `threat-intel` bucket in InfluxDB first (retention 365d).

## 8. Test the publish path

> **No notifications configured.** A failed feed makes workflow 04 stop with an
> error, so it shows red in n8n's execution list, and the Grafana panels flatline.
> Check Overview → Executions periodically, or set an n8n **Error Workflow**
> under workflow Settings if you want something to catch failures automatically.


Don't wait for Sunday. Open workflow 05 → **Execute Workflow**. Watch that:

- `Get Remote File` returns 404 for files that don't exist yet (expected — it
  runs with `neverError` so a 404 is treated as "create", not a failure)
- `Commit File` runs once per changed file
- The repo shows three new commits
- `Build Summary` shows counts and per-file actions in its output

Run it a second time immediately. Every file should report `unchanged` and no
commits should be made. That proves the SHA comparison works and the repo won't
fill up with empty weekly commits.

## 9. Point Pi-hole at it

Once the first real list is published, Settings → Adlists:

```
https://raw.githubusercontent.com/Yel1oww/n8n-threat-blocklist/main/lists/aggressive.txt
```

Then `pihole -g` to update gravity.

Use `aggressive.txt` for yourself — you can allowlist a domain in seconds when
something breaks. Point other people at `strict.txt` in the README.

**This does not affect your ad blocking.** Pi-hole blocks the union of all
adlists; nothing in this file can unblock anything. The Tranco filter only
controls what goes *into* the published file.

---

## How scoring works

| Source | Tier | Notes |
|---|---|---|
| blackbook | 1 | Malware-dedicated domains only, compromised sites excluded upstream |
| ThreatFox | 1 | Confidence ≥ 75 only; `botnet_cc` marked as dedicated infrastructure |
| URLhaus | 2 | Path-depth heuristic separates dedicated hosting from compromised sites |
| OTX | 3 | Community-submitted; corroboration only |
| OpenPhish | 3 | Mostly compromised hosts; aggressive list only |

**strict.txt** — `dedicated AND (tier 1 OR ≥2 sources)`
**aggressive.txt** — everything not caught by an allowlist

Both lists are filtered against the Tranco top 1M *and* your manual allowlist,
at fetch time and again at generate time (the Tranco list changes between runs).
Indicators not re-observed within 90 days are dropped.

## Tuning

| Want | Change |
|---|---|
| Longer memory | `RETENTION_DAYS` in `ti-aggregate.py` |
| Stricter ThreatFox | raise the `conf < 75` threshold in `feed_threatfox` |
| Add/remove a source | edit the `FEEDS` dict and `SOURCE_TIERS` |
| Never publish a domain | add it to `/var/lib/n8n-ti/allowlist.txt` |
