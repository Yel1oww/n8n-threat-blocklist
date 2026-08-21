# Setup

How to run this yourself. Collection runs daily, publication weekly, and the
generated lists are committed to a GitHub repo you control.

**Requirements**

- Self-hosted n8n (the Execute Command node is required, so n8n Cloud won't work)
- Python 3.9+ on the same host as n8n
- Free API keys from [auth.abuse.ch](https://auth.abuse.ch) and
  [otx.alienvault.com](https://otx.alienvault.com)
- A GitHub repo to publish into, plus a fine-grained personal access token
- InfluxDB 2.x — optional, metrics only

Throughout this guide, `<n8n-user>` means the Linux user your n8n service runs
as. Find it with:

```bash
systemctl show -p User --value n8n
```

If that's empty, n8n may be running under your own account or in a container —
see [Running n8n in Docker](#running-n8n-in-docker) below.

---

## 1. Get your API keys

**abuse.ch** — sign up at [auth.abuse.ch](https://auth.abuse.ch) (you can use an
existing Google/GitHub account), then generate an Auth-Key from your profile.
One key covers both ThreatFox and URLhaus.

```bash
curl -s -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Auth-Key: YOUR_KEY" -d '{"query":"get_iocs","days":1}' | head -c 200
```

Expect `"query_status":"ok"`.

**OTX** — sign up at [otx.alienvault.com](https://otx.alienvault.com), then
Settings → OTX Key.

```bash
curl -s -H "X-OTX-API-KEY: YOUR_KEY" \
  https://otx.alienvault.com/api/v1/user/me | head -c 200
```

---

## 2. Create the publishing repo

A new **public** repo. Initialise it with a README so the default branch exists —
the GitHub API can't commit into a completely empty repo.

You don't need to pre-create the `lists/` directory. The workflow creates files
on first run; a 404 from GitHub is treated as "create", not an error.

**Personal access token:** Settings → Developer settings → Fine-grained tokens →
Generate new token.

- Repository access: **Only select repositories** → your new repo
- Repository permissions → **Contents: Read and write**
- Nothing else

Verify it:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer YOUR_PAT" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/OWNER/REPO
```

`200` means the token can see the repo. Fine-grained tokens return `404` rather
than `403` when the repo is out of scope, which is confusing but expected.

---

## 3. Install on the n8n host

```bash
sudo install -m 0755 ti-aggregate.py /usr/local/bin/ti-aggregate.py
sudo mkdir -p /var/lib/n8n-ti /var/cache/n8n-ti
sudo chown -R <n8n-user>:<n8n-user> /var/lib/n8n-ti /var/cache/n8n-ti
```

**The ownership step matters.** n8n's Execute Command node runs as the n8n
service user. If it can't write to `/var/lib/n8n-ti`, the workflow fails with a
permissions error that isn't obvious from the n8n UI.

> **Transfer the file, don't paste it.** Pasting Python into `nano` over SSH can
> pick up stray terminal escape characters. Use `scp`, then confirm:
> ```bash
> python3 -c "import ast;ast.parse(open('/usr/local/bin/ti-aggregate.py').read());print('OK')"
> ```

### Credentials

Keys live in a file on the host, not inside a workflow — so the workflow JSON
stays safe to export and commit.

```bash
sudo tee /etc/n8n-ti.env >/dev/null <<'EOF'
ABUSE_CH_KEY=your_abuse_ch_auth_key
OTX_KEY=your_otx_key
EOF
sudo chmod 640 /etc/n8n-ti.env
sudo chown root:<n8n-user> /etc/n8n-ti.env
```

`640` with `root:<n8n-user>` lets n8n read the file but not modify it. The
quoted `<<'EOF'` stops bash interpreting anything in your keys.

### Manual allowlist (optional but recommended)

Domains that must never be published, whatever a feed says. This is where
confirmed false positives go.

```bash
sudo touch /var/lib/n8n-ti/allowlist.txt
sudo chown <n8n-user> /var/lib/n8n-ti/allowlist.txt
```

---

## 4. Bootstrap and first run

Download the Tranco allowlist first — everything else depends on it.

```bash
set -a; . /etc/n8n-ti.env; set +a
ti-aggregate.py --mode tranco   < /dev/null
ti-aggregate.py --mode fetch    < /dev/null | python3 -m json.tool
```

Keep `< /dev/null`; without it the script waits on stdin for its options JSON
and looks like it's hung.

Check that every source reports `"error": false`. A failing source doesn't abort
the run by design — one dead feed shouldn't block the other four — but you'll
want to know about it.

### Review before publishing

```bash
ti-aggregate.py --mode generate < /dev/null > /tmp/gen.json
python3 -c "import json;print(json.dumps(json.load(open('/tmp/gen.json'))['stats'],indent=2))"
python3 -c "
import json,base64
d=json.load(open('/tmp/gen.json'))
lines=[l for l in base64.b64decode(d['files'][0]['b64']).decode().splitlines()
       if l and not l.startswith('#')]
print(len(lines),'domains in strict'); print('\n'.join(lines[:40]))"
```

**Read those 40 domains.** This is the one manual step and it matters, because
the output is public and other people may subscribe to it. Anything you
recognise as a real business goes into `allowlist.txt` before you publish.

A healthy `strict` list looks like disposable TLDs (`.icu`, `.top`, `.mom`),
dynamic-DNS hosts (`duckdns.org`, `no-ip`), and random-string domains. If you
see ordinary-looking small business domains, the classification needs tuning
before you go live.

---

## 5. Import the workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `04-ti-collect.json` | daily 03:00 | fetch feeds → SQLite → InfluxDB metrics |
| `05-ti-publish.json` | Sunday 08:00 | refresh Tranco → generate → commit to GitHub |

Placeholders to replace after import:

| Placeholder | Node | Value |
|---|---|---|
| `REPLACE_OWNER` / `REPLACE_REPO` | `05` → *Get Remote File*, *Commit File* | your GitHub owner and repo |
| `REPLACE_GITHUB_PAT` | `05` → *Get Remote File*, *Commit File* | `Bearer github_pat_...` |
| `REPLACE_ORG_ID` | `04`, `05` → InfluxDB nodes | your InfluxDB org ID |
| `REPLACE_INFLUX_TOKEN` | `04`, `05` → InfluxDB nodes | `Token ...` |

The PAT goes in **both** GitHub nodes, or the read succeeds and the write 401s.

**No InfluxDB?** Delete the `Write InfluxDB` and `Write Publish Metrics` nodes.
Nothing else depends on them.

---

## 6. Test

Run these manually — don't wait for the schedule, and don't run both at once
(they share a SQLite file).

**Workflow 04.** Execute Workflow, wait for it to finish. If a feed fails it
ends at *Raise Feed Error* and shows red — that's intentional, and the node
message names the broken feed.

**Workflow 05.** Execute Workflow. Expect:

- `Refresh Tranco` — slowest node, ~30s for a 25 MB download
- `Loop Files` — three iterations
- `Get Remote File` — `404` on first run for files that don't exist yet
- `Commit File` — runs once per changed file
- Three new commits in your repo

**Then run 05 a second time.** Every file should report `unchanged` and
`Commit File` should run **zero** times. This proves the SHA comparison works —
without it you'd accumulate 52 empty commits a year.

Activate both workflows once the tests pass.

---

## Running n8n in Docker

The Execute Command node runs *inside* the container, so:

- `ti-aggregate.py` and Python must exist in the container image
- `/var/lib/n8n-ti` and `/var/cache/n8n-ti` need to be mounted volumes, or the
  database is lost on every restart
- `/etc/n8n-ti.env` must be mounted read-only, or passed as container
  environment variables instead

A bind-mounted host directory is usually simplest. The paths are configurable
via `TI_DB`, `TI_CACHE`, and `TI_ALLOWLIST` if the defaults don't suit your
layout.

---

## Configuration

Environment variables read by `ti-aggregate.py`:

| Variable | Default | Purpose |
|---|---|---|
| `ABUSE_CH_KEY` | — | abuse.ch Auth-Key (required) |
| `OTX_KEY` | — | OTX API key (required) |
| `TI_DB` | `/var/lib/n8n-ti/state.db` | SQLite state file |
| `TI_CACHE` | `/var/cache/n8n-ti` | Tranco cache directory |
| `TI_ALLOWLIST` | `/var/lib/n8n-ti/allowlist.txt` | manual allowlist |
| `TI_TRANCO_RANK` | `100000` | how much of Tranco is treated as never-block |

In the script itself:

| Setting | Default | Purpose |
|---|---|---|
| `RETENTION_DAYS` | `90` | drop indicators not re-observed within this window |
| `SOURCE_TIERS` | — | per-feed trust level, drives strict-list eligibility |
| `UA` | — | User-Agent sent to feeds; **change this to your own repo URL** |

### Tuning the output

| Want | Change |
|---|---|
| Smaller, safer strict list | raise the `confidence < 75` threshold in `feed_threatfox` |
| More aggressive allowlisting | raise `TI_TRANCO_RANK` toward `1000000` |
| Less aggressive allowlisting | lower it toward `50000` — but watch for false positives |
| Longer memory | raise `RETENTION_DAYS` |
| Drop a feed | remove it from the `FEEDS` dict |

> **On `TI_TRANCO_RANK`:** the tail of the Tranco top 1M contains live malicious
> domains that rank purely because they receive traffic. Allowlisting all 1M
> will shield exactly the infrastructure you're trying to block. 100k is a
> reasonable balance.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `SyntaxError` near the last line | the script was pasted, not transferred — re-copy with `scp` |
| Script appears to hang | missing `< /dev/null`; it's waiting on stdin |
| `Tranco cache missing` | run `--mode tranco` first |
| Permission denied writing state.db | `/var/lib/n8n-ti` isn't owned by the n8n user |
| `405 Method Not Allowed` from a feed | that feed's API changed; check its current docs |
| GitHub `422 "sha" wasn't supplied` | the file exists but the SHA wasn't read — check *Decide Commit* output |
| GitHub `404` on a repo you own | fine-grained token lacks access to that repo |
| Commits every run with no changes | SHA comparison failing; inspect *Decide Commit* |
