# Simulated datacenter + IoMT (coursework prototype)

This repo is a **small prototype** of a hospital-style **datacenter API** receiving **appointment booking requests** from a **fake IoMT client**.

Appointment payloads are built from the Kaggle `hospital-management-dataset` (`appointments.csv`) and replayed toward the API. All interaction is via the **terminal** — no browser or UI is required.

## Repository layout

| Path | Role |
|------|------|
| [`app/main.py`](app/main.py) | FastAPI server: `/health`, `/api/metrics`, `/api/appointments`, CAPTCHA challenge, defence status routes |
| [`app/metrics.py`](app/metrics.py) | In-process request latency, errors, appointment post counts |
| [`appointments_datastream.py`](appointments_datastream.py) | Streams rows from `data/appointments.csv` into JSON-shaped dicts |
| [`iomt_client.py`](iomt_client.py) | Simulated IoMT device: POSTs appointments on an interval; optional `--use-captcha`; on loopback to `127.0.0.1` binds source `127.0.0.2` by default (distinct from HTTP flood default) |
| [`defence/syn_defence.py`](defence/syn_defence.py) | **SYN defence (Linux, root):** kernel **SYN cookies** (`tcp_syncookies`), iptables **`SNP_ASA`** (stateful limits, optional **SYNPROXY**), sysctl profile, `/proc` helpers |
| [`defence/http_firewall.py`](defence/http_firewall.py) | **HTTP / TCP port shaper (Linux, root):** iptables **`SNP_HTTP`** — per-source `hashlimit` on traffic to a **dport** (reduces PPS to userspace after/alongside TCP) |
| [`defence/captcha.py`](defence/captcha.py) | Checkbox CAPTCHA state file + challenge/verify + per-IP rate window when CAPTCHA is on |
| [`attacks/syn_flood.py`](attacks/syn_flood.py) | **SYN flood (Scapy, `sudo`):** defaults RandIP spoof; `--no-spoof` for single-source loopback |
| [`attacks/http_flood.py`](attacks/http_flood.py) | **HTTP flood (`httpx`):** concurrent POSTs to `/api/appointments`; on `127.0.0.1` default bind `127.0.0.3` |
| [`scripts/download_appointments_csv.py`](scripts/download_appointments_csv.py) | One-time download of CSV into `data/appointments.csv` |
| [`WIRESHARK.md`](WIRESHARK.md) | Display filters and capture notes |

**Stacking iptables:** Only the **first** matching `INPUT` / `raw` rule wins for a packet. Do not enable **`syn_defence`** and **`http_firewall`** on the **same port** without checking `iptables -S INPUT` / `iptables -t raw -S PREROUTING` order (or use one defence at a time).

## Prerequisites

- Python 3.10+
- **SYN attack & kernel defences:** Linux is assumed for `iptables`, `/proc`, and Scapy raw sockets.

## Environment setup

Use [`requirements.txt`](requirements.txt) with **conda** or **venv**.

### Conda

```bash
cd /path/to/snp_group27
conda env create -f environment.yml
conda activate snp_lab
python -c "from app.main import app; print('OK')"
```

### venv

```bash
cd /path/to/snp_group27
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c "from app.main import app; print('OK')"
```

### Download `data/appointments.csv` (once per machine)

Uses KaggleHub and writes `data/appointments.csv`.

```bash
cd /path/to/snp_group27
python scripts/download_appointments_csv.py
```

The app reads only the local file after this (no Kaggle calls until you re-run the script).

## Run the happy path (two terminals)

**Terminal 1 — API server**

```bash
cd /path/to/snp_group27
conda activate snp_lab   # or: source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

**Terminal 2 — fake IoMT client** (one POST every **5** s by default)

```bash
python iomt_client.py --base-url http://127.0.0.1:8000
```

- Slower: `--interval 10` — faster: `--interval 2` — quieter: `--quiet`
- With **CAPTCHA** enabled on the server: add `--use-captcha`

**Optional — list stored appointments**

```bash
curl -s http://127.0.0.1:8000/api/appointments | python -m json.tool
```

## Attacks (lab)

| Attack | Command | Notes |
|--------|---------|--------|
| **SYN flood** | `sudo $(which python) attacks/syn_flood.py` or `sudo $(which python) -m attacks.syn_flood` | Default **RandIP** spoof; `--no-spoof` for single 127.0.0.1 source; defaults `127.0.0.1:8000`, `--count 20000`, `--batch 200` |
| **HTTP flood** | `python attacks/http_flood.py --target http://127.0.0.1:8000` | Defaults `--concurrency 50`, `--duration 20`, path `/api/appointments`. Target host `127.0.0.1` → bind `127.0.0.3` unless `--source-ip` is set |

Use the **same** conda/venv Python with **`sudo`** for Scapy so imports resolve.

## Defences (how they map to the code)

### SYN (network / kernel) — `defence.syn_defence`

- **Kernel SYN cookies:** `on` / `asa-on` sets `tcp_syncookies=1` (see **`GET /api/defence/syn-cookies`** for live sysctl + half-open / TcpExt syncookie stats where available).
- **iptables `SNP_ASA`:** INVALID drop, trusted/recent, **per-source** `connlimit`, **global** NEW SYN/s (`--threshold`, default **5**), optional **established** PPS (`--est-pps`, default **100**; `0` = legacy all-ACCEPT for EST).
- **SYNPROXY (optional):** `asa-intercept` (or `on` does not add SYNPROXY; use the intercept subcommand) on **`raw/PREROUTING`** if the kernel supports it.
- **Kernel-only profile (no `SNP_ASA`):** `kernel-on` / `kernel-off` / `kernel-status` — backlog, `somaxconn`, `rp_filter`, etc.
- **Persist sysctl:** `persist-on` / `persist-off` (writes `/etc/sysctl.d/…`).
- **Read-only (often no root):** `status`, `compliance`, `half-open`, `monitor`, `counts` / `asa-counters`.

**Short commands**

```text
sudo $(which python) -m defence.syn_defence on
sudo $(which python) -m defence.syn_defence off
sudo $(which python) -m defence.syn_defence counts
```

Common options: `--port 8000` `--threshold 5` `--est-pps 100`

### HTTP port shaping (network) — `defence.http_firewall`

- iptables chain **`SNP_HTTP`**: per-source **hashlimit** on EST/REL and NEW SYNs to `--port` (defaults `--est-pps 200`, `--new-syn 20`, optional `--max-conn`).

```text
sudo $(which python) -m defence.http_firewall on
sudo $(which python) -m defence.http_firewall off
python -m defence.http_firewall status
```

**API:** `GET /api/defence/http-firewall`

### Application layer — CAPTCHA

- **Toggle (file):** `python defence/captcha.py --on` / `--off` / `--status` — **restart uvicorn** after changing file, or use env.
- **Env:** `ENABLE_APPOINTMENT_CAPTCHA=1` or `DISABLE_APPOINTMENT_CAPTCHA=1` (see [`defence/captcha.py`](defence/captcha.py) for precedence).
- When enabled: middleware **per-IP rate limit** on `POST /api/appointments`, then **challenge/verify**; IoMT: `python iomt_client.py --use-captcha`.
- Legitimate users must obtain **`GET /api/captcha/challenge`** and send `captcha_challenge_id` + `captcha_answer` on the POST; missing/invalid → **400** / **403**; flood without solving CAPTCHA → errors; burst → **429** from rate limit.

**API:** `GET /api/defence/captcha-status`

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness |
| `GET` | `/api/metrics` | Request count, errors, `appointment_posts`, latency percentiles |
| `GET` | `/api/defence/syn-cookies` | Linux: `tcp_syncookies`, SYN-RECV counts, syncookie TcpExt, `rp_filter` / ingress **guidance** JSON |
| `GET` | `/api/defence/http-firewall` | Linux: whether **`SNP_HTTP`** jump is present for port 8000 |
| `GET` | `/api/defence/captcha-status` | CAPTCHA env, persisted file, effective on/off |
| `GET` | `/api/captcha/challenge` | Issue a one-time checkbox challenge |
| `POST` | `/api/appointments` | Ingest appointment JSON; CAPTCHA + rate limit when enabled |
| `GET` | `/api/appointments?limit=…` | Last N stored appointments (default 50, max 500) |

## Further reading

- Wireshark: [WIRESHARK.md](WIRESHARK.md) — e.g. `http && ip.addr == 127.0.0.1`, `tcp.port == 8000`; for direction, `ip.dst == 127.0.0.1` with **`tcp.dstport == 8000`** (not `dport`).
