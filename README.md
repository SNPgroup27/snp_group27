# Simulated datacenter + IoMT (coursework prototype)

This repo is a **small prototype** of a hospital-style **datacenter API** receiving **CGM-like** telemetry from a **fake IoMT client**. Data values are **random** for now (see [`cgm_datastream.py`](cgm_datastream.py)); you can swap that module for a real dataset later.

**Everything is meant to run in the terminal** — no browser or website is required. You see fake CGM payloads in one window (server) and another (client).

## What is included

| Piece | Role |
|--------|------|
| [`app/main.py`](app/main.py) | FastAPI **server**: ingest CGM JSON, list readings, `/health`, `/api/metrics` |
| [`app/metrics.py`](app/metrics.py) | In-process **request latency** and counters |
| [`cgm_datastream.py`](cgm_datastream.py) | **Fake CGM stream**: random glucose + timestamp in the format the API expects |
| [`iomt_client.py`](iomt_client.py) | **Fake IoMT device(s)**: POST readings on an interval; **prints each message** to the terminal |

## Prerequisites

- Python 3.10+

## Environment setup

The repo includes [`requirements.txt`](requirements.txt). Pick **conda** or **venv**.

### Conda

```bash
cd /path/to/snp_group27
conda env create -f environment.yml
conda activate snp_lab
python -c "from app.main import app; print('OK')"
```

Each new shell: `conda activate snp_lab` (from the repo root).

### venv

```bash
cd /path/to/snp_group27
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run in two terminals (terminal-only)

**Terminal 1 — datacenter server** (quiet HTTP access log so your own lines are easy to read):

```bash
cd /path/to/snp_group27
conda activate snp_lab   # or: source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

You should see a line like `[datacenter] accepted CGM reading device=… glucose_mg_dl=…` each time a reading arrives.

**Terminal 2 — fake IoMT device** (sends fake data slowly by default: every **5** seconds):

```bash
cd /path/to/snp_group27
conda activate snp_lab
python iomt_client.py --base-url http://127.0.0.1:8000
```

You should see lines like `[IoMT → datacenter] device=… glucose_mg_dl=… timestamp=…` for each POST.

- Slower pace: `--interval 10` (seconds between posts).  
- Faster: `--interval 2`.  
- Less output: `--quiet` (still prints errors and the final summary).

**Optional — inspect stored readings in the terminal** (third shell while server runs):

```bash
curl -s http://127.0.0.1:8000/api/cgm/readings | python -m json.tool
```

**Optional — Wireshark** (not required to see data): see [WIRESHARK.md](WIRESHARK.md).

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness |
| `GET` | `/api/metrics` | Request counts, errors, latency percentiles |
| `POST` | `/api/cgm/readings` | Ingest CGM reading JSON: `device_id`, `glucose_mg_dl`, optional `timestamp` |
| `GET` | `/api/cgm/readings` | Last N readings |
| `GET` | `/api/cgm/readings/latest/{device_id}` | Latest reading for a device |

## Further reading

- Observing HTTP traffic in Wireshark: [WIRESHARK.md](WIRESHARK.md)
