# Simulated datacenter + IoMT (coursework prototype)

This repo is a **small prototype** of a hospital-style **datacenter API** receiving\n**appointment booking requests** from a **fake IoMT client**.\n\nThe appointment payloads are built from the Kaggle\n`hospital-management-dataset` (`appointments.csv`) and replayed\ntowards the API. All interaction is via the **terminal** — no browser or UI is required.

## What is included

| Piece | Role |
|--------|------|
| [`app/main.py`](app/main.py) | FastAPI **server**: ingest **appointments**, `/health`, `/api/metrics` |
| [`app/metrics.py`](app/metrics.py) | In-process **request latency** and counters |
| [`appointments_datastream.py`](appointments_datastream.py) | Appointment datastream built from `data/appointments.csv` |
| [`iomt_client.py`](iomt_client.py) | **Fake IoMT client**: POST appointment bookings on an interval; **prints each message** to the terminal |

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

Every new terminal:

```bash
cd /path/to/snp_group27
conda activate snp_lab
```

#### Option B: venv (standard library)

```bash
cd /path/to/snp_group27
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c "from app.main import app; print('OK')"
```

Every new terminal:

```bash
cd /path/to/snp_group27
source .venv/bin/activate
```

### 3. Download the Kaggle appointments CSV (once per machine)

This uses KaggleHub and writes a local copy to `data/appointments.csv`.

```bash
cd /path/to/snp_group27
python scripts/download_appointments_csv.py
```

You should see a message about copying `appointments.csv` into `data/appointments.csv`.

After this step, the app only reads from the local CSV and does not call Kaggle again unless you re-run the script.

## Run in two terminals (terminal-only)

**Terminal 1 — datacenter server** (quiet HTTP access log so your own lines are easy to read):

```bash
cd /path/to/snp_group27
conda activate snp_lab   # or: source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

You should see lines like `[datacenter] accepted appointment id=… patient=… doctor=… date=… time=…` as requests arrive.

**Terminal 2 — fake IoMT appointments client** (sends one booking every **5** seconds by default):

```bash
cd /path/to/snp_group27
conda activate snp_lab
python iomt_client.py --base-url http://127.0.0.1:8000
```

You should see lines like `[Appointments → datacenter] client=… appointment_id=… patient=… doctor=… date=… time=…` for each POST.

- Slower pace: `--interval 10` (seconds between posts).  
- Faster: `--interval 2`.  
- Less output: `--quiet` (still prints errors and the final summary).

**Optional — inspect stored appointments in the terminal** (third shell while server runs):

```bash
curl -s http://127.0.0.1:8000/api/appointments | python -m json.tool
```

**Optional — Wireshark** (not required to see data): see [WIRESHARK.md](WIRESHARK.md).

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness |
| `GET` | `/api/metrics` | Request counts, errors, latency percentiles |
| `POST` | `/api/appointments` | Ingest appointment JSON (schema from `appointments.csv`) |
| `GET` | `/api/appointments` | Last N appointments |

## Further reading

- Observing HTTP traffic in Wireshark: [WIRESHARK.md](WIRESHARK.md)
