# Wireshark: observing IoMT → datacenter traffic

**Optional.** You do not need Wireshark to see data flow: use **two terminals** as in the [README](README.md) — the **client** prints each outgoing payload and the **server** prints each accepted reading.

Use this on **your own** machine or VM when you are allowed to capture traffic for coursework.

This project generates **normal** HTTP traffic: the fake IoMT client (`iomt_client.py`) sends **POST** requests to the simulated datacenter (`uvicorn` on port **8000** by default).

## Where to capture

| Setup | Capture interface |
|--------|-------------------|
| Client and server on **same machine** (`127.0.0.1`) | **Loopback** (`lo` on Linux, `lo0` on macOS) |
| Client and server on **different hosts** | NIC that carries packets between them (e.g. `eth0`, `ens33`) |
| **Docker** | Bridge / veth for the container (depends on your `docker run -p` mapping) |

Start the capture **before** you run the IoMT client so you see the full TCP connection and HTTP bodies.

## Display filters (examples)

Replace `x.x.x.x` with the IP of the machine running the API (often `127.0.0.1`).

- HTTP to the service:  
  `http && ip.addr == x.x.x.x`
- TCP on the API port only:  
  `tcp.port == 8000 && ip.addr == x.x.x.x`

## What you should see

- **TCP handshake** (SYN, SYN-ACK, ACK) then **HTTP** requests.
- **POST** to `/api/appointments` with JSON containing `appointment_id`, `patient_id`, `doctor_id`, `appointment_date`, `appointment_time`, and related fields (from [`appointments_datastream.py`](appointments_datastream.py)).

Right‑click a packet → **Follow** → **TCP Stream** or **HTTP Stream** to view the full request/response for your report.

## Mapping to the prototype

| In Wireshark | In this repo |
|--------------|----------------|
| POST body with appointment JSON | [`appointments_datastream.next_appointment`](appointments_datastream.py) + [`iomt_client.py`](iomt_client.py) |
| HTTP responses from `:8000` | [`app/main.py`](app/main.py) |

## Export for reports

Use **File → Export Packet Dissections** or screenshots with a clear display filter applied.
