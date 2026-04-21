# CGM MITM Demo Run Guide

Overall workflow for the controlled CGM-to-gateway MITM demo.

Component details:

- Attacker node: `src/machine3_attacker/README.md`
- Visual monitor: `src/visuals/README.md`
- Wireshark capture notes: `WIRESHARK.md`

## System Roles

- CGM node: sends glucose readings to the gateway API.
- Gateway node: runs the Flask API and stores readings in SQLite.
- Attacker node: uses ARP spoofing and a transparent proxy to inspect or tamper
  with CGM-to-gateway HTTP traffic.
- Visual monitor: read-only Streamlit dashboards for runtime evidence.

## Setup

From the group repo root:

```bash
sudo apt update
sudo apt install -y python3-venv
python3 -m venv threat_model_mitm/snp
source threat_model_mitm/snp/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r threat_model_mitm/requirements.txt
```

Activate later with:

```bash
source threat_model_mitm/snp/bin/activate
```

Attacker node system tools:

```bash
sudo apt install -y dsniff iptables tcpdump
```

## Configure

Set attacker network values from `threat_model_mitm/src/machine3_attacker/`:

```bash
python3 run_attack.py \
  --set-config cgm_ip="<cgm_ip_address>" \
  --set-config gateway_ip="<gateway_ip_address>" \
  --set-config network_interface="<network_interface>"

python3 run_attack.py --show-config
```

The CGM destination is supplied at runtime with `--gateway-ip`.

Set attacker tamper policy before runtime if the demo scenario changes. See
`src/machine3_attacker/README.md` for policy presets.

## Run Order

1. Start gateway on the gateway node:

```bash
python3 threat_model_mitm/src/main_cgm_api.py --mode gateway
```

2. Start attacker on the attacker node:

```bash
cd threat_model_mitm/src/machine3_attacker
sudo python3 run_attack.py
```

3. Start CGM on the CGM node:

```bash
python3 threat_model_mitm/src/main_cgm_api.py --mode cgm --gateway-ip <gateway_ip_address> --interval 1 --no-loop
```

## Visual Dashboards

Run one dashboard per node:

```bash
streamlit run threat_model_mitm/src/visuals/app.py --server.address 0.0.0.0 --server.port 8501 -- --node cgm
streamlit run threat_model_mitm/src/visuals/app.py --server.address 0.0.0.0 --server.port 8502 -- --node gateway
streamlit run threat_model_mitm/src/visuals/app.py --server.address 0.0.0.0 --server.port 8503 -- --node attacker
```

See `src/visuals/README.md` for path overrides and view details.

## Evidence Outputs

Gateway:

- `threat_model_mitm/data/gateway/hospital.db`
- `threat_model_mitm/src/machine2_gateway/logs/api_requests.log`
- `threat_model_mitm/src/machine2_gateway/logs/critical_alerts.log`

CGM:

- `threat_model_mitm/src/machine1_cgm/logs/cgm_sent_readings.log`

Attacker:

- `threat_model_mitm/src/machine3_attacker/logs/attack_packet_map.jsonl`
- `threat_model_mitm/src/machine3_attacker/logs/attack_summary.json`
- `threat_model_mitm/src/machine3_attacker/logs/phi_exposure.jsonl`

Quick checks:

```bash
tail -n 10 threat_model_mitm/src/machine2_gateway/logs/api_requests.log
ls -la threat_model_mitm/src/machine3_attacker/logs/
sqlite3 threat_model_mitm/data/gateway/hospital.db 'select patient_id, glucose_mmol, device_alert_level, gateway_alert_level from glucose_readings order by id desc limit 10;'
```

Use Wireshark or tcpdump screenshots as supporting evidence for plaintext HTTP
traffic and attacker in-path positioning.

## Stop Order

1. Stop CGM with `Ctrl+C`.
2. Stop attacker with `Ctrl+C`.
3. Wait 5-15 seconds for ARP caches to recover.
4. Stop gateway with `Ctrl+C`.
5. Stop Streamlit dashboards whenever.

Recovery commands if traffic does not recover after stopping the attack:

CGM node on macOS:

```bash
sudo arp -d <gateway_ip_address>
```

Gateway node on Linux:

```bash
sudo ip neigh flush all
```
