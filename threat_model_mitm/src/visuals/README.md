# CGM MITM Visual Monitor

Read-only Streamlit dashboards for CGM, gateway, and attacker evidence.

## Inputs

Paths are resolved from `config.json` in this folder, with fallback paths for
the full repo layout.

- CGM: `threat_model_mitm/src/machine1_cgm/logs/cgm_sent_readings.log`
- Gateway: `threat_model_mitm/data/gateway/hospital.db`
- Gateway alerts: `threat_model_mitm/src/machine2_gateway/logs/critical_alerts.log`
- Attacker packets: `threat_model_mitm/src/machine3_attacker/logs/attack_packet_map.jsonl`
- Attacker summary: `threat_model_mitm/src/machine3_attacker/logs/attack_summary.json`
  after attacker shutdown

The gateway database is opened read-only. Missing files show waiting states.

## Run

From the repo root:

```bash
streamlit run threat_model_mitm/src/visuals/app.py -- --node baseline
streamlit run threat_model_mitm/src/visuals/app.py -- --node cgm
streamlit run threat_model_mitm/src/visuals/app.py -- --node gateway
streamlit run threat_model_mitm/src/visuals/app.py -- --node attacker
```

Split-node dashboard ports:

```bash
streamlit run threat_model_mitm/src/visuals/app.py --server.address 0.0.0.0 --server.port 8501 -- --node cgm
streamlit run threat_model_mitm/src/visuals/app.py --server.address 0.0.0.0 --server.port 8502 -- --node gateway
streamlit run threat_model_mitm/src/visuals/app.py --server.address 0.0.0.0 --server.port 8503 -- --node attacker
```

Open `http://<node_ip>:<port>` from the browser.

## Views

- `baseline`: CGM and gateway on one filesystem
- `cgm`: sent CGM readings
- `gateway`: stored readings and critical alert log
- `attacker`: intercepted packets, tampering evidence, and summary counters

## Path Overrides

Priority:

```text
CLI override > visuals/config.json > fallback paths
```

Examples:

```bash
streamlit run threat_model_mitm/src/visuals/app.py -- --node cgm --cgm-log /path/to/cgm_sent_readings.log
streamlit run threat_model_mitm/src/visuals/app.py -- --node gateway --gateway-db /path/to/hospital.db
streamlit run threat_model_mitm/src/visuals/app.py -- --node attacker --attack-jsonl /path/to/attack_packet_map.jsonl --attack-summary /path/to/attack_summary.json
```

## Controls

- Patient selector is detected from local data sources where available.
- Refresh interval controls disk re-read frequency.
- Alert colours are consistent across panels: LOW red, NORMAL green, HIGH orange.

## Attacker Chart

- Original line: glucose value intercepted from the CGM.
- Modified line: glucose value forwarded to the gateway.
- Divergence indicates a tamper event.

During a live attack, counters are derived from `attack_packet_map.jsonl`.
After shutdown, `attack_summary.json` provides the final aggregate summary.
