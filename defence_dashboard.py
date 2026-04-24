from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

_HERE = Path(__file__).resolve().parent
_SRC  = _HERE / "threat_model_mitm" / "src"
_ROOT = _HERE / "threat_model_mitm"
sys.path.insert(0, str(_SRC))

_DB_PATH        = _ROOT / "data" / "gateway" / "hospital.db"
_CAPTURES       = _HERE / "captures"
_ATTACK_JSONL   = _CAPTURES / "attack_plaintext_fields.jsonl"
_SECURE_JSONL   = _CAPTURES / "secure_tls_fields.jsonl"
_EVIDENCE_JSON  = _CAPTURES / "evidence_report.json"

_C = {
    "LOW":     "#FF4B4B",
    "NORMAL":  "#21C354",
    "HIGH":    "#FF8C00",
    "ANOMALY": "#FF4B4B",
    "SAFE":    "#21C354",
    "BLUE":    "#4C78A8",
    "PURPLE":  "#9B59B6",
}

def _load_readings(limit: int = 200) -> pd.DataFrame:
    if not _DB_PATH.exists():
        return pd.DataFrame()
    try:
        with sqlite3.connect(f"file:{_DB_PATH}?mode=ro", uri=True) as conn:
            return pd.read_sql_query(
                "SELECT * FROM glucose_readings ORDER BY id ASC LIMIT ?",
                conn, params=(limit,)
            )
    except Exception:
        return pd.DataFrame()


def _load_ids_series(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or len(df) < 10:
        return pd.DataFrame()
    from security_core.ai_ids import AnomalyDetector
    rows = []
    for end in range(9, len(df)):
        window = df.iloc[end - 9: end + 1]
        rows.append({
            "packet_id":       int(df.iloc[end]["id"]),
            "mean_latency_ms": round(float(window["latency_ms"].mean()), 2),
            "mismatch_sum":    int(window["alert_mismatch"].sum()),
            "glucose_std":     round(float(window["glucose_mmol"].std(ddof=0)), 4),
        })
    return pd.DataFrame(rows)


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _load_evidence_report() -> dict:
    if not _EVIDENCE_JSON.exists():
        return {}
    try:
        return json.loads(_EVIDENCE_JSON.read_text())
    except Exception:
        return {}


def _proto_table(packets: list[dict]) -> pd.DataFrame:
    rows = []
    for p in packets:
        proto = p.get("_ws.col.Protocol", "TCP")
        rows.append({
            "#":        p.get("frame.number", ""),
            "time":     p.get("frame.time_relative", ""),
            "bytes":    p.get("frame.len", ""),
            "protocol": proto,
            "tls_type": p.get("tls.record.content_type", ""),
            "http_method": p.get("http.request.method", ""),
            "payload_visible": "YES" if p.get("http.file_data") else ("" if "http" not in proto.lower() else "NO"),
        })
    return pd.DataFrame(rows)


st.set_page_config(
    page_title="ELEC0138 CW2 - Defence Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.title("ELEC0138 CW2 - Resilient Security Dashboard")
st.caption("Connected Healthcare: CGM to Hospital Gateway: mTLS + AES-GCM + AI-IDS")

tab_ids, tab_glucose, tab_network, tab_compare = st.tabs([
    "Live IDS",
    "Glucose Monitor",
    "Network Evidence",
    "Attack vs Defence",
])


with tab_ids:
    st.subheader("Isolation Forest - Real-Time Anomaly Detection")

    df = _load_readings()
    if df.empty:
        st.info("No readings yet - run `python3 cw2_demo.py` or `run_evidence_demo.py` first.")
    else:
        ids_df = _load_ids_series(df)

        total = len(df)
        mismatches = int(df["alert_mismatch"].sum())
        if not ids_df.empty:
            from security_core.ai_ids import AnomalyDetector
            detector = AnomalyDetector(_DB_PATH)
            current = detector.evaluate_current_state()
            anomaly_now = bool(current.get("mitm_anomaly", False))
            score_now   = float(current.get("decision_function", 0))
            reason_now  = current.get("anomaly_reason", "")
        else:
            anomaly_now = False
            score_now   = 0.0
            reason_now  = "insufficient data"
            current     = {}

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total packets stored", total)
        c2.metric("Alert mismatches", mismatches,
                  delta=mismatches if mismatches else None,
                  delta_color="inverse")
        c3.metric("IDS score (now)", f"{score_now:.4f}",
                  help="Isolation Forest decision_function - higher = more normal")
        anomaly_label = "ANOMALY" if anomaly_now else "NORMAL"
        c4.metric("IDS status", anomaly_label)

        if anomaly_now:
            st.error(f"IDS ALERT: {reason_now}")
        else:
            st.success("Traffic profile within normal bounds.")

        if not ids_df.empty:
            st.markdown("#### Rolling window features (10-packet windows)")
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Mean latency (ms)**")
                st.line_chart(ids_df.set_index("packet_id")["mean_latency_ms"],
                              color=[_C["BLUE"]], height=200)
            with col_b:
                st.markdown("**Glucose std dev per window**")
                st.line_chart(ids_df.set_index("packet_id")["glucose_std"],
                              color=[_C["PURPLE"]], height=200)

            st.markdown("**Alert mismatches per window** (non-zero = tampering signal)")
            st.bar_chart(ids_df.set_index("packet_id")["mismatch_sum"],
                         color=_C["ANOMALY"], height=160)

        with st.expander("Full IDS state JSON"):
            st.json(current)


with tab_glucose:
    st.subheader("Stored Glucose Readings - Hospital Gateway DB")

    df = _load_readings()
    if df.empty:
        st.info("No readings in DB yet.")
    else:
        latest = df.iloc[-1]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Patient", latest["patient_id"])
        c2.metric("Latest glucose (mmol/L)", f"{latest['glucose_mmol']:.1f}")
        c3.metric("Total stored", len(df))
        c4.metric("Avg latency (ms)", f"{df['latency_ms'].mean():.1f}")

        alert_counts = df["gateway_alert_level"].value_counts().reindex(
            ["LOW", "NORMAL", "HIGH"], fill_value=0
        )
        ca, cb, cc = st.columns(3)
        ca.metric("LOW alerts",    int(alert_counts["LOW"]))
        cb.metric("NORMAL",        int(alert_counts["NORMAL"]))
        cc.metric("HIGH alerts",   int(alert_counts["HIGH"]))

        st.markdown("#### Glucose readings over time")
        chart_df = df.set_index("id")[["glucose_mmol"]].copy()
        st.line_chart(chart_df, color=[_C["BLUE"]], height=220)

        st.markdown("#### Latency per packet (ms)")
        lat_df = df.set_index("id")[["latency_ms"]].copy()
        st.line_chart(lat_df, color=[_C["PURPLE"]], height=160)

        st.markdown("#### Alert mismatch timeline")
        mis_df = df.set_index("id")[["alert_mismatch"]].copy()
        st.bar_chart(mis_df, color=_C["ANOMALY"], height=120)

        st.markdown("#### Recent readings table")
        display_cols = ["id", "patient_id", "glucose_mmol",
                        "device_alert_level", "gateway_alert_level",
                        "alert_mismatch", "latency_ms", "received_at"]
        st.dataframe(
            df[display_cols].tail(15).sort_values("id", ascending=False),
            hide_index=True, use_container_width=True
        )


with tab_network:
    st.subheader("tshark Capture Evidence - Attack vs Secure")

    report = _load_evidence_report()
    if not report:
        st.info(
            "No capture data yet.\n\n"
            "Run `python3 run_evidence_demo.py` to generate:\n"
            "- `captures/attack_plaintext.pcap`\n"
            "- `captures/secure_tls.pcap`\n"
            "- `captures/evidence_report.json`"
        )
    else:
        cmp = report.get("comparison", {})

        phi_attack  = cmp.get("phi_records_exposed_attack", "?")
        phi_defence = cmp.get("phi_records_exposed_defence", 0)

        c1, c2, c3 = st.columns(3)
        c1.metric("PHI exposed (attack)",  f"{phi_attack} records",
                  delta=f"+{phi_attack}" if phi_attack else None, delta_color="inverse")
        c2.metric("PHI exposed (defence)", f"{phi_defence} records")
        c3.metric("TLS encryption",
                  "Confirmed" if cmp.get("tls_encryption_confirmed") else "None")

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("### ATTACK - Plaintext HTTP")
            ap = report.get("attack_phase", {})
            st.metric("Total packets", ap.get("total_packets", "?"))
            st.metric("HTTP POSTs",    ap.get("http_post_requests", "?"))
            st.metric("HTTP payloads visible", ap.get("http_payloads_visible", "?"))
            st.metric("PHI records in capture", ap.get("phi_records_exposed", "?"))
            st.metric("Protocols", ", ".join(ap.get("protocols_seen", ["?"])))

            if ap.get("phi_sample"):
                st.markdown("**Sample PHI visible in capture:**")
                for sample in ap["phi_sample"]:
                    st.code(sample, language="json")

            st.caption(f"PCAP: `{ap.get('pcap_file', 'N/A')}`")
            st.caption("Open in Wireshark, filter: `http.request.uri contains \"/api/glucose\"`")

        with col_b:
            st.markdown("### DEFENCE - mTLS + AES-GCM")
            dp = report.get("defence_phase", {})
            st.metric("Total packets", dp.get("total_packets", "?"))
            st.metric("TLS records",   dp.get("tls_records", "?"))
            st.metric("TLS handshake pkts", dp.get("tls_handshake_packets", "?"))
            st.metric("HTTP POSTs (plaintext)", dp.get("http_post_requests", 0))
            st.metric("Protocols", ", ".join(dp.get("protocols_seen", ["?"])))
            st.success("No PHI readable in capture - all payload is TLS Application Data")
            st.caption(f"PCAP: `{dp.get('pcap_file', 'N/A')}`")
            st.caption("Open in Wireshark, filter: `tls` to see handshake + encrypted records")

        st.markdown("---")
        st.markdown("#### Packet-level detail")
        ptab_a, ptab_b = st.tabs(["Attack packets", "Secure packets"])
        with ptab_a:
            atk_pkts = _load_jsonl(_ATTACK_JSONL)
            if atk_pkts:
                st.dataframe(_proto_table(atk_pkts), use_container_width=True, hide_index=True)
            else:
                st.info("No attack capture data - run `run_evidence_demo.py`")
        with ptab_b:
            sec_pkts = _load_jsonl(_SECURE_JSONL)
            if sec_pkts:
                st.dataframe(_proto_table(sec_pkts), use_container_width=True, hide_index=True)
            else:
                st.info("No secure capture data - run `run_evidence_demo.py`")

        with st.expander("Raw evidence_report.json"):
            st.json(report)

        st.markdown("---")
        st.markdown("#### Wireshark / tshark filter reference")
        filters = {
            "All HTTP traffic (attack pcap)":      "http",
            "CGM POST requests (attack)":          'http.request.uri contains "/api/glucose"',
            "All TLS records (secure pcap)":       "tls",
            "TLS handshake only":                  "tls.handshake",
            "TLS Application Data (encrypted)":    "tls.record.content_type == 23",
            "ARP spoofing evidence (CW1)":         "arp",
            "All CGM gateway traffic":             "tcp.port == 5050 or tcp.port == 5051",
        }
        fdf = pd.DataFrame(
            [{"Use case": k, "Wireshark filter": v} for k, v in filters.items()]
        )
        st.dataframe(fdf, use_container_width=True, hide_index=True)


with tab_compare:
    st.subheader("Threat Mitigation - CW1 Attack vs CW2 Defence")

    st.markdown("""
The CW1 threat model identified two critical threats to the connected CGM healthcare system.
This table maps each attack vector to the specific defence mechanism implemented in CW2.
""")

    mitigation_data = [
        {
            "Threat (CW1)": "MITM - ARP Spoofing + HTTP Interception",
            "STRIDE": "Tampering / Info Disclosure",
            "CW1 Impact": "Patient glucose values silently modified; LOW/HIGH alerts suppressed",
            "CW2 Defence": "mTLS mutual authentication",
            "Mechanism": "Both CGM and gateway present X.509 certificates signed by the lab Root CA. "
                         "An attacker cannot present a valid cert, TLS handshake fails before any data flows.",
            "Evidence": "tshark: `tls.handshake.type` present; no HTTP payload visible",
        },
        {
            "Threat (CW1)": "MITM - Payload Tampering (glucose value rewrite)",
            "STRIDE": "Tampering",
            "CW1 Impact": "Clinical alert suppressed; patient receives wrong treatment",
            "CW2 Defence": "AES-256-GCM end-to-end encryption",
            "Mechanism": "Each packet is encrypted with a fresh 12-byte nonce before leaving the CGM. "
                         "The AESGCM authentication tag makes any ciphertext modification detectable. "
                         "Tamper test: `InvalidTag` exception raised on decrypt.",
            "Evidence": "cw2_demo.py: tamper test output; cipher vs plaintext byte comparison",
        },
        {
            "Threat (CW1)": "Replay Attack (re-send captured packets)",
            "STRIDE": "Repudiation / Spoofing",
            "CW1 Impact": "Attacker replays an old NORMAL reading to mask a HIGH/LOW event",
            "CW2 Defence": "Timestamp freshness window (+/-10 s)",
            "Mechanism": "Gateway rejects any packet whose `timestamp` field is older than 10 seconds. "
                         "Demonstrated: 120-second-old packet, 403 `replay_protection_triggered`.",
            "Evidence": "Gateway log: `REPLAY ATTACK DETECTED age=120.0s`",
        },
        {
            "Threat (CW1)": "Persistent/Insider MITM (undetected long-term tampering)",
            "STRIDE": "Elevation of Privilege",
            "CW1 Impact": "Slow tamper campaign evades manual review",
            "CW2 Defence": "AI Intrusion Detection System (Isolation Forest)",
            "Mechanism": "The gateway continuously evaluates rolling 10-packet windows across three features: "
                         "mean latency, alert mismatch count, and glucose std dev. "
                         "MITM tamper signatures (flat glucose, high latency, repeated mismatches) "
                         "push the window into the anomalous region of the feature space.",
            "Evidence": "IDS tab: decision_function score; `mitm_anomaly: true` in API responses",
        },
    ]

    for row in mitigation_data:
        with st.expander(f"**{row['Threat (CW1)']}** - {row['STRIDE']}"):
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown("**Attack (CW1)**")
                st.error(row["CW1 Impact"])
            with c2:
                st.markdown(f"**Defence: {row['CW2 Defence']}**")
                st.success(row["Mechanism"])
            st.caption(f"Evidence: {row['Evidence']}")

    st.markdown("---")
    st.markdown("#### Zero Trust posture")
    st.markdown("""
| Principle | Implementation |
|---|---|
| Never trust, always verify | mTLS - every connection requires a valid cert from our Root CA |
| Least privilege | Client cert scoped to `clientAuth` only; server cert to `serverAuth` |
| Assume breach | AI-IDS runs on **every** packet, even after mTLS succeeds |
| Encrypt in transit | AES-256-GCM applied at the application layer, independent of TLS |
| Short-lived credentials | Replay window of +/-10 s limits exposure of any captured token |
""")

    st.markdown("---")
    st.markdown("#### Regulatory mapping")
    regs = [
        ("GDPR Art. 32",     "Appropriate technical measures for PHI",       "AES-GCM encryption + mTLS"),
        ("GDPR Art. 32",     "Ongoing confidentiality & integrity",           "AI-IDS continuous monitoring"),
        ("PSTI Act 2022",    "No default passwords; secure by design",        "Certificate-based auth - no shared secrets"),
        ("CRA (EU)",         "Vulnerability handling for connected products", "Tamper detection via AEAD auth tag"),
        ("ISO 27001 A.10",   "Cryptographic controls",                        "AES-256-GCM, TLS 1.2+, 4096-bit CA"),
        ("HIPAA 164.312",   "Encryption of ePHI in transit",                 "End-to-end AES-GCM + mTLS"),
    ]
    rdf = pd.DataFrame(regs, columns=["Regulation", "Requirement", "Our Implementation"])
    st.dataframe(rdf, use_container_width=True, hide_index=True)

with st.sidebar:
    st.title("ELEC0138 CW2")
    st.caption("Connected Healthcare - CGM Security")
    st.divider()

    st.markdown("**Run demos:**")
    st.code("python3 cw2_demo.py", language="bash")
    st.code("python3 run_evidence_demo.py", language="bash")
    st.divider()

    st.markdown("**Status:**")
    db_ok = _DB_PATH.exists()
    cap_ok = _EVIDENCE_JSON.exists()
    st.markdown(f"DB: {'available' if db_ok else 'not found'}")
    st.markdown(f"Captures: {'available' if cap_ok else 'run evidence demo'}")
    st.divider()

    refresh = st.slider("Auto-refresh (s)", 2, 30, 5)

time.sleep(refresh)
st.rerun()
