from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

log = logging.getLogger("tshark")


class TsharkCapture:
    _FIELDS = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "frame.len",
        "tcp.flags.str",
        "tls.record.content_type",
        "tls.handshake.type",
        "http.request.method",
        "http.request.uri",
        "http.file_data",
        "http.response.code",
        "tcp.payload",
        "_ws.col.Protocol",
    ]

    def __init__(
        self,
        port: int,
        label: str,
        out_dir: Path,
        interface: str = "lo",
    ) -> None:
        self._port = port
        self._label = label
        self._out_dir = Path(out_dir)
        self._interface = interface
        self._out_dir.mkdir(parents=True, exist_ok=True)

        self._pcap_path = self._out_dir / f"{label}.pcap"
        self._json_path = self._out_dir / f"{label}_fields.jsonl"
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        cmd = [
            "tshark",
            "-i", self._interface,
            "-f", f"tcp port {self._port}",
            "-w", str(self._pcap_path),
            "-q",
        ]
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info("Capture started label=%s port=%d pcap=%s",
                 self._label, self._port, self._pcap_path)
        time.sleep(0.5)

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
            log.info("Capture stopped label=%s", self._label)

        if self._pcap_path.exists():
            self._export_fields()

    def _export_fields(self) -> None:
        args = ["tshark", "-r", str(self._pcap_path), "-T", "fields", "-E", "header=n",
                "-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f"]
        for field in self._FIELDS:
            args += ["-e", field]

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            log.warning("Field export timed out")
            return

        packets = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != len(self._FIELDS):
                continue
            pkt = dict(zip(self._FIELDS, parts))
            pkt = {k: v for k, v in pkt.items() if v}
            packets.append(pkt)

        with open(self._json_path, "w", encoding="utf-8") as fh:
            for pkt in packets:
                fh.write(json.dumps(pkt) + "\n")

        log.info("Exported %d packets jsonl=%s", len(packets), self._json_path)

    def load_packets(self) -> list[dict]:
        if not self._json_path.exists():
            return []
        packets = []
        with open(self._json_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        packets.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return packets

    @staticmethod
    def _decode_hex_payload(hex_str: str) -> str:
        try:
            return bytes.fromhex(hex_str.replace(":", "")).decode("utf-8", errors="replace")
        except Exception:
            return hex_str

    def summarise(self) -> dict:
        packets = self.load_packets()
        total = len(packets)
        if total == 0:
            return {"label": self._label, "total_packets": 0, "note": "no packets captured"}

        tls_records   = [p for p in packets if "tls.record.content_type" in p]
        tls_handshake = [p for p in packets if "tls.handshake.type" in p]
        http_posts    = [p for p in packets if p.get("http.request.method") == "POST"]
        http_payloads = [p for p in packets if p.get("http.file_data") or p.get("tcp.payload")]
        phi_exposed   = []
        for p in http_posts:
            raw_hex = p.get("http.file_data", "") or p.get("tcp.payload", "")
            if raw_hex:
                decoded = self._decode_hex_payload(raw_hex)
                if "patient_id" in decoded or "glucose" in decoded:
                    phi_exposed.append(decoded[:300])

        data_packets = [p for p in packets if p.get("_ws.col.Protocol") not in ("TCP", "")]
        unique_protocols = sorted({p.get("_ws.col.Protocol", "TCP") for p in packets if p.get("_ws.col.Protocol")})
        total_bytes = sum(int(p.get("frame.len", 0)) for p in packets if p.get("frame.len", "").isdigit())

        return {
            "label": self._label,
            "pcap_file": str(self._pcap_path),
            "jsonl_file": str(self._json_path),
            "total_packets": total,
            "total_bytes": total_bytes,
            "protocols_seen": unique_protocols,
            "tls_records": len(tls_records),
            "tls_handshake_packets": len(tls_handshake),
            "http_post_requests": len(http_posts),
            "http_payloads_visible": len(http_payloads),
            "phi_records_exposed": len(phi_exposed),
            "phi_sample": phi_exposed[:2],
            "plaintext_http": len(http_posts) > 0,
            "encrypted": len(tls_records) > 0 and len(http_posts) == 0,
        }

    @property
    def pcap_path(self) -> Path:
        return self._pcap_path

    @property
    def json_path(self) -> Path:
        return self._json_path
