"""Convert GlucoBench rows into minimal CGM packet files with basic EDA.

Data preprocessed from "GlucoBench: Glucose Monitoring and Lifestyle Data"
https://www.kaggle.com/datasets/omenkj/glucobench-glucose-monitoring-and-lifestyle-data
Stored in ./threat_model_mitm/data/cgm_packets_normal/ for use in the MITM simulator
Final Normal System Flow uses data from U001 Data.
"""

from __future__ import annotations

import csv
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any

# Placeholder path for offline preprocessing only, and should be run before simulator setup/worflow.
DATASET_PATH = "./path/to/GlucoBench_benchmark_dataset.csv"
OUTPUT_DIR = Path("./threat_model_mitm/data/cgm_packets_normal")
REQUIRED_COLUMNS = ("glucose", "timestamp", "user_id", "device_id")
ALERT_LEVELS = ("LOW", "NORMAL", "HIGH")


logging.basicConfig(level=logging.INFO, format="%(message)s")
LOGGER = logging.getLogger(__name__)


class CGMPacketPreprocessor:
    """Convert dataset rows into per-patient CGM packet files and EDA summaries."""

    def __init__(
        self,
        dataset_path: str = DATASET_PATH,
        output_dir: Path = OUTPUT_DIR,
    ) -> None:
        """Initialise the preprocessor with input and output locations."""
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.stats: dict[str, Any] = {
            "total_rows": 0,
            "valid_rows": 0,
            "skipped_rows": 0,
            "errors": [],
            "columns": {},
            "alert_distribution": {level: 0 for level in ALERT_LEVELS},
            "eda": {},
            "patients": {},
        }
        self.packets_by_patient: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
        self.glucose_values: list[float] = []

    @staticmethod
    def mg_dl_to_mmol_l(mg_dl: float) -> float:
        """Convert glucose from mg/dL to mmol/L."""
        return round(mg_dl / 18.0, 1)

    @staticmethod
    def calculate_alert_level(glucose_mmol: float) -> str:
        """Map glucose values to simulator alert levels."""
        if glucose_mmol < 3.9:
            return "LOW"
        if glucose_mmol <= 10.0:
            return "NORMAL"
        return "HIGH"

    @staticmethod
    def parse_timestamp(value: str) -> datetime:
        """Parse supported timestamp formats."""
        formats = (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
        )
        for timestamp_format in formats:
            try:
                return datetime.strptime(value, timestamp_format)
            except ValueError:
                continue
        raise ValueError(f"Unsupported timestamp format: {value}")

    @classmethod
    def validate_row(cls, row: dict[str, str], row_num: int) -> list[str]:
        """Validate the fields needed for packet conversion."""
        issues: list[str] = []

        for column in REQUIRED_COLUMNS:
            if not row.get(column):
                issues.append(f"Row {row_num}: missing {column}")

        try:
            glucose = float(row["glucose"])
            if glucose < 20 or glucose > 600:
                issues.append(f"Row {row_num}: glucose {glucose} out of range")
        except (KeyError, ValueError):
            issues.append(f"Row {row_num}: invalid glucose")

        try:
            cls.parse_timestamp(row["timestamp"])
        except (KeyError, ValueError):
            issues.append(f"Row {row_num}: invalid timestamp")

        return issues

    @classmethod
    def convert_to_cgm_packet(cls, row: dict[str, str]) -> dict[str, Any]:
        """Convert a CSV row into a minimal CGM packet."""
        glucose_mmol = cls.mg_dl_to_mmol_l(float(row["glucose"]))
        return {
            "patient_id": row["user_id"],
            "device_id": row["device_id"],
            "glucose_mmol": glucose_mmol,
            "alert_level": cls.calculate_alert_level(glucose_mmol),
        }

    @staticmethod
    def build_basic_eda(glucose_values: list[float], patient_count: int) -> dict[str, Any]:
        """Build a compact EDA summary for the converted dataset."""
        if not glucose_values:
            return {
                "patient_count": patient_count,
                "glucose_mmol": {
                    "count": 0,
                    "min": None,
                    "max": None,
                    "mean": None,
                },
            }

        return {
            "patient_count": patient_count,
            "glucose_mmol": {
                "count": len(glucose_values),
                "min": min(glucose_values),
                "max": max(glucose_values),
                "mean": round(mean(glucose_values), 2),
            },
        }

    @staticmethod
    def build_patient_summary(
        packets_by_patient: dict[str, list[dict[str, Any]]],
    ) -> dict[str, dict[str, Any]]:
        """Build per-patient packet counts and alert distribution."""
        patient_summary: dict[str, dict[str, Any]] = {}

        for patient_id, packets in sorted(packets_by_patient.items()):
            alert_distribution = {level: 0 for level in ALERT_LEVELS}
            for packet in packets:
                alert_distribution[packet["alert_level"]] += 1

            patient_summary[patient_id] = {
                "packet_count": len(packets),
                "alert_distribution": alert_distribution,
            }

        return patient_summary

    def log_summary(self) -> None:
        """Log a concise processing summary."""
        LOGGER.info(
            "Rows: %s total, %s valid, %s skipped",
            self.stats["total_rows"],
            self.stats["valid_rows"],
            self.stats["skipped_rows"],
        )
        LOGGER.info("Patients: %s", self.stats["eda"]["patient_count"])
        LOGGER.info(
            "Columns: %s kept, %s removed",
            self.stats["columns"]["kept"],
            self.stats["columns"]["removed"],
        )

        glucose_stats = self.stats["eda"]["glucose_mmol"]
        LOGGER.info(
            "Glucose mmol/L: count=%s min=%s max=%s mean=%s",
            glucose_stats["count"],
            glucose_stats["min"],
            glucose_stats["max"],
            glucose_stats["mean"],
        )

        LOGGER.info("Alert distribution:")
        for level in ALERT_LEVELS:
            count = self.stats["alert_distribution"][level]
            valid_rows = self.stats["valid_rows"]
            percentage = (count / valid_rows * 100) if valid_rows else 0
            LOGGER.info("  %s: %s (%.2f%%)", level, count, percentage)

        LOGGER.info("Per-patient summary:")
        for patient_id, patient_stats in self.stats["patients"].items():
            distribution = patient_stats["alert_distribution"]
            LOGGER.info(
                "  %s: packets=%s LOW=%s NORMAL=%s HIGH=%s",
                patient_id,
                patient_stats["packet_count"],
                distribution["LOW"],
                distribution["NORMAL"],
                distribution["HIGH"],
            )

        if self.stats["errors"]:
            LOGGER.info("Validation issues: %s", len(self.stats["errors"]))

    def _load_and_process_rows(self) -> None:
        """Read the CSV dataset, validate rows, and convert packets."""
        with open(self.dataset_path, "r", encoding="utf-8") as dataset_file:
            reader = csv.DictReader(dataset_file)
            fieldnames = reader.fieldnames or []
            missing_columns = [column for column in REQUIRED_COLUMNS if column not in fieldnames]
            if missing_columns:
                raise ValueError(f"Missing required columns: {', '.join(missing_columns)}")

            self.stats["columns"] = {
                "total": len(fieldnames),
                "kept": len(REQUIRED_COLUMNS),
                "removed": len(fieldnames) - len(REQUIRED_COLUMNS),
                "kept_names": list(REQUIRED_COLUMNS),
            }

            for row_num, row in enumerate(reader, start=2):
                self.stats["total_rows"] += 1

                issues = self.validate_row(row, row_num)
                if issues:
                    self.stats["errors"].extend(issues)
                    self.stats["skipped_rows"] += 1
                    continue

                packet = self.convert_to_cgm_packet(row)
                sort_timestamp = self.parse_timestamp(row["timestamp"])
                self.packets_by_patient[row["user_id"]].append((sort_timestamp, packet))
                self.stats["alert_distribution"][packet["alert_level"]] += 1
                self.stats["valid_rows"] += 1
                self.glucose_values.append(packet["glucose_mmol"])

    def _write_patient_packets(self) -> None:
        """Write sorted per-patient packet files."""
        for patient_id, packet_entries in self.packets_by_patient.items():
            packet_entries.sort(key=lambda entry: entry[0])
            packets = [packet for _, packet in packet_entries]
            output_file = self.output_dir / f"{patient_id}_packets.json"
            with open(output_file, "w", encoding="utf-8") as output_handle:
                json.dump(packets, output_handle, indent=2)

    def _write_summary(self) -> None:
        """Write the preprocessing summary file."""
        summary_file = self.output_dir / "preprocessing_summary.json"
        with open(summary_file, "w", encoding="utf-8") as summary_handle:
            json.dump(self.stats, summary_handle, indent=2)

    def run(self) -> None:
        """Convert the dataset and write per-patient packet files."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._load_and_process_rows()
            self._write_patient_packets()
            packets_only = {
                patient_id: [packet for _, packet in packet_entries]
                for patient_id, packet_entries in self.packets_by_patient.items()
            }

            self.stats["eda"] = self.build_basic_eda(
                self.glucose_values,
                len(self.packets_by_patient),
            )
            self.stats["patients"] = self.build_patient_summary(packets_only)

            self._write_summary()

            LOGGER.info("Dataset: %s", self.dataset_path)
            LOGGER.info("Output: %s", self.output_dir.resolve())
            self.log_summary()
        except FileNotFoundError:
            LOGGER.error("Dataset not found: %s", self.dataset_path)
        except Exception:
            LOGGER.exception("Preprocessing failed")


def main() -> None:
    """Run the packet preprocessing workflow."""
    CGMPacketPreprocessor().run()


if __name__ == "__main__":
    main()
