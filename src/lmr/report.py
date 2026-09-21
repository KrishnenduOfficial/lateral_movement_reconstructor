"""
Report generation module.

Exports in-memory DetectionFinding objects to standard, machine-readable
formats (JSON and CSV) for SIEM ingestion and analyst review.
"""

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import List

from lmr.schema import DetectionFinding


def export_findings(findings: List[DetectionFinding], out_dir: Path) -> None:
    """
    Writes detection findings to findings.json and findings.csv inside the output directory.
    """
    if not findings:
        return

    json_path = out_dir / "findings.json"
    csv_path = out_dir / "findings.csv"

    # Convert dataclasses to standard Python dictionaries
    findings_dicts = [asdict(f) for f in findings]

    # 1. Export JSON (Machine-readable for SIEMs/SOAR)
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(findings_dicts, f, indent=4)

    # 2. Export CSV (Human-readable for Excel / Timeline Explorer)
    if findings_dicts:
        # Extract the column headers from the keys of the first finding
        headers = list(findings_dicts[0].keys())
        
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for row in findings_dicts:
                # Convert lists (like evidence_uids) to strings so they fit in a CSV cell
                csv_row = {
                    k: (",".join(v) if isinstance(v, list) else v) 
                    for k, v in row.items()
                }
                writer.writerow(csv_row)