"""
Zeek TSV Log Parser.

Reads standard Zeek TSV logs line-by-line, dynamically extracts column headers,
and yields each log entry as a Python dictionary.
"""

from pathlib import Path
from typing import Any, Dict, Iterator


def parse_zeek_tsv(log_path: Path) -> Iterator[Dict[str, Any]]:
    """
    Reads a Zeek TSV log file and yields one dictionary per log entry.
    Dynamically maps values to column names defined in the #fields header.
    
    Args:
        log_path: The path to the Zeek .log file.
        
    Yields:
        A dictionary mapping column names to their string values (or None if unset).
    """
    if not log_path.is_file():
        return

    # Zeek defaults; these may be overridden by the log headers
    separator = "\t"
    unset_field = "-"
    fields = []

    with log_path.open("rt", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            
            # Handle Zeek's metadata headers
            if line.startswith("#"):
                if line.startswith("#separator"):
                    # Format: #separator \x09
                    sep_char = line.split(" ")[1]
                    # Convert the literal string "\x09" to an actual tab character
                    if sep_char == "\\x09":
                        separator = "\t"
                    else:
                        separator = sep_char
                
                elif line.startswith("#unset_field"):
                    # Format: #unset_field   -
                    unset_field = line.split(separator)[1]
                
                elif line.startswith("#fields"):
                    # Format: #fields   ts  uid  id.orig_h
                    # We slice [1:] to skip the actual "#fields" word
                    fields = line.split(separator)[1:]
                
                continue  # Skip to the next line, do not parse metadata as data
            
            # Safety check: if a log has no #fields header, skip the row
            if not fields:
                continue

            # Parse actual log data
            values = line.split(separator)
            record = {}
            
            for col_name, val in zip(fields, values):
                if val == unset_field:
                    record[col_name] = None
                else:
                    record[col_name] = val
                    
            yield record