"""
Zeek TSV Log Parser.
Reads standard Zeek TSV logs line-by-line, dynamically extracts column headers,
safely converts Zeek's unset/empty markers to Python None, and auto-converts comma-separated lists.
"""

from pathlib import Path
from typing import Any, Dict, Iterator

def parse_zeek_tsv(log_path: Path) -> Iterator[Dict[str, Any]]:
    if not log_path.is_file():
        return

    # Zeek defaults; these may be overridden by the log headers
    separator = "\t"
    set_separator = ","
    unset_field = "-"
    empty_field = "(empty)"
    fields = []
    types = []

    with log_path.open("rt", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            
            # Handle Zeek's metadata headers
            if line.startswith("#"):
                if line.startswith("#separator"):
                    sep_char = line.split(" ")[1]
                    separator = "\t" if sep_char == "\\x09" else sep_char
                elif line.startswith("#set_separator"):
                    set_separator = line.split(separator)[1]
                elif line.startswith("#unset_field"):
                    unset_field = line.split(separator)[1]
                elif line.startswith("#empty_field"):
                    empty_field = line.split(separator)[1]
                elif line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                elif line.startswith("#types"):
                    types = line.split(separator)[1:]
                continue  # Skip metadata lines
            
            # Safety check: if a log has no #fields header, skip the row
            if not fields:
                continue

            # Parse actual log data
            values = line.split(separator)
            record = {}
            
            for col_name, val, col_type in zip(fields, values, types):
                if val == unset_field or val == empty_field:
                    record[col_name] = None
                else:
                    # If Zeek schema declares this column as a set/vector (list), split it
                    if col_type.startswith("set[") or col_type.startswith("vector["):
                        record[col_name] = val.split(set_separator)
                    # Handle Zeek booleans
                    elif col_type == "bool":
                        record[col_name] = True if val == "T" else False
                    else:
                        record[col_name] = val
                        
            yield record