from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

# Paths
ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "output" / "analysis_results.csv"
JSON_PATH = ROOT / "output" / "analysis_results.json"

# Column names (legacy support kept for older files)
MITRE_COL = "mitre_techniques_virtual"
MITRE_COL_LEGACY = "mitre_techniques"
MITRE_DERIVED = "mitre_techniques"  # new derived column name replacing mitre_technique_new
MITRE_DERIVED_OLD = "mitre_technique_new"

# ---------------------------------------------------
# 1. RULES: Mapping Behaviors → MITRE Techniques
# ---------------------------------------------------

VT_TECHNIQUE_SPLIT = lambda s: {t.strip() for t in s.split(",") if t.strip()}

# Inference based on behavior counts
COUNT_MAPPING_RULES = {
    "processes_count": [(lambda v: v > 0, "T1106")],  # Native API execution
    "files_written_count": [(lambda v: v > 0, "T1105")],  # Ingress tool transfer
    "files_deleted_count": [(lambda v: v > 0, "T1070.004")],  # Indicator removal: File Deletion
    "registry_keys_set_count": [(lambda v: v > 0, "T1112")],  # Modify registry
    "dns_lookups_count": [(lambda v: v > 0, "T1071.004")],  # DNS
    "ip_connections_count": [(lambda v: v > 0, "T1071")],  # C2 over network
    "http_requests_count": [(lambda v: v > 0, "T1071.001")],  # C2 over HTTP
}

# Inference from process names (EXPANDED for Execution, Persistence, and Transfer)
PROCESS_RULES = {
    r"regsvr32\.exe": "T1218.011",
    r"svchost\.exe": "T1569.002",
    r"wmi(adap|prvse)\.exe": "T1047",
    r"\.ocx": "T1574.002",
    r"\.dll": "T1574.002",
    r"powershell\.exe": "T1059.001",  # Command and Scripting Interpreter: PowerShell
    r"cmd\.exe": "T1059.003",         # Command and Scripting Interpreter: Windows Command Shell
    r"schtasks\.exe": "T1053.005",    # Scheduled Task/Job (Persistence)
    r"bitsadmin\.exe": "T1197",       # BITS Jobs (Lateral Tool Transfer/Download)
}

# Inference from signatures (EXPANDED for Process Injection, Discovery, and Evasion)
SIGNATURE_RULES = {
    "encode data using xor": "T1027.002",
    "encode data using base64": "T1027.001",
    "peb access": "T1055",
    "authenticate hmac": "T1573",
    "enumerate pe sections": "T1518.001",
    "parse pe exports": "T1055.003",
    "write process memory": "T1055",             # Process Injection
    "create remote thread": "T1055.003",         # Specific Process Injection technique
    "create service": "T1543.003",               # Service Creation (Persistence)
    "enumerate running processes": "T1057",      # Process Discovery
    "clear event logs": "T1070.001",             # Indicator Removal: Clear Host Logs
    "accesses system info": "T1082",             # System Information Discovery
    "enumerates files and directories": "T1083", # File and Directory Discovery
}

# Inference from registry paths (EXPANDED for Persistence)
REGISTRY_RULES = {
    r"systemcertificates": "T1553",  # Subvert trust
    r"browser helper objects": "T1082",  # Discovery
    r"\\\\.dll": "T1012",  # Query registry
    r"\\\\.ocx": "T1012",
    r"currentversion\\run": "T1547.001",         # Registry Run Keys / Startup Folder (Persistence)
    r"currentversion\\runonce": "T1547.001",     # Registry Run Keys / Startup Folder (Persistence)
}

# Inference from file operations
FILE_RULES = {
    r"zone.identifier": "T1564.004", # Hide Artifacts: Zone Identifier Deletion
    r"\\\\loader": "T1036",
}

# ---------------------------------------------------
# 2. HELPER FUNCTIONS (No change needed)
# ---------------------------------------------------

def _add_if_match(text, rules, technique_set):
    if not isinstance(text, str) or not text.strip():
        return
    text_l = text.lower()
    for pattern, tid in rules.items():
        if re.search(pattern, text_l):
            technique_set.add(tid)


def _apply_count_rules(row, technique_set):
    for column, rules in COUNT_MAPPING_RULES.items():
        value = row.get(column, 0) or 0
        try:
            value = float(value)
        except Exception:
            value = 0
        for condition, tid in rules:
            if condition(value):
                technique_set.add(tid)


def _extract_vt_techniques(row):
    mitre_field = row.get(MITRE_COL) if MITRE_COL in row else row.get(MITRE_COL_LEGACY)
    if isinstance(mitre_field, str) and mitre_field.strip():
        return VT_TECHNIQUE_SPLIT(mitre_field)
    return set()


def map_techniques_from_row(row):
    techniques = set()

    # 1. MITRE techniques directly from VirusTotal
    techniques.update(_extract_vt_techniques(row))

    # 2. Count-based inference
    _apply_count_rules(row, techniques)

    # 3. Process details (includes new interpreter rules)
    _add_if_match(row.get("process_details", ""), PROCESS_RULES, techniques)

    # 4. Signature matches (includes new process injection/discovery/evasion rules)
    _add_if_match(row.get("signature_matches", ""), SIGNATURE_RULES, techniques)

    # 5. Registry written/read (includes new persistence rules)
    _add_if_match(row.get("registry_written", ""), REGISTRY_RULES, techniques)
    _add_if_match(row.get("registry_read", ""), REGISTRY_RULES, techniques)

    # 6. File operations
    _add_if_match(row.get("files_written", ""), FILE_RULES, techniques)
    _add_if_match(row.get("files_deleted", ""), FILE_RULES, techniques)

    return sorted(techniques)


def add_mitre_technique_new(df):
    # Drop legacy derived column if present; we'll recreate under the new name
    if MITRE_DERIVED_OLD in df.columns and MITRE_DERIVED not in df.columns:
        df = df.drop(columns=[MITRE_DERIVED_OLD])

    df[MITRE_DERIVED] = (
        df.apply(map_techniques_from_row, axis=1)
        .apply(lambda items: ", ".join(items))
    )

    # Place the new column immediately after the MITRE techniques column
    anchor_col = MITRE_COL if MITRE_COL in df.columns else MITRE_COL_LEGACY
    if anchor_col in df.columns:
        cols = list(df.columns)
        # Ensure only one derived column
        if MITRE_DERIVED in cols:
            cols.remove(MITRE_DERIVED)
        insert_at = cols.index(anchor_col) + 1
        cols = cols[:insert_at] + [MITRE_DERIVED] + cols[insert_at:]
        df = df[cols]
    return df


def main():
    # NOTE: Ensure analysis_results.csv is in the correct path relative to the script execution.
    try:
        df = pd.read_csv(CSV_PATH)
    except FileNotFoundError:
        print(f"Error: Could not find the file at {CSV_PATH}. Please check your file path.")
        return

    # Rename legacy column to the new name if needed
    if MITRE_COL not in df.columns and MITRE_COL_LEGACY in df.columns:
        df = df.rename(columns={MITRE_COL_LEGACY: MITRE_COL})

    df = add_mitre_technique_new(df)

    # Ensure the output directory exists
    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    df.to_csv(CSV_PATH, index=False)
    df.to_json(JSON_PATH, orient="records", indent=2)
    print(f"Updated {CSV_PATH} and {JSON_PATH} with mitre_technique_new")


if __name__ == "__main__":
    main()
