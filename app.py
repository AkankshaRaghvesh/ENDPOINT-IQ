from flask import Flask, render_template
from datetime import datetime, date
import json
import os
import csv
from pathlib import Path

app = Flask(__name__)

# ---- Files (keep these in your Project folder) ----
DATA_FILE = "endpoint_health_final.json"
NIST_CSV = "NIST_SP-800-53_rev5.csv"

# ---- Load NIST catalog once (cached) ----
def load_nist_controls(csv_path: str) -> dict:
    """
    CSV columns confirmed: identifier, name, control_text, discussion, related
    Returns dict: CONTROL_ID -> {id, title, text}
    """
    controls = {}
    path = Path(csv_path)
    if not path.exists():
        return controls

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = (row.get("identifier", "") or "").strip().upper()
            if not cid:
                continue
            controls[cid] = {
                "id": cid,
                "title": (row.get("name", "") or "").strip(),
                "text": (row.get("control_text", "") or "").strip(),
            }
    return controls

NIST_CONTROLS = load_nist_controls(NIST_CSV)

def nist_lookup(control_id: str):
    c = NIST_CONTROLS.get(control_id.upper())
    if not c:
        return ("", "")
    return (c.get("title", ""), c.get("text", ""))


# ---- Map your detected risks -> NIST control IDs (simple but strong MVP) ----
RISK_TO_NIST = {
    "BitLocker encryption is not enabled": ["SC-28", "SC-13"],
    "Microsoft Defender real-time protection is disabled": ["SI-3"],
    "Outdated patches / missing updates": ["SI-2", "RA-5"],
    "Pending system reboot": ["SI-2", "CM-3"],
    "Low disk space on C: drive": ["CM-6"],  # ties to maintaining required configuration/health settings
}


@app.route("/")
def dashboard():
    if (not os.path.exists(DATA_FILE)) or os.path.getsize(DATA_FILE) == 0:
        return "endpoint_health_final.json is missing/empty. Run your PowerShell scripts first.", 400

    with open(DATA_FILE, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    # --- helpers ---
    def clamp(x, lo=0, hi=100):
        try:
            x = float(x)
            return max(lo, min(hi, x))
        except:
            return None

    def parse_int_from_string(s):
        # handles "12", "12 characters", "12 chars"
        try:
            if s is None: return None
            import re
            m = re.search(r"(\d+)", str(s))
            return int(m.group(1)) if m else None
        except:
            return None

    # --- device icon ---
    os_caption = str(data.get("os_caption", "")).lower()
    device_icon = "🖥️"
    if "windows" in os_caption:
        device_icon = "💻"

    # --- patch age ---
    patch_age_days = 0
    try:
        last_patch = str(data.get("last_update_installed_date", "")).split(" ")[0]
        d = datetime.fromisoformat(last_patch).date()
        patch_age_days = (date.today() - d).days
    except:
        patch_age_days = 0

    # --- pull values from JSON (new + existing) ---
    disk_free = clamp(data.get("system_drive_free_percent", 100))
    defender_on = (str(data.get("defender_realtime_protection", "On")).lower() == "on")
    bitlocker_on = bool(data.get("bitlocker_enabled", False))
    pending_reboot = bool(data.get("pending_reboot", False))

    av_sig_age = clamp(data.get("av_signature_age_days", None), 0, 3650)
    cpu_avg = clamp(data.get("cpu_avg_60s", None), 0, 100)
    cpu_max = clamp(data.get("cpu_max_60s", None), 0, 100)
    mem_used = clamp(data.get("memory_used_percent", None), 0, 100)

    batt_health = clamp(data.get("battery_health_percent", None), 0, 100)
    batt_cycles = clamp(data.get("battery_cycle_count", None), 0, 100000)

    smart_health = str(data.get("smart_health", "Not Available"))
    smart_ok = (smart_health.strip().lower() == "ok")

    pwd_min_len_raw = data.get("password_min_length", "Unknown")
    pwd_max_age_raw = data.get("password_max_age", "Unknown")
    pwd_min_len = parse_int_from_string(pwd_min_len_raw)
    pwd_max_age_days = parse_int_from_string(pwd_max_age_raw)  # may be None

    # --- Compliance thresholds (you can tune later) ---
    # (These are standard-ish defaults for demo; adjust per org policy)
    rules = {
        "Disk Free >= 10%": (disk_free is not None and disk_free >= 10),
        "Defender Real-time = On": defender_on,
        "BitLocker Enabled": bitlocker_on,
        "Pending Reboot = False": (pending_reboot is False),
        "Patch Age <= 30 days": (patch_age_days <= 30),
        "AV Signature Age <= 3 days": (av_sig_age is not None and av_sig_age <= 3),
        "Password Min Length >= 12": (pwd_min_len is not None and pwd_min_len >= 12),
        "Password Max Age <= 90 days": (pwd_max_age_days is not None and pwd_max_age_days <= 90),
        "CPU Avg (60s) <= 85%": (cpu_avg is not None and cpu_avg <= 85),
        "Memory Used <= 85%": (mem_used is not None and mem_used <= 85),
        "SMART Health = OK": smart_ok,
        "Battery Health >= 80%": (batt_health is not None and batt_health >= 80),
    }

    # --- Convert raw metrics into 0–100 “scores” (higher is better) ---
    score_disk = clamp(disk_free) if disk_free is not None else None
    score_patch = clamp(100 - min(patch_age_days, 100))
    score_reboot = 100 if not pending_reboot else 0
    score_defender = 100 if defender_on else 0
    score_bitlocker = 100 if bitlocker_on else 0
    score_avsig = clamp(100 - min(av_sig_age or 100, 100))
    score_cpu = clamp(100 - (cpu_avg or 0))
    score_mem = clamp(100 - (mem_used or 0))
    score_smart = 100 if smart_ok else 0
    score_battery = clamp(batt_health) if batt_health is not None else None

    # password score (simple)
    score_pwd_len = 100 if (pwd_min_len is not None and pwd_min_len >= 12) else 0
    score_pwd_age = 100 if (pwd_max_age_days is not None and pwd_max_age_days <= 90) else 0

    # --- Category scores (0–100) ---
    def avg(vals):
        vals = [v for v in vals if v is not None]
        return round(sum(vals)/len(vals), 2) if vals else 0

    cat_security = avg([score_defender, score_bitlocker, score_pwd_len, score_pwd_age])
    cat_patching = avg([score_patch, score_reboot, score_avsig])
    cat_performance = avg([score_cpu, score_mem])
    cat_devicehealth = avg([score_disk, score_smart, score_battery])

    # For donut we show "risk" per category (0–100, higher = riskier)
    donut_security_risk = round(100 - cat_security, 2)
    donut_patching_risk = round(100 - cat_patching, 2)
    donut_perf_risk = round(100 - cat_performance, 2)
    donut_health_risk = round(100 - cat_devicehealth, 2)

    # --- Results table rows (all features) ---
    results_rows = [
        {"feature":"Disk Free (C:)", "value": f"{disk_free}%" if disk_free is not None else "N/A",
         "compliant": rules["Disk Free >= 10%"], "desc":"Disk Free >= 10%"},
        {"feature":"Patch Age", "value": f"{patch_age_days} days", "compliant": rules["Patch Age <= 30 days"], "desc":"Patch Age <= 30 days"},
        {"feature":"Pending Reboot", "value": str(pending_reboot), "compliant": rules["Pending Reboot = False"], "desc":"Pending Reboot = False"},
        {"feature":"Defender Real-time", "value": "On" if defender_on else "Off", "compliant": rules["Defender Real-time = On"], "desc":"Defender Real-time = On"},
        {"feature":"BitLocker", "value": str(bitlocker_on), "compliant": rules["BitLocker Enabled"], "desc":"BitLocker Enabled"},
        {"feature":"AV Signature Age", "value": f"{av_sig_age} days" if av_sig_age is not None else "N/A",
         "compliant": rules["AV Signature Age <= 3 days"], "desc":"AV Signature Age <= 3 days"},
        {"feature":"Password Min Length", "value": str(pwd_min_len_raw), "compliant": rules["Password Min Length >= 12"], "desc":"Password Min Length >= 12"},
        {"feature":"Password Max Age", "value": str(pwd_max_age_raw), "compliant": rules["Password Max Age <= 90 days"], "desc":"Password Max Age <= 90 days"},
        {"feature":"CPU Avg (60s)", "value": f"{cpu_avg}%" if cpu_avg is not None else "N/A", "compliant": rules["CPU Avg (60s) <= 85%"], "desc":"CPU Avg (60s) <= 85%"},
        {"feature":"Memory Used", "value": f"{mem_used}%" if mem_used is not None else "N/A", "compliant": rules["Memory Used <= 85%"], "desc":"Memory Used <= 85%"},
        {"feature":"SMART Health", "value": smart_health, "compliant": rules["SMART Health = OK"], "desc":"SMART Health = OK"},
        {"feature":"Battery Health", "value": f"{batt_health}%" if batt_health is not None else "N/A", "compliant": rules["Battery Health >= 80%"], "desc":"Battery Health >= 80%"},
        {"feature":"Battery Cycle Count", "value": str(batt_cycles) if batt_cycles is not None else "N/A", "compliant": True, "desc":"Informational"},
    ]

    # --- NIST mapping for ALL checks (compliant + non-compliant) ---
    # (Mappings are best-fit and can be tuned; titles/text come from your official CSV)
    CHECK_TO_NIST = {
        "Disk Free >= 10%": ["CM-6"],
        "Patch Age <= 30 days": ["SI-2", "RA-5"],
        "Pending Reboot = False": ["SI-2", "CM-3"],
        "Defender Real-time = On": ["SI-3"],
        "BitLocker Enabled": ["SC-28", "SC-13"],
        "AV Signature Age <= 3 days": ["SI-3"],
        "Password Min Length >= 12": ["IA-5"],
        "Password Max Age <= 90 days": ["IA-5"],
        "CPU Avg (60s) <= 85%": ["SI-11"],
        "Memory Used <= 85%": ["SI-11"],
        "SMART Health = OK": ["SI-7"],
        "Battery Health >= 80%": ["SI-11"],
    }

    # Build NIST compliance table rows for ALL checks
    nist_rows = []
    for row in results_rows:
        check = row["desc"]
        if check not in CHECK_TO_NIST:
            continue
        for cid in CHECK_TO_NIST[check]:
            title, text = nist_lookup(cid)
            nist_rows.append({
                "control_id": cid,
                "title": title if title else "(Not found in CSV)",
                "text": text if text else "(Not found in CSV)",
                "check": check,
                "status": "Compliant" if row["compliant"] else "Not Compliant",
                "evidence": f'{row["feature"]}: {row["value"]}'
            })

    # --- score marker for the colored scale ---
    risk_score = int(data.get("risk_score", 0))
    score_pct = max(0, min(100, risk_score))

    return render_template(
        "dashboard.html",
        data=data,
        device_icon=device_icon,
        patch_age_days=patch_age_days,
        score_pct=score_pct,

        # chart numbers
        donut_values=[donut_security_risk, donut_patching_risk, donut_perf_risk, donut_health_risk],
        bar_labels=["Security", "Patching", "Performance", "Device Health"],
        bar_scores=[cat_security, cat_patching, cat_performance, cat_devicehealth],

        # tables
        results_rows=results_rows,
        nist_rows=nist_rows
    )


if __name__ == "__main__":
    app.run(debug=True)
