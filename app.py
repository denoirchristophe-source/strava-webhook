import os, hmac, hashlib, json, math, requests
from flask import Flask, request, jsonify, abort

CLIENT_ID       = os.getenv("STRAVA_CLIENT_ID")
CLIENT_SECRET   = os.getenv("STRAVA_CLIENT_SECRET")
VERIFY_TOKEN    = os.getenv("STRAVA_VERIFY_TOKEN", "verify_me")
ATHLETE_REFRESH = os.getenv("STRAVA_REFRESH_TOKEN")
SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL")  # optionnel

TOKEN_URL    = "https://www.strava.com/oauth/token"
ACTIVITY_URL = "https://www.strava.com/api/v3/activities/{id}"

app = Flask(__name__)

def get_access_token(refresh_token: str) -> str:
    r = requests.post(TOKEN_URL, data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }, timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]

def verify_signature(raw_body: bytes, header_sig: str) -> bool:
    if not header_sig:
        return False
    digest = hmac.new(CLIENT_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, header_sig)

def fmt_pace(sec_per_km: float) -> str:
    if not sec_per_km or sec_per_km <= 0: return "-"
    m = int(sec_per_km // 60); s = int(sec_per_km % 60)
    return f"{m}:{s:02d}/km"

def estimate_trimp(avg_hr, max_hr, dur_min, sex="M"):
    if not avg_hr or not max_hr or not dur_min: return None
    hr_ratio = avg_hr/max_hr
    k = 1.67 if sex=="M" else 1.92
    return round(dur_min * hr_ratio * math.exp(k*hr_ratio), 1)

def parse_comment(desc: str):
    info = {"tags":[], "rpe":None, "ressenti":None}
    if not desc: return info
    low = desc.lower()
    for tag in ["#ef","#seuil","#vma","#as10","#as21","#sl","#cotes","#piste"]:
        if tag in low: info["tags"].append(tag[1:].upper())
    import re
    m = re.search(r"rpe\s*([0-9]{1,2})", low)
    if m:
        try: info["rpe"] = int(m.group(1))
        except: pass
    for word in ["excellent","bon","moyen","fatigué","difficile","facile"]:
        if word in low: info["ressenti"] = word; break
    return info

def analyze_activity(a: dict) -> str:
    name = a.get("name")
    dist_km = round((a.get("distance") or 0)/1000, 2)
    mov = a.get("moving_time") or 0
    elev = int(a.get("total_elevation_gain") or 0)
    avg_hr = a.get("average_heartrate")
    max_hr = a.get("max_heartrate")
    cad = a.get("average_cadence")
    desc = a.get("description") or ""
    info = parse_comment(desc)
    pace = (mov/dist_km) if dist_km > 0 else None
    trimp = estimate_trimp(avg_hr, max_hr or 190, mov/60)

    lines = []
    lines.append(f"*{name}*")
    lines.append(f"- Distance : *{dist_km} km* | D+ : *{elev} m*")
    lines.append(f"- Temps : {int(mov//60)}′{int(mov%60):02d} | Allure moy : *{fmt_pace(pace)}*")
    if avg_hr: lines.append(f"- FC moy/max : *{int(avg_hr)} / {int(max_hr or 0)}* bpm")
    if cad: lines.append(f"- Cadence moy : *{round(cad,1)}* spm")
    if trimp: lines.append(f"- TRIMP estimé : *{trimp}*")
    if info["tags"]: lines.append(f"- Tags : {', '.join(info['tags'])}")
    if info["rpe"] is not None: lines.append(f"- RPE : *{info['rpe']}*")
    if info["ressenti"]: lines.append(f"- Ressenti : *{info['ressenti']}*")
    if desc: lines.append(f"- Commentaire : {desc}")
    return "\n".join(lines)

def push_slack(text: str):
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=10)
        except Exception:
            pass

@app.get("/")
def index():
    return "Strava Webhook OK", 200

@app.get("/webhook"
