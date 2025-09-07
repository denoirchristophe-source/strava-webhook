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

def
