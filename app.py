import os
import hmac
import hashlib
import math
import requests
from collections import deque
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, abort

# =======================
# Configuration (env vars)
# =======================
CLIENT_ID         = os.getenv("STRAVA_CLIENT_ID")
CLIENT_SECRET     = os.getenv("STRAVA_CLIENT_SECRET")
VERIFY_TOKEN      = os.getenv("STRAVA_VERIFY_TOKEN", "verify_me")
ATHLETE_REFRESH   = os.getenv("STRAVA_REFRESH_TOKEN")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")  # optionnel
SKIP_SIG_CHECK    = os.getenv("STRAVA_SKIP_SIGNATURE_CHECK") == "1"

TOKEN_URL    = "https://www.strava.com/oauth/token"
ACTIVITY_URL = "https://www.strava.com/api/v3/activities/{id}"

# =======================
# App & stockage léger
# =======================
app = Flask(__name__)
app.logger.setLevel("INFO")

last_reports = deque(maxlen=50)   # derniers rapports
last_events  = deque(maxlen=50)   # derniers événements webhook bruts

# =======================
# Utils
# =======================
def refresh_access_token():
    """Récupère un access_token valide via refresh_token."""
    if not CLIENT_ID or not CLIENT_SECRET or not ATHLETE_REFRESH:
        app.logger.error("⚠️ STRAVA_CLIENT_ID/SECRET/REFRESH_TOKEN manquent.")
        return None

    resp = requests.post(TOKEN_URL, data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": ATHLETE_REFRESH,
    }, timeout=20)

    if resp.status_code != 200:
        app.logger.error(f"❌ Erreur refresh token: {resp.text}")
        return None

    return resp.json().get("access_token")

def fetch_activity(activity_id):
    """Appelle l’API Strava pour récupérer une activité complète."""
    token = refresh_access_token()
    if not token:
        return None

    resp = requests.get(
        ACTIVITY_URL.format(id=activity_id),
        headers={"Authorization": f"Bearer {token}"},
        params={"include_all_efforts": "false"},
        timeout=20
    )
    if resp.status_code != 200:
        app.logger.error(f"❌ Erreur fetch activité {activity_id}: {resp.text}")
        return None

    return resp.json()

def fmt_pace_min_per_km(distance_km, moving_time_s):
    if not distance_km or distance_km <= 0:
        return None
    pace_min = (moving_time_s / 60.0) / distance_km
    return pace_min

def format_report(activity):
    """Génère un petit rapport textuel pour une activité."""
    if not activity:
        return "❌ Impossible de récupérer l’activité."

    name   = activity.get("name", "Sans titre")
    dist_km = (activity.get("distance", 0) or 0) / 1000.0
    mov_s   = (activity.get("moving_time", 0) or 0)
    elev    = int(activity.get("total_elevation_gain", 0) or 0)
    pace_min = fmt_pace_min_per_km(dist_km, mov_s)

    def pace_str(pm):
        if not pm or pm <= 0:
            return "n/a"
        m = int(pm)
        s = int(round((pm - m) * 60))
        return f"{m}:{s:02d}/km"

    lines = []
    lines.append(f"🏃 **{name}**")
    lines.append(f"Distance : {dist_km:.2f} km")
    lines.append(f"Durée : {mov_s//60:.0f} min {mov_s%60:.0f} s")
    lines.append(f"Dénivelé : {elev} m")
    lines.append(f"Allure moy. : {pace_str(pace_min)}")
    lines.append(f"Date : {activity.get('start_date_local') or activity.get('start_date') or 'n/a'}")

    # HR / cadence si dispo
    avg_hr = activity.get("average_heartrate")
    max_hr = activity.get("max_heartrate")
    if avg_hr:
        lines.append(f"FC moy/max : {int(avg_hr)} / {int(max_hr or 0)} bpm")
    cad = activity.get("average_cadence")
    if cad:
        lines.append(f"Cadence : {round(cad,1)} spm")

    # TRIMP (approx)
    def estimate_trimp(avg_hr, max_hr, dur_min, sex="M"):
        if not avg_hr or not max_hr or not dur_min:
            return None
        hr_ratio = avg_hr / max_hr
        k = 1.67 if sex == "M" else 1.92
        return round(dur_min * hr_ratio * math.exp(k * hr_ratio), 1)

    trimp = estimate_trimp(avg_hr, (max_hr or 190), mov_s/60.0)
    if trimp:
        lines.append(f"TRIMP estimé : {trimp}")

    # commentaire si présent
    desc = activity.get("description")
    if desc:
        lines.append("—")
        lines.append(desc)

    return "\n".join(lines)

def send_slack(report):
    """Envoie le rapport sur Slack (si configuré)."""
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": report}, timeout=10)
        except Exception as e:
            app.logger.error(f"⚠️ Slack error: {e}")

def verify_signature(raw_body: bytes, header_sig: str) -> bool:
    """Vérifie la signature Strava (HMAC-SHA256) — optionnelle (bypass si SKIP_SIG_CHECK)."""
    if SKIP_SIG_CHECK:
        app.logger.warning("Signature SKIPPED (DEV mode)")
        return True
    if not header_sig or not CLIENT_SECRET:
        return False
    sig = header_sig.strip()
    if sig.startswith("sha256="):
        sig = sig.split("=", 1)[1]
    digest = hmac.new(CLIENT_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)

# =======================
# Routes Flask
# =======================

@app.get("/")
def home():
    return "✅ Strava Webhook actif"

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "events_cached": len(last_events),
        "reports_cached": len(last_reports),
        "skip_signature": SKIP_SIG_CHECK,
        "time": datetime.now(timezone.utc).isoformat()
    })

@app.get("/last")
def last_report():
    """Affiche le dernier rapport généré."""
    if not last_reports:
        return "Aucun rapport disponible."
    return f"<pre>{last_reports[-1]}</pre>"

@app.get("/report/<int:activity_id>")
def report_activity(activity_id):
    """Forcer un rapport pour une activité donnée."""
    activity = fetch_activity(activity_id)
    report = format_report(activity)
    # on le mémorise aussi
    last_reports.append(report)
    return f"<pre>{report}</pre>"

@app.get("/events")
def show_events():
    """Liste brute des derniers événements Strava."""
    return jsonify(list(last_events))

@app.get("/summary/7d")
def summary_7d():
    """
    Petit résumé (sans pandas) sur les 7 derniers jours :
    - nb d'activités, km total, D+ total
    """
    token = refresh_access_token()
    if not token:
        abort(500)

    after = int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp())
    resp = requests.get(
        "https://www.strava.com/api/v3/athlete/activities",
        headers={"Authorization": f"Bearer {token}"},
        params={"after": after, "per_page": 200},
        timeout=20
    )
    if resp.status_code != 200:
        abort(resp.status_code)

    activities = resp.json() if isinstance(resp.json(), list) else []
    total_km = sum((a.get("distance") or 0) for a in activities) / 1000.0
    total_dplus = sum((a.get("total_elevation_gain") or 0) for a in activities)
    total_time_s = sum((a.get("moving_time") or 0) for a in activities)

    pace_min = (total_time_s / 60.0) / total_km if total_km > 0 else None
    def pace_str(pm):
        if not pm or pm <= 0:
            return "-"
        m = int(pm)
        s = int(round((pm - m) * 60))
        return f"{m}:{s:02d}/km"

    return jsonify({
        "count": len(activities),
        "total_km": round(total_km, 2),
        "total_dplus": int(total_dplus),
        "moving_time_h": round(total_time_s / 3600.0, 2),
        "avg_pace": pace_str(pace_min)
    })

@app.get("/webhook")
def verify_webhook():
    """Strava envoie GET pour valider l’URL."""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        return jsonify({"hub.challenge": challenge})
    abort(403)

@app.post("/webhook")
def handle_webhook():
    """Réception des events Strava."""
    raw = request.get_data()
    sig = request.headers.get("X-Strava-Signature")
    if not verify_signature(raw, sig):
        app.logger.warning("❌ Signature invalide")
        return abort(401)

    event = request.json or {}
    app.logger.info(f"POST /webhook body={event}")
    last_events.append(event)

    if event.get("object_type") == "activity" and event.get("aspect_type") == "create":
        activity_id = event.get("object_id")
        activity = fetch_activity(activity_id)
        report = format_report(activity)
        last_reports.append(report)
        send_slack(report)
        app.logger.info(f"✅ Rapport généré pour activité {activity_id}")
    else:
        # Note: les modifs de *titre* déclenchent update; la *description* NON.
        app.logger.info("ℹ️ Event ignoré (non activity/create)")

    return jsonify({"status": "ok"})

# =======================
# Entrypoint local (Render utilise gunicorn)
# =======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
