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

TOKEN_URL    = "https://www.strava.com/oauth/token"
ACTIVITY_URL = "https://www.strava.com/api/v3/activities/{id}"

# =======================
# App & stockage léger
# =======================
app = Flask(__name__)
app.logger.setLevel("INFO")

# Stockage mémoire (on garde les 50 derniers rapports et événements bruts)
last_reports = deque(maxlen=50)
last_events  = deque(maxlen=50)

# =======================
# Utils
# =======================
def refresh_access_token():
    """Récupère un access_token valide via refresh_token"""
    if not CLIENT_ID or not CLIENT_SECRET or not ATHLETE_REFRESH:
        app.logger.error("⚠️ STRAVA_CLIENT_ID/SECRET/REFRESH_TOKEN manquent.")
        return None

    resp = requests.post(TOKEN_URL, data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": ATHLETE_REFRESH,
    })

    if resp.status_code != 200:
        app.logger.error(f"❌ Erreur refresh token: {resp.text}")
        return None

    return resp.json().get("access_token")

def fetch_activity(activity_id):
    """Appelle l’API Strava pour récupérer une activité complète"""
    token = refresh_access_token()
    if not token:
        return None

    resp = requests.get(
        ACTIVITY_URL.format(id=activity_id),
        headers={"Authorization": f"Bearer {token}"}
    )
    if resp.status_code != 200:
        app.logger.error(f"❌ Erreur fetch activité {activity_id}: {resp.text}")
        return None

    return resp.json()

def format_report(activity):
    """Génère un petit rapport textuel pour une activité"""
    if not activity:
        return "❌ Impossible de récupérer l’activité."

    name   = activity.get("name", "Sans titre")
    dist   = activity.get("distance", 0) / 1000
    moving = activity.get("moving_time", 0) / 60
    elev   = activity.get("total_elevation_gain", 0)
    pace   = (moving / dist) if dist > 0 else 0

    report = [
        f"🏃 **{name}**",
        f"Distance : {dist:.2f} km",
        f"Durée : {moving:.0f} min",
        f"Dénivelé : {elev:.0f} m",
        f"Allure moy. : {pace:.2f} min/km" if pace else "Allure : n/a",
        f"Date : {activity.get('start_date_local', 'n/a')}"
    ]
    return "\n".join(report)

def send_slack(report):
    """Envoie le rapport sur Slack (si configuré)"""
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": report})
        except Exception as e:
            app.logger.error(f"⚠️ Slack error: {e}")

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
        "time": datetime.now(timezone.utc).isoformat()
    })

@app.get("/last")
def last_report():
    """Affiche le dernier rapport généré"""
    if not last_reports:
        return "Aucun rapport disponible."
    return f"<pre>{last_reports[-1]}</pre>"

@app.get("/report/<int:activity_id>")
def report_activity(activity_id):
    """Forcer un rapport pour une activité donnée"""
    activity = fetch_activity(activity_id)
    report = format_report(activity)
    return f"<pre>{report}</pre>"

@app.get("/events")
def show_events():
    """Liste brute des derniers événements Strava"""
    return jsonify(list(last_events))

@app.get("/summary/7d")
def summary_7d():
    """Petit résumé sur les 7 derniers jours"""
    token = refresh_access_token()
    if not token:
        abort(500)

    after = int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp())
    resp = requests.get(
        "https://www.strava.com/api/v3/athlete/activities",
        headers={"Authorization": f"Bearer {token}"},
        params={"after": after, "per_page": 100}
    )
    if resp.status_code != 200:
        abort(resp.status_code)

    activities = resp.json()
    total_km = sum(a.get("distance", 0) for a in activities) / 1000
    total_dplus = sum(a.get("total_elevation_gain", 0) for a in activities)
    return jsonify({
        "count": len(activities),
        "total_km": round(total_km, 2),
        "total_dplus": int(total_dplus)
    })

@app.get("/webhook")
def verify_webhook():
    """Strava envoie GET pour valider l’URL"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return jsonify({"hub.challenge": challenge})
    abort(403)

@app.post("/webhook")
def handle_webhook():
    """Réception des events Strava"""
    event = request.json
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
        app.logger.info("ℹ️ Event ignoré (non activity/create)")

    return jsonify({"status": "ok"})

# =======================
# Entrypoint Render
# =======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
