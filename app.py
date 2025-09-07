import os, hmac, hashlib, json, math
import requests
from flask import Flask, request, jsonify, abort

# ---- Config via variables d'environnement (Render) ----
CLIENT_ID       = os.getenv("STRAVA_CLIENT_ID")
CLIENT_SECRET   = os.getenv("STRAVA_CLIENT_SECRET")
VERIFY_TOKEN    = os.getenv("STRAVA_VERIFY_TOKEN", "verify_me")
ATHLETE_REFRESH = os.getenv("STRAVA_REFRESH_TOKEN")
SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL")  # optionnel

TOKEN_URL    = "https://www.strava.com/oauth/token"
ACTIVITY_URL = "https://www.strava.com/api/v3/activities/{id}"

app = Flask(__name__)
app.logger.setLevel("INFO")

def get_access_token(refresh_token: str) -> str:
    r = requests.post(TOKEN_URL, data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }, timeout=20)
    r.raise_for_status()
    data = r.json()
    # Strava peut renvoyer un nouveau refresh_token; non persisté ici.
    return data["access_token"]

def verify_signature(raw_body: bytes, header_sig: str) -> bool:
    """
    Vérifie X-Strava-Signature = HMAC-SHA256(body, CLIENT_SECRET).
    Gère un éventuel préfixe 'sha256=' envoyé par Strava.
    """
    if not header_sig or not CLIENT_SECRET:
        return False
    sig = header_sig.strip()
    if sig.startswith("sha256="):
        sig = sig.split("=", 1)[1]
    digest = hm
