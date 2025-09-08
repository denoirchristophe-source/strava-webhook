import os
import hmac
import hashlib
import math
import requests
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

app = Flask(__name__)
app.logger.setLevel("INFO")

# Cache mémoire du dernier rapport
LAST_REPORT = None


# =======================
# Utilitaires
# =======================
def get_access_token(refresh_token: str) -> str:
    r = requests.post(
        TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        timeout=20,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def verify_signature(raw_body: bytes, header_sig: str) -> bool:
    """Vérifie X-Strava-Signature = HMAC-SHA256(body, CLIENT_SECRET)."""
    if SKIP_SIG_CHECK:
        app.logger.warning("Skipping signature check (DEV mode).")
        return True
    if not header_sig or not CLIENT_SECRET:
        return False
    sig = header_sig.strip()
    if sig.startswith("sha256="):  # tolère le préfixe
        sig = sig.split("=", 1)[1]
    digest = hmac.new(CLIENT_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)


def fmt_pace(sec_per_km: float) -> str:
    if not sec_per_km or sec_per_km <= 0:
        return "-"
    m = int(sec_per_km // 60)
    s = int(sec_per_km % 60)
    return f"{m}:{s:02d}/km"


def estimate_trimp(avg_hr, max_hr, dur_min, sex="M"):
    if not avg_hr or not max_hr or not dur_min:
        return None
    hr_ratio = avg_hr / max_hr
    k = 1.67 if sex == "M" else 1.92
    return round(dur_min * hr_ratio * math.exp(k * hr_ratio), 1)


def parse_comment(desc: str):
    info = {"tags": [], "rpe": None, "ressenti": None}
    if not desc:
        return info
    low = desc.lower()
    for tag in ["#ef", "#seuil", "#vma", "#as10", "#as21", "#sl", "#cotes", "#piste"]:
        if tag in low:
            info["tags"].append(tag[1:].upper())
    import re
    m = re.search(r"rpe\s*([0-9]{1,2})", low)
    if m:
        try:
            info["rpe"] = int(m.group(1))
        except Exception:
            pass
    for word in ["excellent", "bon", "moyen", "fatigué", "difficile", "facile"]:
        if word in low:
            info["ressenti"] = word
            break
    return info


def analyze_activity(a: dict) -> str:
    name = a.get("name")
    dist_km = round((a.get("distance") or 0) / 1000, 2)
    mov = a.get("moving_time") or 0
    elev = int(a.get("total_elevation_gain") or 0)
    avg_hr = a.get("average_heartrate")
    max_hr = a.get("max_heartrate")
    cad = a.get("average_cadence")
    desc = a.get("description") or ""
    info = parse_comment(desc)
    pace = (mov / dist_km) if dist_km > 0 else None
    trimp = estimate_trimp(avg_hr, max_hr or 190, mov / 60)

    lines = []
    lines.append(f"*{name}*")
    lines.append(f"- Distance : *{dist_km} km* | D+ : *{elev} m*")
    lines.append(f"- Temps : {int(mov // 60)}′{int(mov % 60):02d} | Allure moy : *{fmt_pace(pace)}*")
    if avg_hr:
        lines.append(f"- FC moy/max : *{int(avg_hr)} / {int(max_hr or 0)}* bpm")
    if cad:
        lines.append(f"- Cadence moy : *{round(cad, 1)}* spm")
    if trimp:
        lines.append(f"- TRIMP estimé : *{trimp}*")
    if info["tags"]:
        lines.append(f"- Tags : {', '.join(info['tags'])}")
    if info["rpe"] is not None:
        lines.append(f"- RPE : *{info['rpe']}*")
    if info["ressenti"]:
        lines.append(f"- Ressenti : *{info['ressenti']}*")
    if desc:
        lines.append(f"- Commentaire : {desc}")
    return "\n".join(lines)


def push_slack(text: str):
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)
        except Exception:
            pass


# =======================
# Routes
# =======================
@app.get("/")
def index():
    return "Strava Webhook OK", 200


@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    app.logger.info(f"GET /webhook verify: mode={mode}, token={token}, challenge={challenge}")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        return jsonify({"hub.challenge": challenge})
    return abort(403)


@app.post("/webhook")
def webhook_event():
    # Logs d'entrée
    app.logger.info(f"POST /webhook headers={dict(request.headers)}")
    app.logger.info(f"POST /webhook body={request.get_data(as_text=True)}")

    # Signature
    sig = request.headers.get("X-Strava-Signature")
    raw = request.get_data()
    if not verify_signature(raw, sig):
        app.logger.warning("POST /webhook signature invalid -> 401")
        return abort(401)

    event = request.json or {}
    # {"object_type":"activity","object_id":123,"aspect_type":"create"|"update"|"delete"}
    if event.get("object_type") == "activity" and event.get("aspect_type") in ("create", "update"):
        act_id = event.get("object_id")
        try:
            access = get_access_token(ATHLETE_REFRESH)
            r = requests.get(
                ACTIVITY_URL.format(id=act_id),
                headers={"Authorization": f"Bearer {access}"},
                params={"include_all_efforts": "false"},
                timeout=20,
            )
            r.raise_for_status()
            report = analyze_activity(r.json())
            app.logger.info(f"Activity {act_id} processed. Report length={len(report)}")

            # Cache mémoire + best-effort fichier
            global LAST_REPORT
            LAST_REPORT = report
            try:
                with open("last_activity_report.md", "w", encoding="utf-8") as f:
                    f.write(report)
                app.logger.info("last_activity_report.md written.")
            except Exception as e:
                app.logger.warning(f"Could not write last_activity_report.md: {e}")

            push_slack(f":runner: Nouvelle activité #{act_id}\n{report}")
        except Exception as e:
            app.logger.exception(f"Error while processing activity {act_id}: {e}")
            push_slack(f":warning: Erreur activité {act_id}: {e}")
            return jsonify({"status": "error", "message": str(e)}), 200

    return jsonify({"status": "ok"}), 200


@app.get("/report/<int:activity_id>")
def report_activity(activity_id: int):
    try:
        access = get_access_token(ATHLETE_REFRESH)
        r = requests.get(
            ACTIVITY_URL.format(id=activity_id),
            headers={"Authorization": f"Bearer {access}"},
            params={"include_all_efforts": "false"},
            timeout=20,
        )
        r.raise_for_status()
        a = r.json()
        report = analyze_activity(a)

        global LAST_REPORT
        LAST_REPORT = report
        try:
            with open("last_activity_report.md", "w", encoding="utf-8") as f:
                f.write(report)
        except Exception:
            pass

        return report, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as e:
        app.logger.exception(f"Error generating report for {activity_id}: {e}")
        return jsonify({"status":"error", "message": str(e)}), 500


@app.get("/health")
def health():
    present = {
        "STRAVA_CLIENT_ID": bool(CLIENT_ID),
        "STRAVA_CLIENT_SECRET": bool(CLIENT_SECRET),
        "STRAVA_REFRESH_TOKEN": bool(ATHLETE_REFRESH),
        "STRAVA_VERIFY_TOKEN": bool(VERIFY_TOKEN),
        "SKIP_SIGNATURE": SKIP_SIG_CHECK,
    }
    return jsonify({"ok": True, "env_present": present}), 200


@app.get("/last")
def last_report():
    if LAST_REPORT:
        return LAST_REPORT, 200, {"Content-Type": "text/plain; charset=utf-8"}
    try:
        with open("last_activity_report.md", "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except FileNotFoundError:
        return "Pas encore de rapport (fais une activité ou édite une description).", 404
