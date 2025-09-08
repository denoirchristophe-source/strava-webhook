import os
import hmac
import hashlib
import math
import json
import csv
import requests
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
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

LAST_REPORT = None                               # cache mémoire du dernier rapport
EVENT_LOG   = deque(maxlen=20)                   # derniers 20 événements reçus

DATA_DIR = Path("/mnt/data")                     # persistance Render (éphémère mais survive aux requêtes)
DATA_DIR.mkdir(parents=True, exist_ok=True)
CSV_PATH = DATA_DIR / "history.csv"


# =======================
# Utilitaires généraux
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
    """
    Vérifie X-Strava-Signature = HMAC-SHA256(body, CLIENT_SECRET).
    Si STRAVA_SKIP_SIGNATURE_CHECK=1, bypass (mode DEV).
    """
    if os.getenv("STRAVA_SKIP_SIGNATURE_CHECK") == "1":
        app.logger.warning("Skipping signature check (DEV mode).")
        return True

    if not header_sig or not CLIENT_SECRET:
        return False

    sig = header_sig.strip()
    if sig.startswith("sha256="):  # tolère le préfixe éventuel
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
    trimp = estimate_trimp(avg_hr, (max_hr or 190), mov / 60)

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
# Utilitaires CSV/historique
# =======================
def ensure_csv_header():
    if not CSV_PATH.exists():
        with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "activity_id","start_date_local","name","distance_km","moving_time_s",
                "elev_gain_m","avg_hr","max_hr","cadence_spm","pace_s_per_km",
                "pace","trimp","tags","rpe","ressenti"
            ])


def append_activity_row(act: dict, report_text: str):
    """Ajoute une ligne dans history.csv pour l’activité."""
    ensure_csv_header()
    act_id   = act.get("id")
    name     = act.get("name") or ""
    dist_km  = round((act.get("distance") or 0) / 1000, 3)
    mov_s    = int(act.get("moving_time") or 0)
    elev_m   = int(act.get("total_elevation_gain") or 0)
    avg_hr   = act.get("average_heartrate")
    max_hr   = act.get("max_heartrate")
    cad      = act.get("average_cadence")
    startloc = act.get("start_date_local") or act.get("start_date")
    pace_s   = int(mov_s / dist_km) if dist_km > 0 else None

    info = parse_comment(act.get("description") or "")
    tags = ",".join(info["tags"]) if info["tags"] else ""
    rpe  = info["rpe"]
    res  = info["ressenti"]

    with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            act_id, startloc, name, dist_km, mov_s,
            elev_m, avg_hr, max_hr, (round(cad,1) if cad else None), pace_s,
            fmt_pace(pace_s if pace_s else 0),
            estimate_trimp(avg_hr, (max_hr or 190), mov_s/60),
            tags, rpe, res
        ])


def parse_dt_any(s: str):
    """Parse ISO date; gère 'Z' en UTC."""
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")
        except Exception:
            return None


# =======================
# Routes
# =======================
@app.get("/")
def index():
    return "Strava Webhook OK", 200


@app.get("/webhook")
def webhook_verify():
    """
    Validation Strava:
    GET /webhook?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    app.logger.info(f"GET /webhook verify: mode={mode}, token={token}, challenge={challenge}")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        return jsonify({"hub.challenge": challenge})
    return abort(403)


@app.post("/webhook")
def webhook_event():
    # Logs bruts
    app.logger.info(f"POST /webhook headers={dict(request.headers)}")
    body_text = request.get_data(as_text=True)
    app.logger.info(f"POST /webhook body={body_text}")

    # Journalise (debug)
    try:
        EVENT_LOG.append({
            "headers": dict(request.headers),
            "body": request.get_json(silent=True) or body_text,
        })
    except Exception:
        pass

    # Signature HMAC
    sig = request.headers.get("X-Strava-Signature")
    raw = request.get_data()
    if not verify_signature(raw, sig):
        app.logger.warning("POST /webhook signature invalid -> 401")
        return abort(401)

    event = request.json or {}
    app.logger.info(
        f"Parsed event: object_type={event.get('object_type')} "
        f"aspect_type={event.get('aspect_type')} "
        f"object_id={event.get('object_id')} "
        f"owner_id={event.get('owner_id')} "
        f"updates={event.get('updates')}"
    )

    # On traite create/update d'activités
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
            a = r.json()
            report = analyze_activity(a)
            app.logger.info(f"Activity {act_id} processed. Report length={len(report)}")

            # Cache + fichier
            global LAST_REPORT
            LAST_REPORT = report
            try:
                with open("last_activity_report.md", "w", encoding="utf-8") as f:
                    f.write(report)
                app.logger.info("last_activity_report.md written.")
            except Exception as e:
                app.logger.warning(f"Could not write last_activity_report.md: {e}")

            # Historique CSV
            try:
                append_activity_row(a, report)
                app.logger.info("history.csv updated.")
            except Exception as e:
                app.logger.warning(f"Could not append history.csv: {e}")

            push_slack(f":runner: Nouvelle activité #{act_id}\n{report}")
        except Exception as e:
            app.logger.exception(f"Error while processing activity {act_id}: {e}")
            push_slack(f":warning: Erreur activité {act_id}: {e}")
            return jsonify({"status": "error", "message": str(e)}), 200
    else:
        app.logger.info(f"Event ignored (not create/update on activity): {event}")

    return jsonify({"status": "ok"}), 200


@app.get("/report/<int:activity_id>")
def report_activity(activity_id: int):
    """Génère un rapport à la demande pour une activité précise."""
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

        # Historique CSV même sur demande (utile si manqué au webhook)
        try:
            append_activity_row(a, report)
        except Exception:
            pass

        return report, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as e:
        app.logger.exception(f"Error generating report for {activity_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.get("/health")
def health():
    present = {
        "STRAVA_CLIENT_ID": bool(CLIENT_ID),
        "STRAVA_CLIENT_SECRET": bool(CLIENT_SECRET),
        "STRAVA_REFRESH_TOKEN": bool(ATHLETE_REFRESH),
        "STRAVA_VERIFY_TOKEN": bool(VERIFY_TOKEN),
        "SKIP_SIGNATURE": (os.getenv("STRAVA_SKIP_SIGNATURE_CHECK") == "1"),
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


# ======= DEBUG =======
@app.get("/debug/events")
def debug_events():
    try:
        lines = []
        for i, e in enumerate(list(EVENT_LOG)[-20:], 1):
            body = e.get("body")
            if isinstance(body, (dict, list)):
                body_txt = json.dumps(body, ensure_ascii=False)
            else:
                body_txt = str(body)
            lines.append(
                f"#{i}: headers-keys={list(e.get('headers', {}).keys())}\n"
                f"body={body_txt}\n"
            )
        return "\n".join(lines) or "Aucun événement reçu.", 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as ex:
        return f"Erreur debug_events: {ex}", 500, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/debug/force/<int:activity_id>")
def debug_force(activity_id: int):
    """Force l'analyse d'une activité (utile si Strava n'a pas envoyé d'update)."""
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

        # historise aussi
        try:
            append_activity_row(a, report)
        except Exception:
            pass

        return report, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as ex:
        app.logger.exception(f"debug_force error for {activity_id}: {ex}")
        return jsonify({"status": "error", "message": str(ex)}), 500


# ======= EXPORT / SUMMARY =======
@app.get("/export.csv")
def export_csv():
    ensure_csv_header()
    try:
        with CSV_PATH.open("r", encoding="utf-8") as f:
            data = f.read()
        headers = {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": 'attachment; filename="history.csv"',
        }
        return data, 200, headers
    except Exception as e:
        return f"Erreur lecture CSV: {e}", 500, {"Content-Type":"text/plain; charset=utf-8"}


@app.get("/summary/7d")
def summary_7d():
    ensure_csv_header()
    if not CSV_PATH.exists():
        return jsonify({"error": "no data yet"}), 404

    rows = []
    try:
        with CSV_PATH.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
    except Exception as e:
        return jsonify({"error": f"failed to read csv: {e}"}), 500

    if not rows:
        return jsonify({"error": "no rows"}), 404

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=7)

    # Fitre sur 7j, somme des métriques
    def to_float(x):
        try:
            return float(x)
        except Exception:
            return 0.0

    def to_int(x):
        try:
            return int(float(x))
        except Exception:
            return 0

    recent = []
    for r in rows:
        dt = parse_dt_any(r.get("start_date_local"))
        if dt is None:
            continue
        # si pas tz, considère UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt >= cutoff:
            recent.append(r)

    if not recent:
        return jsonify({"message": "no activities in last 7 days"}), 200

    dist = sum(to_float(r.get("distance_km")) for r in recent)
    movs = sum(to_int(r.get("moving_time_s")) for r in recent)
    elev = sum(to_float(r.get("elev_gain_m")) for r in recent)
    trmp = sum(to_float(r.get("trimp")) for r in recent)

    # répartition par tags
    tags_list = ["EF","SEUIL","VMA","AS10","AS21","SL","COTES","PISTE"]
    counts = {t: 0 for t in tags_list}
    for r in recent:
        tags = (r.get("tags") or "")
        tagset = {t.strip() for t in tags.split(",") if t.strip()}
        for t in tags_list:
            if t in tagset:
                counts[t] += 1

    pace_s = int(movs / dist) if dist > 0 else None
    payload = {
        "window_days": 7,
        "activities": len(recent),
        "distance_km": round(dist, 2),
        "moving_time_h": round(movs/3600, 2),
        "elev_gain_m": int(round(elev)),
        "trimp_sum": round(trmp, 1),
        "avg_pace": fmt_pace(pace_s) if pace_s else "-",
        "by_tags": counts,
    }
    return jsonify(payload), 200
