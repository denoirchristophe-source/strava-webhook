@app.get("/summary/7d")
def summary_7d():
    ensure_csv_header()
    if not CSV_PATH.exists():
        return jsonify({"error":"no data yet"}), 404

    import pandas as pd  # Render a déjà pandas ? Si non, ajoute-le à requirements.txt
    try:
        df = pd.read_csv(CSV_PATH, parse_dates=["start_date_local"])
    except Exception as e:
        return jsonify({"error": f"failed to read csv: {e}"}), 500

    if df.empty:
        return jsonify({"error":"no rows"}), 404

    now = datetime.now(timezone.utc)
    # Certaines start_date_local sont en chaîne sans tz; on tolère.
    try:
        df["start_date_local"] = pd.to_datetime(df["start_date_local"], utc=True, errors="coerce")
    except Exception:
        pass

    cutoff = now - timedelta(days=7)
    recent = df[df["start_date_local"] >= cutoff]
    if recent.empty:
        return jsonify({"message":"no activities in last 7 days"}), 200

    def safe_sum(col):
        return float(recent[col].fillna(0).sum())

    dist = safe_sum("distance_km")
    movs = safe_sum("moving_time_s")
    elev = safe_sum("elev_gain_m")
    trimp = safe_sum("trimp")

    # répartition par tags (EF/SEUIL/VMA/AS10/AS21/SL/COTES/PISTE)
    def has_tag(s, tag):
        if not isinstance(s, str): return False
        return tag in s.split(",")
    tags = ["EF","SEUIL","VMA","AS10","AS21","SL","COTES","PISTE"]
    counts = {t:int(recent["tags"].apply(lambda s: has_tag(s, t)).sum()) for t in tags}

    # allure moyenne globale (sur l’ensemble)
    pace_s = int(movs / dist) if dist > 0 else None

    payload = {
        "window_days": 7,
        "activities": int(len(recent)),
        "distance_km": round(dist, 2),
        "moving_time_h": round(movs/3600, 2),
        "elev_gain_m": int(elev),
        "trimp_sum": round(trimp, 1),
        "avg_pace": fmt_pace(pace_s) if pace_s else "-",
        "by_tags": counts,
    }
    return jsonify(payload), 200
