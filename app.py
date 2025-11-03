#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
import os
from datetime import datetime

LOG_FILE = "security.log"

app = Flask(__name__)

# -----------------------------
# Helper functions
# -----------------------------
def parse_log_for_stats(logpath):
    safe = 0
    corrupted = 0
    last_anom = None
    if not os.path.exists(logpath):
        return safe, corrupted, last_anom

    with open(logpath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "INFO:" in line and "verified OK" in line:
                safe += 1
            elif "WARNING:" in line and "integrity failed" in line:
                corrupted += 1
                ts = line.split(']')[0].strip('[')
                last_anom = ts
            elif "ALERT:" in line:
                corrupted += 1
                ts = line.split(']')[0].strip('[')
                last_anom = ts

    return safe, corrupted, last_anom


def tail_file(path, n=20):
    if not os.path.exists(path):
        return ["(log file not found)"]
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        return lines[-n:]


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    safe, corrupted, last = parse_log_for_stats(LOG_FILE)
    logs = tail_file(LOG_FILE, 20)
    return render_template("index.html", safe_count=safe, corrupted_count=corrupted, last_anomaly=last, logs=logs)

@app.route("/status")
def status():
    safe, corrupted, last = parse_log_for_stats(LOG_FILE)
    return jsonify({"safe": safe, "corrupted": corrupted, "last_anomaly": last})

@app.route("/logs")
def logs():
    lines = tail_file(LOG_FILE, 20)
    return jsonify({"logs": lines})

# -----------------------------
# Main entry
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
