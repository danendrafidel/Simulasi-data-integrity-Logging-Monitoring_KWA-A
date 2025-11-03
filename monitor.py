#!/usr/bin/env python3
import os
import sys
import time
import json
import hashlib
import argparse
from datetime import datetime
import logging
import smtplib
from email.message import EmailMessage

# ---------------------------
# Configuration defaults
# ---------------------------
DEFAULT_DIR = "./secure_files"
HASH_DB = "hash_db.json"
LOG_FILE = "security.log"
HASH_ALGO = "sha256"
DEFAULT_INTERVAL = 5  # seconds

# ---------------------------
# Logging setup (custom format)
# ---------------------------
class SecurityLogger:
    def __init__(self, logfile=LOG_FILE):
        self.logfile = logfile
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            fh = logging.FileHandler(logfile)
            fh.setLevel(logging.DEBUG)
            fmt = logging.Formatter("%(message)s")
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)

            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)
            ch.setFormatter(fmt)
            self.logger.addHandler(ch)

    def _ts(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def info(self, message, filename=None):
        if filename:
            msg = f"[{self._ts()}] INFO: File {filename} {message}"
        else:
            msg = f"[{self._ts()}] INFO: {message}"
        self.logger.info(msg)

    def warning(self, message, filename=None):
        if filename:
            msg = f"[{self._ts()}] WARNING: File {filename} {message}"
        else:
            msg = f"[{self._ts()}] WARNING: {message}"
        self.logger.warning(msg)

    def alert(self, message, filename=None):
        if filename:
            msg = f"[{self._ts()}] ALERT: File {filename} {message}"
        else:
            msg = f"[{self._ts()}] ALERT: {message}"
        self.logger.critical(msg)
        print(msg)

# ---------------------------
# Hash helpers
# ---------------------------
def hash_file(path, algo=HASH_ALGO):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------
# SMTP helper (optional)
# ---------------------------
def send_email(smtp_cfg, subject, body, to_addr):
    if not smtp_cfg or not smtp_cfg.get("enabled"):
        print(f"[SIMULATED EMAIL] To: {to_addr}, Subject: {subject}\n{body}\n")
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_cfg.get("from_addr")
        msg["To"] = to_addr
        msg.set_content(body)

        if smtp_cfg.get("use_tls", True):
            server = smtplib.SMTP(smtp_cfg["host"], smtp_cfg.get("port", 587))
            server.starttls()
            server.login(smtp_cfg["username"], smtp_cfg["password"])
        else:
            server = smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg.get("port", 465))
            server.login(smtp_cfg["username"], smtp_cfg["password"])

        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

# ---------------------------
# Hash DB handling
# ---------------------------
def load_hash_db(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_hash_db(path, db):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

# ---------------------------
# Monitoring logic
# ---------------------------
def scan_directory(dirpath):
    files = {}
    for root, dirs, filenames in os.walk(dirpath):
        for fn in filenames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, dirpath)
            files[rel] = {
                "path": full,
                "mtime": os.path.getmtime(full),
                "size": os.path.getsize(full)
            }
    return files

def perform_check(dirpath, hash_db_path, logger, smtp_cfg=None, auto_update=False):
    if not os.path.isdir(dirpath):
        raise FileNotFoundError(f"Directory {dirpath} not found")

    current = scan_directory(dirpath)
    db = load_hash_db(hash_db_path)

    safe = 0
    corrupted = 0
    last_anomaly = None

    # New file
    for rel, meta in current.items():
        if rel not in db:
            logger.alert("detected as unknown.", filename=rel)
            last_anomaly = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current_hash = hash_file(meta["path"])
            if auto_update:
                db[rel] = {"hash": current_hash, "mtime": meta["mtime"], "size": meta["size"]}
                logger.info("added to baseline (auto-update).", filename=rel)

    # Deleted file
    deleted = [f for f in db.keys() if f not in current]
    for f in deleted:
        logger.alert("deleted from monitored folder.", filename=f)
        last_anomaly = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if auto_update:
            db.pop(f, None)
            logger.info("removed from baseline (auto-update).", filename=f)

    # Modified file
    for rel, meta in current.items():
        if rel in db:
            try:
                cur_h = hash_file(meta["path"])
            except Exception as e:
                logger.alert(f"could not be read: {e}", filename=rel)
                last_anomaly = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                corrupted += 1
                continue

            baseline_h = db[rel].get("hash")
            if cur_h == baseline_h:
                logger.info("verified OK.", filename=rel)
                safe += 1
            else:
                logger.warning("integrity failed!", filename=rel)
                last_anomaly = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                corrupted += 1
                subject = f"[ALERT] Integrity failed: {rel}"
                body = f"File {rel} changed.\nBaseline hash: {baseline_h}\nCurrent hash: {cur_h}"
                print(f"[SIMULATED ALERT] {subject}\n{body}\n")
                send_email(smtp_cfg or {}, subject, body, smtp_cfg.get("to_addr") if smtp_cfg else "admin@example.com")
                if auto_update:
                    db[rel]["hash"] = cur_h
                    db[rel]["mtime"] = meta["mtime"]
                    db[rel]["size"] = meta["size"]
                    logger.info("baseline updated after modification (auto-update).", filename=rel)

    save_hash_db(hash_db_path, db)
    return safe, corrupted, last_anomaly

# ---------------------------
# CLI & main
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Simple File Integrity Monitor (polling daemon).")
    p.add_argument("--dir", default=DEFAULT_DIR, help="Directory to monitor")
    p.add_argument("--hash-db", default=HASH_DB, help="Path to hash DB (json)")
    p.add_argument("--log", default=LOG_FILE, help="Path to security log")
    p.add_argument("--watch", action="store_true", help="Run as watcher (daemon) with interval")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Polling interval in seconds")
    p.add_argument("--auto-update", action="store_true", help="Automatically update baseline on add/delete/mod")
    p.add_argument("--smtp-config", default=None, help="Path to SMTP config JSON (optional)")
    return p.parse_args()

def main():
    args = parse_args()
    monitor_dir = args.dir
    hash_db_path = args.hash_db
    logger = SecurityLogger(logfile=args.log)

    if not os.path.exists(hash_db_path):
        logger.info("Baseline DB not found. Creating new baseline from current files.")
        files = scan_directory(monitor_dir)
        db = {}
        for rel, meta in files.items():
            try:
                db[rel] = {
                    "hash": hash_file(meta["path"]),
                    "mtime": meta["mtime"],
                    "size": meta["size"]
                }
                logger.info("added to baseline.", filename=rel)
            except Exception as e:
                logger.warning(f"failed to hash during baseline creation: {e}", filename=rel)
        save_hash_db(hash_db_path, db)

    smtp_cfg = None
    if args.smtp_config:
        if os.path.exists(args.smtp_config):
            with open(args.smtp_config, "r", encoding="utf-8") as f:
                smtp_cfg = json.load(f)
        else:
            logger.warning("SMTP config file not found, email alerts will be simulated.")

    if not args.watch:
        try:
            safe, corrupted, last = perform_check(monitor_dir, hash_db_path, logger, smtp_cfg=smtp_cfg, auto_update=args.auto_update)
            print(f"Done. Safe: {safe}, Corrupted: {corrupted}, Last anomaly: {last}")
        except Exception as e:
            print("Error:", e)
            sys.exit(1)
    else:
        logger.info(f"Starting watcher on {monitor_dir}, interval {args.interval}s.")
        try:
            while True:
                try:
                    safe, corrupted, last = perform_check(monitor_dir, hash_db_path, logger, smtp_cfg=smtp_cfg, auto_update=args.auto_update)
                except Exception as e:
                    logger.alert(f"Watcher error: {e}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Watcher stopped by user. Exiting.")

if __name__ == "__main__":
    main()
