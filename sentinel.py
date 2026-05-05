"""
sentinel.py
A system-wide security file monitor that watches for suspicious activity,
tracks file change frequency, saves structured event data, sends desktop
alerts, and generates a summary report on exit.
"""

import time
import os
import csv
import sqlite3
import threading
import platform
import subprocess
import smtplib
import re
from datetime import datetime
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# -- Configuration -------------------------------------------------------------

class Config:
    """
    Central configuration for Sentinel.
    Modify these values to customize behavior.
    """

    LOG_FILE        = "sentinel_events.log"
    CSV_FILE        = "sentinel_events.csv"
    DB_FILE         = "sentinel.db"
    REPORT_FILE     = "sentinel_report.txt"
    FREQ_THRESHOLD  = 20

    SENSITIVE_EXTENSIONS = {
        ".env", ".pem", ".key", ".p12", ".pfx", ".cert", ".cer",
        ".ssh", ".gpg", ".kdb", ".kdbx", ".shadow", ".passwd",
        ".db", ".py", ".sh", ".bash", ".ps1", ".bat", ".cmd",
        ".exe", ".dll", ".so", ".dylib",
    }

    RANSOMWARE_EXTENSIONS = {
        ".locked", ".encrypted", ".crypted", ".crypt", ".enc",
        ".ransom", ".wnry", ".wcry", ".wncry", ".zepto",
        ".locky", ".cerber", ".aaa", ".abc", ".xyz", ".zzz",
    }

    SUSPICIOUS_PATHS = [
        r"[\\/]\.ssh[\\/]",
        r"[\\/](passwd|shadow|sudoers)",
        r"startup|autorun|crontab",
    ]

    EMAIL_ENABLED   = False
    EMAIL_FROM      = ""
    EMAIL_TO        = ""
    EMAIL_PASSWORD  = ""
    EMAIL_SMTP      = "smtp.gmail.com"
    EMAIL_PORT      = 587

    @staticmethod
    def get_watch_dirs():
        system = platform.system()
        home = os.path.expanduser("~")
        dirs = [home]
        if system == "Windows":
            dirs += [
                os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu"),
                "C:\\Windows\\System32\\drivers\\etc",
            ]
        elif system == "Darwin": # macOS
            dirs += [
                "/Library/LaunchDaemons", "/Library/LaunchAgents",
                os.path.join(home, "Library", "LaunchAgents"),
            ]
        elif system == "Linux":
            dirs += ["/etc", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", 
                     "/etc/cron.monthly", "/var", "/var/log", "/var/log/syslog", "/bin", "/usr/bin", "/usr/local/bin", "/sbin"]
        return [d for d in dirs if os.path.exists(d)]


# -- Data Storage --------------------------------------------------------------

class DataStore:
    """
    Handles all persistent storage: SQLite database and CSV file.
    Creates the schema on first run and provides insert methods.
    """

    def __init__(self, db_path: str, csv_path: str):
        self.db_path  = db_path
        self.csv_path = csv_path
        self._lock    = threading.Lock()
        self._init_db()
        self._init_csv()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    path        TEXT NOT NULL,
                    dest_path   TEXT,
                    is_dir      INTEGER NOT NULL,
                    severity    TEXT NOT NULL,
                    reason      TEXT,
                    line_count  INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS frequency (
                    path        TEXT PRIMARY KEY,
                    count       INTEGER DEFAULT 0,
                    last_seen   TEXT
                )
            """)

    def _init_csv(self):
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "event_type", "path", "dest_path",
                    "is_dir", "severity", "reason", "line_count"
                ])

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def insert_event(self, timestamp, event_type, path, dest_path,
                     is_dir, severity, reason, line_count=None):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO events
                    (timestamp, event_type, path, dest_path, is_dir, severity, reason, line_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, event_type, path, dest_path,
                      int(is_dir), severity, reason, line_count))
                conn.execute("""
                    INSERT INTO frequency (path, count, last_seen)
                    VALUES (?, 1, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        count = count + 1,
                        last_seen = excluded.last_seen
                """, (path, timestamp))
            with open(self.csv_path, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp, event_type, path, dest_path or "",
                    is_dir, severity, reason or "", line_count or ""
                ])

    def get_top_changed(self, limit=10):
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT path, count, last_seen FROM frequency
                ORDER BY count DESC LIMIT ?
            """, (limit,)).fetchall()
        return rows

    def get_summary_counts(self):
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) FROM events GROUP BY severity"
            ).fetchall()
            by_type = conn.execute(
                "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
            ).fetchall()
        return total, dict(by_severity), dict(by_type)

    def purge_self_entries(self, ignored_names: set, ignored_patterns: tuple = ()):
        """
        Remove events and frequency entries for Sentinel's own output files,
        cookie/cache noise, and directory-only MODIFIED rows. Called on startup
        to clean data recorded before the ignore list was in place.
        """
        with self._lock:
            with self._get_conn() as conn:
                for name in ignored_names:
                    like = "%/" + name
                    conn.execute("DELETE FROM events WHERE path LIKE ? OR path = ?", (like, name))
                    conn.execute("DELETE FROM frequency WHERE path LIKE ? OR path = ?", (like, name))
                for pattern in ignored_patterns:
                    like = "%/" + pattern + "%"
                    conn.execute("DELETE FROM events WHERE path LIKE ?", (like,))
                    conn.execute("DELETE FROM frequency WHERE path LIKE ?", (like,))
                conn.execute(
                    "DELETE FROM frequency WHERE path NOT LIKE '%.%' AND path NOT GLOB '*/.*'"
                )
                conn.execute(
                    "DELETE FROM events WHERE is_dir = 1 AND event_type = 'MODIFIED'"
                )


# -- Alert System --------------------------------------------------------------

class AlertManager:
    """
    Sends desktop notifications and optional email alerts for high-severity events.
    """

    def __init__(self, config: Config):
        self.config  = config
        self.system  = platform.system()
        self._lock   = threading.Lock()

    def notify(self, title: str, message: str, severity: str):
        if severity in ("HIGH", "CRITICAL"):
            threading.Thread(
                target=self._desktop_notify, args=(title, message), daemon=True
            ).start()
            if self.config.EMAIL_ENABLED:
                threading.Thread(
                    target=self._email_notify, args=(title, message), daemon=True
                ).start()

    def _desktop_notify(self, title: str, message: str):
        try:
            if self.system == "Windows":
                ps = (
                    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
                    "ContentType = WindowsRuntime] | Out-Null; "
                    "$template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02; "
                    "$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template); "
                    '$xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("{}")) | Out-Null; '
                    '$xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("{}")) | Out-Null; '
                    "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
                    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Sentinel').Show($toast);"
                ).format(title, message)
                subprocess.run(
                    ["powershell", "-Command", ps],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                    )
            elif self.system == "Linux":
                subprocess.run(["notify-send", title, message], check=False)
            elif self.system == "Darwin": # macOS
                script = 'display notification "{}" with title "{}"'.format(message, title)
                subprocess.run(["osascript", "-e", script], check=False)
        except Exception as e:
            print("[AlertManager] Desktop notify failed: {}".format(e))

    def _email_notify(self, title: str, message: str):
        try:
            with smtplib.SMTP(self.config.EMAIL_SMTP, self.config.EMAIL_PORT) as smtp:
                smtp.starttls()
                smtp.login(self.config.EMAIL_FROM, self.config.EMAIL_PASSWORD)
                body = "Subject: [Sentinel Alert] {}\n\n{}".format(title, message)
                smtp.sendmail(self.config.EMAIL_FROM, self.config.EMAIL_TO, body)
        except Exception as e:
            print("[AlertManager] Email notify failed: {}".format(e))


# -- Threat Analyzer -----------------------------------------------------------

class ThreatAnalyzer:
    """
    Analyzes file events and assigns a severity level and reason.
    Returns (severity, reason) where severity is one of:
        INFO | LOW | MEDIUM | HIGH | CRITICAL
    """

    def __init__(self, config: Config):
        self.config       = config
        self._freq_window = defaultdict(list)
        self._lock        = threading.Lock()

    def analyze(self, path: str, event_type: str, dest_path: str = None) -> tuple:
        reasons    = []
        severity   = "INFO"
        check_path = dest_path if dest_path else path
        ext        = os.path.splitext(check_path)[1].lower()
        basename   = os.path.basename(check_path).lower()

        if ext in self.config.RANSOMWARE_EXTENSIONS:
            reasons.append("Ransomware-associated extension '{}'".format(ext))
            severity = self._escalate(severity, "CRITICAL")
        elif ext in self.config.SENSITIVE_EXTENSIONS:
            reasons.append("Sensitive file type '{}'".format(ext))
            severity = self._escalate(severity, "HIGH")

        for pattern in self.config.SUSPICIOUS_PATHS:
            if re.search(pattern, check_path, re.IGNORECASE):
                reasons.append("Suspicious path pattern matched: '{}'".format(pattern))
                severity = self._escalate(severity, "MEDIUM")
                break

        if basename.startswith(".") and event_type in ("CREATED", "MODIFIED"):
            reasons.append("Hidden file activity")
            severity = self._escalate(severity, "MEDIUM")

        if event_type == "DELETED":
            severity = self._escalate(severity, "LOW")
            reasons.append("File deleted")

        # Only track frequency for files, not directories
        if not os.path.isdir(path):
            freq_hit, freq_count = self._check_frequency(path)
            if freq_hit:
                reasons.append("High change frequency: {} changes/min".format(freq_count))
                severity = self._escalate(severity, "HIGH")

        return severity, ("; ".join(reasons) if reasons else None)

    def _check_frequency(self, path: str) -> tuple:
        now = time.time()
        with self._lock:
            self._freq_window[path].append(now)
            self._freq_window[path] = [
                t for t in self._freq_window[path] if now - t < 60
            ]
            count = len(self._freq_window[path])
        return count >= self.config.FREQ_THRESHOLD, count

    @staticmethod
    def _escalate(current: str, proposed: str) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return proposed if order.index(proposed) > order.index(current) else current


# -- Logger --------------------------------------------------------------------

class EventLogger:
    """
    Handles formatted console output and plain-text log file writing.
    Color-codes output by severity level.
    """

    COLORS = {
        "INFO":     "\033[37m",
        "LOW":      "\033[36m",
        "MEDIUM":   "\033[33m",
        "HIGH":     "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET":    "\033[0m",
    }

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._lock    = threading.Lock()

    def log(self, message: str, severity: str = "INFO"):
        color   = self.COLORS.get(severity, "")
        reset   = self.COLORS["RESET"]
        colored = "{}{}{}".format(color, message, reset)
        with self._lock:
            print(colored)
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(message + "\n")
            except Exception as e:
                print("[EventLogger] Write failed: {}".format(e))


# -- File Handler --------------------------------------------------------------

class SentinelHandler(FileSystemEventHandler):
    """
    Watchdog event handler. Dispatches events to the analyzer, logger,
    data store, and alert manager.
    """

    def __init__(self, logger: EventLogger, store: DataStore,
                 analyzer: ThreatAnalyzer, alerts: AlertManager):
        self.logger   = logger
        self.store    = store
        self.analyzer = analyzer
        self.alerts   = alerts

    def on_created(self, event):  self._handle(event, "CREATED")
    def on_modified(self, event): self._handle(event, "MODIFIED")
    def on_deleted(self, event):  self._handle(event, "DELETED")
    def on_moved(self, event):    self._handle(event, "MOVED", dest_path=event.dest_path)

    # Sentinel's own output files

    _IGNORED_NAMES = {
        os.path.basename(Config.LOG_FILE),
        os.path.basename(Config.CSV_FILE),
        os.path.basename(Config.DB_FILE),
        os.path.basename(Config.DB_FILE) + "-journal",
        os.path.basename(Config.DB_FILE) + "-wal",
        os.path.basename(Config.DB_FILE) + "-shm",
        os.path.basename(Config.REPORT_FILE),
    }

    _IGNORED_PATTERNS = (
        "cookies",          # Firefox: cookies.sqlite, Chrome: Cookies
        "cookies.sqlite",   # WAL/journal/shm siblings
        "cache2",           # Firefox cache
        "places.sqlite",    # Firefox history/bookmarks
        "webappsstore",     # Firefox web storage
        "favicons.sqlite",  # Firefox favicons
        "sessionstore",     # Firefox session store 
        "renderer_js.log",  # Discord renderer log
        "serverlist.json",  # VPN server list
        "state.vscdb",      # VS Code state database
        "state.vscdb-journal", # VS Code state database journal
        "scope_v3.json",    # Discord scope file
        "sqlite-wal",       # SQLite write-ahead log
        ".sqlite-journal",  # SQLite journal file
        "__psscriptpolicytest_", # PowerShell script policy test files
        "psscriptpolicytest", # PowerShell script policy test files
        "startupprofiledata-noninteractive",   # PowerShell internal file
        "LOG.old",          # Common log rotation pattern
        "LOG",
        "chrome-extension", # Chrome extension data
        "chrome-extension_", # Chrome extension data
        "flatpak",          # Flatpak application data
        "flatpak-cache",    # Flatpak cache
        ".tmp",             # Temporary files
    )

    def _is_ignored(self, path: str) -> bool:
        """Return True if this path should be silently skipped."""
        name = os.path.basename(path).lower()
        if name in self._IGNORED_NAMES:
            return True
        for pattern in self._IGNORED_PATTERNS:
            if (name == pattern
                    or name.startswith(pattern + ".")
                    or name.startswith(pattern + "-")
                    or pattern in name):
                return True
        return False

    def _handle(self, event, event_type: str, dest_path: str = None):

        if event.is_directory and event_type == "MODIFIED":
            return

        if self._is_ignored(event.src_path):
            return

        timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        path       = event.src_path
        is_dir     = event.is_directory
        item_label = "DIR " if is_dir else "FILE"

        severity, reason = self.analyzer.analyze(path, event_type, dest_path)

        if dest_path:
            msg = "[{}] [{:<8}] [{}] {}: {} -> {}".format(
                timestamp, severity, event_type, item_label, path, dest_path)
        else:
            msg = "[{}] [{:<8}] [{}] {}: {}".format(
                timestamp, severity, event_type, item_label, path)

        if reason:
            msg += "\n            \u26a0  {}".format(reason)

        self.logger.log(msg, severity)
        self.store.insert_event(timestamp, event_type, path, dest_path,
                                is_dir, severity, reason)

        if severity in ("HIGH", "CRITICAL"):
            self.alerts.notify(
                "Sentinel: {} \u2014 {}".format(severity, event_type),
                "{}\n{}".format(path, reason or ""),
                severity
            )

        if not is_dir:
            check = dest_path if dest_path else path
            if check.endswith((".txt", ".log", ".md", ".csv")):
                if event_type in ("MODIFIED", "MOVED"):
                    threading.Thread(
                        target=self._count_lines,
                        args=(check, timestamp, severity),
                        daemon=True
                    ).start()
                elif event_type == "CREATED":
                    threading.Thread(
                        target=self._delayed_count,
                        args=(check, timestamp, severity),
                        daemon=True
                    ).start()

    def _count_lines(self, path: str, timestamp: str, severity: str):
        try:
            prev_size = -1
            for _ in range(10):
                time.sleep(0.1)
                try:
                    curr_size = os.path.getsize(path)
                except FileNotFoundError:
                    return
                if curr_size == prev_size:
                    break
                prev_size = curr_size
            with open(path, "r", errors="replace") as f:
                line_count = sum(1 for _ in f)
            self.logger.log(
                "            \u2192 Lines in file: {}".format(line_count), severity)
        except Exception as e:
            self.logger.log(
                "            \u2192 Could not read file: {}".format(e), "LOW")

    def _delayed_count(self, path: str, timestamp: str, severity: str):
        prev_size = -1
        for _ in range(20):
            time.sleep(0.1)
            try:
                curr_size = os.path.getsize(path)
            except FileNotFoundError:
                return
            if curr_size == prev_size and curr_size > 0:
                break
            prev_size = curr_size
        self._count_lines(path, timestamp, severity)


# -- Report Generator ----------------------------------------------------------

class ReportGenerator:
    """
    Generates a human-readable summary report from the data store on exit.
    """

    def __init__(self, store: DataStore, report_path: str):
        self.store       = store
        self.report_path = report_path

    def generate(self, watch_dirs: list, start_time: datetime):
        elapsed            = datetime.now() - start_time
        total, by_sev, by_type = self.store.get_summary_counts()
        top_files          = self.store.get_top_changed(10)

        lines = [
            "=" * 64,
            "  SENTINEL \u2014 SECURITY MONITOR REPORT",
            "=" * 64,
            "  Generated : {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "  Session   : {}".format(str(elapsed).split(".")[0]),
            "  Watching  : {} director{}".format(
                len(watch_dirs), "y" if len(watch_dirs) == 1 else "ies"),
            "",
            "  Watched Directories:",
        ]
        for d in watch_dirs:
            lines.append("    \u2022 {}".format(d))

        lines += [
            "", "-" * 64,
            "  Total Events : {}".format(total),
            "", "  By Severity:",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = by_sev.get(sev, 0)
            bar   = "\u2588" * min(count, 40)
            lines.append("    {:<10} {:>5}  {}".format(sev, count, bar))

        lines += ["", "  By Event Type:"]
        for etype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append("    {:<12} {:>5}".format(etype, count))

        lines += [
            "", "-" * 64,
            "  Top 10 Most Frequently Changed Files:",
        ]
        if top_files:
            for i, (path, count, last_seen) in enumerate(top_files, 1):
                lines.append("  {:>2}. [{:>4}x]  {}".format(i, count, path))
                lines.append("        Last seen: {}".format(last_seen))
        else:
            lines.append("    No data.")

        lines += [
            "", "=" * 64,
            "  Data saved to:",
            "    Log  : {}".format(Config.LOG_FILE),
            "    CSV  : {}".format(Config.CSV_FILE),
            "    DB   : {}".format(Config.DB_FILE),
            "=" * 64,
        ]

        report = "\n".join(lines)
        print("\n" + report)
        try:
            with open(self.report_path, "w", encoding="utf-8") as f: 
                f.write(report + "\n")
            print("\n  Report saved to: {}".format(self.report_path))
        except Exception as e:
            print("  Could not save report: {}".format(e))


# -- Terminal Dashboard --------------------------------------------------------

class Dashboard:
    """
    Interactive terminal dashboard shown before monitoring begins.
    Lets the user configure watch directories, adjust thresholds,
    toggle email alerts, and choose what to monitor.
    """

    C = {
        "reset":   "\033[0m",
        "bold":    "\033[1m",
        "dim":     "\033[2m",
        "magenta": "\033[35m",
        "cyan":    "\033[36m",
        "yellow":  "\033[33m",
        "red":     "\033[31m",
        "green":   "\033[32m",
        "white":   "\033[97m",
        "gray":    "\033[90m",
    }

    BANNER = r"""
     _____ _______ __   __ ________ _______ __   __ _______ __
    / ____|  _____|  \ |  |__    __|__   __|  \ |  |  _____|  |
   | (___ | |___  |   \|  |  |  |     | |  |   \|  | |___  |  |
    \___ \|  ___| |  . `  |  |  |     | |  |  . `  |  ___| |  |
    ____) | |_____|  |\   |  |  |   __| |__|  |\   | |_____|  |____
   |_____/|_______|__| \__|  |__|  |_______|__| \__|_______|_______|
    """

    def __init__(self, config: Config):
        self.config     = config
        self.watch_dirs = list(config.get_watch_dirs())
        self.custom_dirs: list = []

    def _c(self, color: str, text: str) -> str:
        return "{}{}{}".format(self.C.get(color, ""), text, self.C["reset"])

    def _clear(self):
        os.system("cls" if platform.system() == "Windows" else "clear")

    def _rule(self, char="\u2500", width=64):
        print(self._c("gray", char * width))

    def _header(self, subtitle: str = ""):
        self._clear()
        print(self._c("magenta", self.BANNER))
        print(self._c("gray", "  System Security File Monitor".center(64)))
        if subtitle:
            print(self._c("cyan", "  {}".format(subtitle).center(64)))
        print()
        self._rule()
        print()

    def _menu_item(self, key: str, label: str, value: str = "", dim: bool = False):
        k   = self._c("cyan",                     "  [{}]".format(key))
        lbl = self._c("dim" if dim else "white",   "  {}".format(label))
        val = self._c("yellow", "  {}".format(value)) if value else ""
        print("{}{}{}".format(k, lbl, val))

    def _input(self, prompt: str) -> str:
        return input(self._c("cyan", "\n  > {}: ".format(prompt))).strip()

    # -- Screens ---------------------------------------------------------------

    def main_menu(self) -> bool:
        """Main loop. Returns True to start monitoring, False to quit."""
        while True:
            self._header("Configuration Dashboard")
            self._status_bar()
            print()
            self._rule()
            print()
            print(self._c("gray", "  Configure\n"))
            self._menu_item("1", "Manage watch directories")
            self._menu_item("2", "Threat sensitivity")
            self._menu_item("3", "Email alerts",
                            "enabled" if self.config.EMAIL_ENABLED else "disabled")
            self._menu_item("4", "File types & extensions")
            print()
            self._rule()
            print()
            print(self._c("gray", "  Actions\n"))
            self._menu_item("5", "Start monitoring")
            self._menu_item("6", "Preview system info")
            self._menu_item("7", "Quit")
            print()
            self._rule()

            choice = self._input("Select option").upper()
            if   choice == "1": self._screen_directories()
            elif choice == "2": self._screen_sensitivity()
            elif choice == "3": self._screen_email()
            elif choice == "4": self._screen_extensions()
            elif choice == "5": return True
            elif choice == "6": self._screen_preview()
            elif choice == "7": return False

    def _status_bar(self):
        items = [
            ("platform",       platform.system()),
            ("watching",       "{} dir{}".format(
                len(self.watch_dirs), "s" if len(self.watch_dirs) != 1 else "")),
            ("freq threshold", "{}/min".format(self.config.FREQ_THRESHOLD)),
            ("email alerts",   "on" if self.config.EMAIL_ENABLED else "off"),
        ]
        print("  " + "   ".join(
            "{} {}".format(self._c("gray", k + ":"), self._c("yellow", v))
            for k, v in items
        ))

    def _screen_directories(self):
        while True:
            self._header("Watch Directories")
            for i, d in enumerate(self.watch_dirs, 1):
                exists = os.path.exists(d)
                icon   = self._c("green", "\u2713") if exists else self._c("red", "\u2717")
                print("  {}  {} {}".format(icon, self._c("white", str(i) + "."), d))
            print()
            self._rule()
            print()
            self._menu_item("1", "Add directory")
            self._menu_item("2", "Remove directory")
            self._menu_item("3", "Restore system defaults")
            self._menu_item("4", "Back")
            print()
            self._rule()

            choice = self._input("Select option").upper()

            if choice == "1":
                path = self._input("Enter full directory path")
                if os.path.isdir(path):
                    if path not in self.watch_dirs:
                        self.watch_dirs.append(path)
                        print(self._c("green", "\n  Added: {}".format(path)))
                    else:
                        print(self._c("yellow", "\n  Already in list."))
                else:
                    print(self._c("red", "\n  Path does not exist or is not a directory."))

            elif choice == "2":
                if not self.watch_dirs:
                    print(self._c("red", "\n  No directories to remove."))
                    continue
                idx = self._input("Enter number to remove")
                try:
                    removed = self.watch_dirs.pop(int(idx) - 1)
                    print(self._c("yellow", "\n  Removed: {}".format(removed)))
                except (ValueError, IndexError):
                    print(self._c("red", "\n  Invalid selection."))

            elif choice == "3":
                self.watch_dirs = list(self.config.get_watch_dirs())
                print(self._c("green", "\n  Restored system defaults."))

            elif choice == "4":
                break

    def _screen_sensitivity(self):
        while True:
            self._header("Threat Sensitivity")
            print("  Current threshold: {}".format(
                self._c("yellow", "{} changes/min".format(self.config.FREQ_THRESHOLD))))
            print()
            print(self._c("gray",
                "  A file that changes more than this many times per minute\n"
                "  within a watched directory will trigger a HIGH alert.\n"
                "  Lower = more sensitive. Recommended: 3-10."
            ))
            print()
            self._menu_item("1", "Low sensitivity    (threshold: 30)")
            self._menu_item("2", "Medium sensitivity (threshold: 20) ", "recommended")
            self._menu_item("3", "High sensitivity   (threshold: 10)")
            self._menu_item("4", "Custom value")
            self._menu_item("5", "Back")
            print()
            self._rule()

            choice = self._input("Select option")
            mapping = {"1": 30, "2": 20, "3": 10}

            if choice in mapping:
                self.config.FREQ_THRESHOLD = mapping[choice]
            elif choice == "4":
                val = self._input("Enter custom threshold (integer)")
                try:
                    self.config.FREQ_THRESHOLD = max(1, int(val))
                except ValueError:
                    pass
            elif choice == "5":
                break

    def _screen_email(self):
        while True:
            self._header("Email Alerts")
            status = (self._c("green", "ENABLED")
                      if self.config.EMAIL_ENABLED
                      else self._c("red", "DISABLED"))
            print("  Status: {}".format(status))
            print()

            if self.config.EMAIL_ENABLED:
                print("  From : {}".format(
                    self._c("yellow", self.config.EMAIL_FROM or "(not set)")))
                print("  To   : {}".format(
                    self._c("yellow", self.config.EMAIL_TO or "(not set)")))
                print("  SMTP : {}:{}".format(
                    self._c("yellow", self.config.EMAIL_SMTP), self.config.EMAIL_PORT))
                print()

            print(self._c("gray",
                "  Alerts are sent via SMTP for HIGH and CRITICAL events.\n"
                "  For Gmail, use an App Password (not your account password).\n"
                "  See: myaccount.google.com/apppasswords"
            ))
            print()
            self._menu_item("1", "Toggle email alerts on/off")
            self._menu_item("2", "Configure SMTP settings")
            self._menu_item("3", "Back")
            print()
            self._rule()

            choice = self._input("Select option")

            if choice == "1":
                self.config.EMAIL_ENABLED = not self.config.EMAIL_ENABLED

            elif choice == "2":
                print()
                self.config.EMAIL_FROM = (
                    self._input("From email address") or self.config.EMAIL_FROM)
                self.config.EMAIL_TO = (
                    self._input("To email address") or self.config.EMAIL_TO)
                self.config.EMAIL_PASSWORD = (
                    self._input("App password") or self.config.EMAIL_PASSWORD)
                smtp = self._input("SMTP server [{}]".format(self.config.EMAIL_SMTP))
                if smtp:
                    self.config.EMAIL_SMTP = smtp
                port = self._input("SMTP port [{}]".format(self.config.EMAIL_PORT))
                if port.isdigit():
                    self.config.EMAIL_PORT = int(port)

            elif choice == "3":
                break

    def _screen_extensions(self):
        while True:
            self._header("File Types & Extensions")

            def fmt_set(s):
                return "  " + "  ".join(self._c("yellow", ext) for ext in sorted(s))

            print(self._c("white", "  CRITICAL \u2014 Ransomware extensions:"))
            print(fmt_set(self.config.RANSOMWARE_EXTENSIONS))
            print()
            print(self._c("white", "  HIGH \u2014 Sensitive extensions:"))
            print(fmt_set(self.config.SENSITIVE_EXTENSIONS))
            print()
            self._rule()
            print()
            self._menu_item("1", "Add extension to sensitive list")
            self._menu_item("2", "Remove extension from sensitive list")
            self._menu_item("3", "Back")
            print()
            self._rule()

            choice = self._input("Select option")

            if choice == "1":
                ext = self._input("Enter extension (e.g. .cfg)")
                if not ext.startswith("."):
                    ext = "." + ext
                self.config.SENSITIVE_EXTENSIONS.add(ext.lower())

            elif choice == "2":
                ext = self._input("Enter extension to remove")
                if not ext.startswith("."):
                    ext = "." + ext
                self.config.SENSITIVE_EXTENSIONS.discard(ext.lower())

            elif choice == "3":
                break

    def _screen_preview(self):
        while True:
            self._header("System Preview")
            print("  OS         : {} {} ({})".format(
                platform.system(), platform.release(), platform.machine()))
            print("  Python     : {}".format(platform.python_version()))
            print("  Home       : {}".format(os.path.expanduser("~")))
            print()
            print(self._c("white", "  Directories that will be watched:"))
            for d in self.watch_dirs:
                exists = os.path.exists(d)
                color  = "green" if exists else "red"
                label  = "exists" if exists else "not found"
                print("    {}  {}".format(self._c(color, label.ljust(10)), d))
            print()
            print(self._c("white", "  Output files:"))
            for label, path in [
                ("Log",    Config.LOG_FILE),
                ("CSV",    Config.CSV_FILE),
                ("DB",     Config.DB_FILE),
                ("Report", Config.REPORT_FILE),
            ]:
                exists = os.path.exists(path)
                note   = (self._c("yellow", "(exists, will append)")
                          if exists else self._c("gray", "(will be created)"))
                print("    {:<8} {}  {}".format(label, path, note))
            print()
            self._rule()
            print()
            self._menu_item("1", "Back")
            print()
            self._rule()

            if self._input("Select option") == "1":
                break

    def run(self) -> tuple:
        """Show the dashboard. Returns (should_start: bool, watch_dirs: list)."""
        should_start = self.main_menu()
        self._clear()
        return should_start, self.watch_dirs


# -- Monitor Orchestrator ------------------------------------------------------

class Sentinel:
    """
    Top-level orchestrator. Wires all components together and manages
    the watchdog observers for multiple directories.
    """

    def __init__(self):
        self.config    = Config()
        self.logger    = EventLogger(Config.LOG_FILE)
        self.store     = DataStore(Config.DB_FILE, Config.CSV_FILE)
        self.analyzer  = ThreatAnalyzer(self.config)
        self.alerts    = AlertManager(self.config)
        self.reporter  = ReportGenerator(self.store, Config.REPORT_FILE)
        self.handler   = SentinelHandler(
            self.logger, self.store, self.analyzer, self.alerts
        )
        self.observers  = []
        self.watch_dirs = []
        self.start_time = None

    def start(self):
        dashboard = Dashboard(self.config)
        should_start, self.watch_dirs = dashboard.run()

        if not should_start:
            print("  Exiting Sentinel. Goodbye.\n")
            return

        self.start_time = datetime.now()
        self.watch_dirs = self.watch_dirs or self.config.get_watch_dirs()

        # Clean up any self-generated noise recorded in previous sessions
        self.store.purge_self_entries(SentinelHandler._IGNORED_NAMES, SentinelHandler._IGNORED_PATTERNS)

        print("\033[35m")
        print("=" * 64)
        print("  SENTINEL \u2014 Now Monitoring")
        print("=" * 64)
        print("\033[0m  Platform   : {} {}".format(platform.system(), platform.release()))
        print("  Started    : {}".format(self.start_time.strftime("%Y-%m-%d %H:%M:%S")))
        print("  Watching   : {} director{}".format(
            len(self.watch_dirs), "y" if len(self.watch_dirs) == 1 else "ies"))
        for d in self.watch_dirs:
            print("    \u2022 {}".format(d))
        print("  Log        : {}".format(Config.LOG_FILE))
        print("  Database   : {}".format(Config.DB_FILE))
        print("  CSV        : {}".format(Config.CSV_FILE))
        print("\033[35m" + "=" * 64 + "\033[0m")
        print("  Press Ctrl+C to stop and generate report...\n")

        for directory in self.watch_dirs:
            try:
                observer = Observer()
                observer.schedule(self.handler, directory, recursive=True)
                observer.start()
                self.observers.append(observer)
            except Exception as e:
                print("  [!] Could not watch {}: {}".format(directory, e))

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self._shutdown()

    def _shutdown(self):
        print("\n\033[33m  Stopping Sentinel...\033[0m")
        for observer in self.observers:
            observer.stop()
        for observer in self.observers:
            observer.join()
        self.reporter.generate(self.watch_dirs, self.start_time)


if __name__ == "__main__":
    Sentinel().start()