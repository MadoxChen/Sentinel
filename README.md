
  Sentinel - System Security File Monitor
================================================================


OVERVIEW
--------
Sentinel is a real-time, system-wide file security monitor. It
watches your file system for suspicious activity, classifies
every event by threat severity, sends desktop (and optional
email) alerts, stores all events in a SQLite database and CSV
file, and generates a full summary report when you exit.
 
 
REQUIREMENTS
------------
  Python 3.8 or higher
  pip
  watchdog
 
  Desktop notifications require:  
  
   - Linux   - notify-send  (sudo apt install libnotify-bin)
   - macOS   - osascript    (built-in)
   - Windows - PowerShell   (built-in)
 
 
INSTALLATION
------------
1. Make sure Python 3.8+ is installed.
   Check with:  python3 --version
 
2. Install the required library:
   pip install -r requirements.txt
 
Or manually:
   ```
   pip install watchdog
   ```
 
 
RUNNING SENTINEL
----------------

```
pip install watchdog
```

You will be taken to the interactive dashboard first.
From there you can configure directories, sensitivity, and
email alerts before starting the monitor.

Press Ctrl+C at any time while monitoring to stop and generate
the exit report.
