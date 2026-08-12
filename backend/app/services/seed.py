import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from zipfile import ZipFile

from app.db import EVIDENCE_DIR


def write_demo_package() -> Path:
    root = EVIDENCE_DIR / "_demo_src"
    root.mkdir(parents=True, exist_ok=True)
    t0 = datetime(2026, 3, 12, 8, 57, 0)

    events = [
        {"source_type": "windows_event", "event_type": "logon", "timestamp": (t0).isoformat(), "description": "Windows Event 4624 successful logon for CORP\\j.patel on WORKSTATION-14", "actor": "CORP\\j.patel", "target": "WORKSTATION-14"},
        {"source_type": "browser", "event_type": "url_visit", "timestamp": (t0 + timedelta(minutes=5)).isoformat(), "description": "Browser visit: https://github.com/acme/ProjectX", "actor": "j.patel", "target": "https://github.com/acme/ProjectX"},
        {"source_type": "windows_event", "event_type": "usb", "timestamp": (t0 + timedelta(minutes=13)).isoformat(), "description": "USB mass storage inserted VID_0781&PID_5581 SanDisk Ultra serial 4C530001", "actor": "j.patel", "target": "SanDisk Ultra"},
        {"source_type": "filesystem", "event_type": "file_access", "timestamp": (t0 + timedelta(minutes=16)).isoformat(), "description": "File accessed C:\\Users\\j.patel\\Documents\\ProjectX\\source\\api_keys.env", "actor": "j.patel", "target": "api_keys.env"},
        {"source_type": "filesystem", "event_type": "archive_created", "timestamp": (t0 + timedelta(minutes=18)).isoformat(), "description": "Archive created C:\\Users\\j.patel\\Desktop\\SourceCode.zip (42 MB)", "actor": "j.patel", "target": "SourceCode.zip"},
        {"source_type": "filesystem", "event_type": "file_copy", "timestamp": (t0 + timedelta(minutes=22)).isoformat(), "description": "File copy detected SourceCode.zip -> E:\\backup\\SourceCode.zip", "actor": "j.patel", "target": "E:\\backup\\SourceCode.zip"},
        {"source_type": "windows_event", "event_type": "usb", "timestamp": (t0 + timedelta(minutes=25)).isoformat(), "description": "USB device removed SanDisk Ultra", "actor": "j.patel", "target": "SanDisk Ultra"},
        {"source_type": "browser", "event_type": "url_visit", "timestamp": (t0 + timedelta(minutes=28)).isoformat(), "description": "Browser visit: https://drive.google.com/drive/my-drive", "actor": "j.patel", "target": "https://drive.google.com/drive/my-drive"},
        {"source_type": "windows_event", "event_type": "logout", "timestamp": (t0 + timedelta(minutes=43)).isoformat(), "description": "Windows Event 4634 logoff CORP\\j.patel", "actor": "CORP\\j.patel", "target": "WORKSTATION-14"},
    ]
    (root / "timeline_export.json").write_text(json.dumps(events, indent=2))

    # Chrome-like history
    hist = root / "History"
    if hist.exists():
        hist.unlink()
    con = sqlite3.connect(hist)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.execute(
        "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, tab_url TEXT)"
    )
    chrome_epoch = datetime(1601, 1, 1)

    def ct(dt):
        return int((dt - chrome_epoch).total_seconds() * 1_000_000)

    con.execute("INSERT INTO urls VALUES (1, 'https://github.com/acme/ProjectX', 'ProjectX')")
    con.execute("INSERT INTO urls VALUES (2, 'https://drive.google.com/drive/my-drive', 'Google Drive')")
    con.execute("INSERT INTO visits VALUES (1, 1, ?)", (ct(t0 + timedelta(minutes=5)),))
    con.execute("INSERT INTO visits VALUES (2, 2, ?)", (ct(t0 + timedelta(minutes=28)),))
    con.execute(
        "INSERT INTO downloads VALUES (1, 'C:\\\\Users\\\\j.patel\\\\Downloads\\\\rclone.exe', ?, 'https://example.com/rclone.exe')",
        (ct(t0 + timedelta(minutes=27)),),
    )
    con.commit()
    con.close()

    csv = root / "filesystem_files.csv"
    csv.write_text(
        "timestamp,event_type,path,description,actor\n"
        f"{(t0+timedelta(minutes=16)).isoformat()},file_access,C:/Users/j.patel/Documents/ProjectX/source/api_keys.env,Confidential env file accessed,j.patel\n"
        f"{(t0+timedelta(minutes=18)).isoformat()},archive_created,C:/Users/j.patel/Desktop/SourceCode.zip,Staging archive created,j.patel\n"
    )

    zpath = EVIDENCE_DIR / "CASE-DEMO.zip"
    with ZipFile(zpath, "w") as zf:
        for p in root.iterdir():
            zf.write(p, arcname=p.name)
    return zpath
