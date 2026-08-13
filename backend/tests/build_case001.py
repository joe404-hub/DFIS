"""Build a CASE001-shaped synthetic ZIP and print parser output."""
import csv
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.parsers import classify_skipped, parse_file


def build(root: Path) -> Path:
    if root.exists():
        import shutil

        shutil.rmtree(root)
    dirs = {
        "Windows": root / "Windows",
        "Registry": root / "Registry",
        "Browser": root / "Browser",
        "Network": root / "Network",
        "Memory": root / "Memory",
        "FileSystem": root / "FileSystem",
        "Metadata": root / "Metadata",
    }
    for d in dirs.values():
        d.mkdir(parents=True)

    def wcsv(path, header, rows):
        with path.open("w", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            wr.writerow(header)
            wr.writerows(rows)

    wcsv(
        dirs["Windows"] / "Security_events.csv",
        ["TimeCreated", "EventID", "AccountName", "Message"],
        [
            ["2026-08-12T03:30:00", "4624", "analyst", "Successful logon"],
            ["2026-08-12T03:32:00", "4688", "analyst", "PowerShell.exe started"],
            ["2026-08-12T04:10:00", "4672", "admin", "Special privileges assigned"],
            ["2026-08-12T04:20:00", "4634", "analyst", "Logoff"],
        ],
    )
    wcsv(
        dirs["Windows"] / "System_events.csv",
        ["timestamp", "event_id", "description", "device"],
        [
            ["2026-08-12T03:33:00", "7045", "Synthetic Service Installed", "FakeSvc"],
            ["2026-08-12T03:40:00", "6416", "USB Connected SanDisk", "SanDisk"],
            ["2026-08-12T04:00:00", "2102", "USB Removed SanDisk", "SanDisk"],
        ],
    )
    wcsv(
        dirs["Registry"] / "registry_artifacts.csv",
        ["timestamp", "key", "value", "description"],
        [
            ["2026-08-12T03:40:05", r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "SanDisk", "USBSTOR history"],
            ["2026-08-12T03:33:10", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "FakeSvc", "Run key persistence"],
        ],
    )
    wcsv(
        dirs["Browser"] / "Cookies.csv",
        ["creation_time", "host", "name"],
        [["2026-08-12T03:36:00", "intranet.corp", "session"]],
    )
    hist = dirs["Browser"] / "History.sqlite"
    con = sqlite3.connect(hist)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, tab_url TEXT)")
    epoch = datetime(1601, 1, 1)

    def ct(s):
        dt = datetime.fromisoformat(s)
        return int((dt - epoch).total_seconds() * 1_000_000)

    con.execute("INSERT INTO urls VALUES (1,'https://intranet.corp/drive','Internal Drive')")
    con.execute("INSERT INTO visits VALUES (1,1,?)", (ct("2026-08-12T04:05:00"),))
    con.execute(
        "INSERT INTO downloads VALUES (1,'C:/Users/analyst/Downloads/ProjectX_template.docx',?,'https://intranet.corp/files')",
        (ct("2026-08-12T03:35:00"),),
    )
    con.commit()
    con.close()
    wcsv(
        dirs["Network"] / "Capture_packets.csv",
        ["timestamp", "src_ip", "dst_ip", "protocol", "info"],
        [
            ["2026-08-12T04:05:10", "10.0.0.14", "10.0.0.8", "TCP", "Internal Drive accessed"],
            ["2026-08-12T03:36:00", "10.0.0.14", "10.0.0.53", "DNS", "intranet.corp"],
        ],
    )
    (dirs["Memory"] / "Memory.raw.txt").write_text(
        "2026-08-12T03:32:05 | process_create | powershell.exe pid=4420\n"
        "Process: powershell.exe\nPID: 4420\n"
    )
    wcsv(
        dirs["FileSystem"] / "filesystem_events.csv",
        ["timestamp", "event_type", "path", "source", "description", "actor"],
        [
            ["2026-08-12T03:45:00", "FILE_OPEN", "C:/Users/analyst/Documents/Sensitive_ProjectX.xlsx", "", "File opened", "analyst"],
            ["2026-08-12T03:50:00", "FILE_OPEN", "C:/Users/analyst/Documents/Customer_List.csv", "", "File opened", "analyst"],
            ["2026-08-12T03:53:00", "FILE_COPY", "E:/Transfer/Sensitive_ProjectX.xlsx", "C:/Users/analyst/Documents/Sensitive_ProjectX.xlsx", "Copied to USB", "analyst"],
            ["2026-08-12T03:55:00", "FILE_COPY", "E:/Transfer/Customer_List.csv", "C:/Users/analyst/Documents/Customer_List.csv", "Copied to USB", "analyst"],
        ],
    )
    (root / "case_manifest.json").write_text(
        json.dumps({"case": "CASE001", "scenario": "Synthetic insider-threat / possible data-exfiltration demonstration case"})
    )
    (root / "README.txt").write_text("Documentation only.")
    with (root / "expected_timeline.csv").open("w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["timestamp", "event"])
        wr.writerow(["2026-08-12T03:45:00", "FILE_OPEN Sensitive_ProjectX.xlsx"])
    zpath = root.parent / "CASE001_synthetic_forensics.zip"
    with ZipFile(zpath, "w") as zf:
        for p in root.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(p.relative_to(root)))
    return zpath


if __name__ == "__main__":
    root = Path("/tmp/case001_src")
    z = build(root)
    print("ZIP", z)
    events = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        reason = classify_skipped(p)
        if reason:
            print("SKIP", p.name, reason)
            continue
        evs = parse_file(p)
        print(f"PARSE {p.relative_to(root)} -> {len(evs)}")
        events.extend(evs)
    events.sort(key=lambda e: e["timestamp"] or datetime.min)
    for e in events:
        print(f"  {e['timestamp']}  {e['source_type']:14} {e['event_type']:18} {e['description'][:90]}")
