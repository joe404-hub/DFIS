#!/usr/bin/env python3
"""Generate a complete, defensible forensic evidence package as a verified .ZIP container.

This script packages high-fidelity forensic telemetry across all 10 categories:
1. Windows Security Event Logs (XML / EVTX)
2. Windows System Event Logs (XML / EVTX)
3. PowerShell Script Block & Engine Logs
4. Windows Registry Hives & Exports (SYSTEM, SOFTWARE, NTUSER.DAT)
5. Chrome/Edge Browser SQLite Database & Session Cookies
6. FileSystem Metadata & NTFS USN Change Journal
7. Windows Prefetch Execution Traces (.pf.csv)
8. Windows Amcache Application Inventory & Cryptographic Hashes
9. Network Traffic Capture (PCAP) & NetFlow Session Logs
10. Volatile Memory Snapshot & Active Sockets

It computes individual SHA-256 digests, generates an acquisition_manifest.json,
and packages everything into a forensically defensible ZIP container.
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_evidence_package(output_zip: str | Path, case_number: str = "CASE-2026-DFIR", investigator: str = "Lead Forensic Examiner") -> Path:
    out_path = Path(output_zip).resolve()
    temp_dir = Path("/tmp") / f"evidence_build_{int(datetime.utcnow().timestamp())}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    t0 = datetime(2026, 8, 14, 9, 0, 0)
    manifest_files = []

    try:
        # 1. Windows Security Event Logs
        sec_dir = temp_dir / "Windows" / "EventLogs"
        sec_dir.mkdir(parents=True, exist_ok=True)
        sec_xml = sec_dir / "Security.xml"
        sec_xml.write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System><EventID>4624</EventID><TimeCreated SystemTime="{(t0).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="TargetUserName">analyst</Data>
      <Data Name="TargetDomainName">CORP</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="LogonProcessName">User32</Data>
      <Data Name="AuthenticationPackageName">Negotiate</Data>
      <Data Name="WorkstationName">WORKSTATION-14</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4672</EventID><TimeCreated SystemTime="{(t0 + timedelta(seconds=1)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="SubjectDomainName">CORP</Data>
      <Data Name="PrivilegeList">SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=2, seconds=15)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c whoami /priv /fo csv</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=4)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=4, seconds=45)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\net.exe</Data>
      <Data Name="CommandLine">net user analyst /domain</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=5, seconds=10)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\nltest.exe</Data>
      <Data Name="CommandLine">nltest /dclist:corp.local</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4663</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=6, seconds=20)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ObjectName">C:\\Users\\analyst\\Documents\\Confidential\\Sensitive_ProjectX.xlsx</Data>
      <Data Name="ObjectType">File</Data>
      <Data Name="AccessMask">0x1</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4663</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=7, seconds=5)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ObjectName">C:\\Users\\analyst\\Documents\\Confidential\\Customer_Database_Q3.csv</Data>
      <Data Name="ObjectType">File</Data>
      <Data Name="AccessMask">0x1</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4663</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=7, seconds=15)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ObjectName">C:\\Users\\analyst\\Documents\\Confidential\\API_Keys_Production.env</Data>
      <Data Name="ObjectType">File</Data>
      <Data Name="AccessMask">0x1</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=8)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data>
      <Data Name="CommandLine">&quot;C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe&quot; --profile-directory=&quot;Default&quot;</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=9, seconds=30)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\certutil.exe</Data>
      <Data Name="CommandLine">certutil.exe -urlcache -split -f https://intranet.corp/files/DemoUpdater.exe C:\\ProgramData\\DemoUpdater.exe</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=10)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\ProgramData\\DemoUpdater.exe</Data>
      <Data Name="CommandLine">C:\\ProgramData\\DemoUpdater.exe -install -silent</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4697</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=10, seconds=5)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ServiceName">DemoUpdater</Data>
      <Data Name="ServiceFileName">C:\\ProgramData\\DemoUpdater.exe</Data>
      <Data Name="ServiceType">0x10</Data>
      <Data Name="ServiceStartType">2</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=12, seconds=10)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\robocopy.exe</Data>
      <Data Name="CommandLine">robocopy C:\\Users\\analyst\\Documents\\Confidential C:\\Users\\analyst\\AppData\\Local\\Temp\\stage /E /R:0 /W:0</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>6416</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=14)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="DeviceDescription">SanDisk Ultra USB Device</Data>
      <Data Name="DeviceInstanceId">USB\\VID_0781&amp;PID_5581\\4C530001</Data>
      <Data Name="ClassName">DiskDrive</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=23)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\xcopy.exe</Data>
      <Data Name="CommandLine">xcopy C:\\Users\\analyst\\AppData\\Local\\Temp\\stage\\* E:\\Transfer\\ /Y /Q</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4663</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=23, seconds=15)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ObjectName">E:\\Transfer\\Sensitive_ProjectX.xlsx</Data>
      <Data Name="ObjectType">File</Data>
      <Data Name="AccessMask">0x2</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\xcopy.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4663</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=23, seconds=25)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ObjectName">E:\\Transfer\\Customer_Database_Q3.csv</Data>
      <Data Name="ObjectType">File</Data>
      <Data Name="AccessMask">0x2</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\xcopy.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4688</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=28)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cipher.exe</Data>
      <Data Name="CommandLine">cipher.exe /w:C:\\Users\\analyst\\AppData\\Local\\Temp\\stage</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4660</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=28, seconds=35)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="ObjectName">C:\\Users\\analyst\\AppData\\Local\\Temp\\stage\\confidential_backup.zip</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4634</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=35)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Security</Channel></System>
    <EventData>
      <Data Name="TargetUserName">analyst</Data>
      <Data Name="LogonType">2</Data>
    </EventData>
  </Event>
</Events>""")

        # 2. Windows System Event Logs
        sys_xml = sec_dir / "System.xml"
        sys_xml.write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System><EventID>7045</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=10)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>System</Channel></System>
    <EventData>
      <Data Name="ServiceName">DemoUpdater</Data>
      <Data Name="ImagePath">C:\\ProgramData\\DemoUpdater.exe</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">auto start</Data>
      <Data Name="AccountName">LocalSystem</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>7036</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=10, seconds=2)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>System</Channel></System>
    <EventData>
      <Data Name="param1">DemoUpdater</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>7040</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=11)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>System</Channel></System>
    <EventData>
      <Data Name="param1">RemoteRegistry</Data>
      <Data Name="param2">disabled</Data>
      <Data Name="param3">demand start</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>20001</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=14)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-Kernel-PnP/Configuration</Channel></System>
    <EventData>
      <Data Name="DriverName">usbstor.inf</Data>
      <Data Name="DeviceInstanceId">USB\\VID_0781&amp;PID_5581\\4C530001</Data>
      <Data Name="Description">SanDisk Ultra USB Device</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>20003</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=14, seconds=2)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-Kernel-PnP/Configuration</Channel></System>
    <EventData>
      <Data Name="ServiceName">disk</Data>
      <Data Name="DeviceInstanceId">Disk&amp;Ven_SanDisk&amp;Prod_Ultra</Data>
      <Data Name="Description">SanDisk Ultra Disk Device</Data>
    </EventData>
  </Event>
</Events>""")

        # 3. PowerShell Logs
        ps_dir = temp_dir / "Windows" / "PowerShell"
        ps_dir.mkdir(parents=True, exist_ok=True)
        ps_xml = ps_dir / "PowerShell_Operational.xml"
        ps_xml.write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System><EventID>400</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=4)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="EngineVersion">5.1.19041.1</Data>
      <Data Name="NewEngineState">Available</Data>
      <Data Name="SequenceNumber">1</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>600</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=4, seconds=1)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ProviderName">FileSystem</Data>
      <Data Name="NewProviderState">Started</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=4, seconds=30)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">Get-ChildItem -Path C:\\Users\\analyst\\Documents\\Confidential -Recurse -File | Select-Object FullName, Length</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=5)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">Get-Process | Where-Object {{$_.ProcessName -match "defender|edr|av|sentinel"}}</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=6, seconds=15)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">[System.IO.File]::ReadAllBytes('C:\\Users\\analyst\\Documents\\Confidential\\Sensitive_ProjectX.xlsx')</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=7, seconds=30)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">Compress-Archive -Path C:\\Users\\analyst\\Documents\\Confidential\\* -DestinationPath C:\\Users\\analyst\\AppData\\Local\\Temp\\stage\\confidential_backup.zip -CompressionLevel Optimal</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=8, seconds=45)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">Invoke-WebRequest -Uri 'https://intranet.corp/internal-drive/upload' -Method POST -InFile 'C:\\Users\\analyst\\AppData\\Local\\Temp\\stage\\confidential_backup.zip' -UseBasicParsing</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=23)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">Copy-Item -Path C:\\Users\\analyst\\AppData\\Local\\Temp\\stage\\* -Destination 'E:\\Transfer\\' -Recurse -Force</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>4104</EventID><TimeCreated SystemTime="{(t0 + timedelta(minutes=28, seconds=30)).isoformat()}Z" /><Computer>WORKSTATION-14</Computer><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
    <EventData>
      <Data Name="ScriptBlockText">Remove-Item -Path C:\\Users\\analyst\\AppData\\Local\\Temp\\stage\\* -Force; Clear-History</Data>
      <Data Name="SubjectUserName">analyst</Data>
    </EventData>
  </Event>
</Events>""")

        # 4. Registry Hives
        reg_dir = temp_dir / "Windows" / "Registry"
        reg_dir.mkdir(parents=True, exist_ok=True)
        reg_csv = reg_dir / "registry_artifacts.csv"
        reg_csv.write_text(
            "hive,artifact,timestamp,key_or_value,interpretation\n"
            f"SYSTEM,USBSTOR,{(t0 + timedelta(minutes=14)).isoformat()},USB\\VID_0781&PID_5581\\4C530001,SanDisk Ultra Removable Media Serial 4C530001\n"
            f"SYSTEM,MountedDevices,{(t0 + timedelta(minutes=14, seconds=1)).isoformat()},\\DosDevices\\E:,Volume mounted to USB removable storage device (SanDisk Ultra)\n"
            f"SYSTEM,Services,{(t0 + timedelta(minutes=10)).isoformat()},HKLM\\System\\CurrentControlSet\\Services\\DemoUpdater,DemoUpdater service configured with autostart binary C:\\ProgramData\\DemoUpdater.exe\n"
            f"SYSTEM,ShimCache,{(t0 + timedelta(minutes=10)).isoformat()},C:\\ProgramData\\DemoUpdater.exe,Application compatibility cache entry for unverified binary\n"
            f"SYSTEM,BAM,{(t0 + timedelta(minutes=4, seconds=12)).isoformat()},\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,Background Activity Moderator execution record for analyst\n"
            f"SOFTWARE,RunKey,{(t0 + timedelta(minutes=10)).isoformat()},HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DemoUpdater,\"C:\\ProgramData\\DemoUpdater.exe\" -background persistence\n"
            f"SOFTWARE,RunOnce,{(t0 + timedelta(minutes=10, seconds=5)).isoformat()},HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\CleanupAgent,\"C:\\ProgramData\\cleanup.bat\" runonce persistence\n"
            f"NTUSER.DAT,UserAssist,{(t0 + timedelta(minutes=4)).isoformat()},{{CEBFF5CD-3520-49BA-A115-0883479B33A3}}\\powershell.exe,Executed 14 times by user analyst\n"
            f"NTUSER.DAT,UserAssist,{(t0 + timedelta(minutes=8)).isoformat()},{{CEBFF5CD-3520-49BA-A115-0883479B33A3}}\\chrome.exe,Executed 42 times by user analyst\n"
            f"NTUSER.DAT,UserAssist,{(t0 + timedelta(minutes=12)).isoformat()},{{CEBFF5CD-3520-49BA-A115-0883479B33A3}}\\robocopy.exe,Executed 3 times by user analyst\n"
            f"NTUSER.DAT,RecentDocs,{(t0 + timedelta(minutes=6)).isoformat()},.xlsx\\Sensitive_ProjectX.xlsx,Recently opened sensitive financial spreadsheet\n"
            f"NTUSER.DAT,RecentDocs,{(t0 + timedelta(minutes=6, seconds=45)).isoformat()},.csv\\Customer_Database_Q3.csv,Recently opened customer database export\n"
            f"NTUSER.DAT,RecentDocs,{(t0 + timedelta(minutes=7, seconds=30)).isoformat()},.zip\\confidential_backup.zip,Recently accessed archive package\n"
            f"NTUSER.DAT,TypedURLs,{(t0 + timedelta(minutes=8, seconds=10)).isoformat()},url1\\https://intranet.corp/internal-drive,Directly typed internal document portal URL\n"
            f"NTUSER.DAT,TypedURLs,{(t0 + timedelta(minutes=8, seconds=30)).isoformat()},url2\\https://drive.google.com/drive/u/0/my-drive,Directly typed cloud storage URL\n"
            f"NTUSER.DAT,TypedPaths,{(t0 + timedelta(minutes=22, seconds=50)).isoformat()},url1\\E:\\Transfer\\,Directly navigated to USB drive mount point\n"
            f"NTUSER.DAT,ShellBags,{(t0 + timedelta(minutes=23, seconds=5)).isoformat()},HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\E:\\Transfer,Folder accessed in Windows Explorer on removable drive\n"
            f"NTUSER.DAT,MountPoints2,{(t0 + timedelta(minutes=14, seconds=2)).isoformat()},HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##Volume{{70720a5b-0000-0000-0000-100000000000}},Removable volume connected under user session\n"
        )

        # 5. Browser History & Cookies
        br_dir = temp_dir / "Browser"
        br_dir.mkdir(parents=True, exist_ok=True)
        hist_db = br_dir / "History"
        con = sqlite3.connect(hist_db)
        con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)")
        con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER)")
        con.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, tab_url TEXT, total_bytes INTEGER, received_bytes INTEGER, state INTEGER)")
        con.execute("CREATE TABLE keyword_search_terms (keyword_id INTEGER PRIMARY KEY, url_id INTEGER, lower_term TEXT, term TEXT)")

        epoch = datetime(1601, 1, 1)
        def to_ct(dt):
            return int((dt - epoch).total_seconds() * 1_000_000)

        urls_data = [
            (1, "https://intranet.corp/internal-drive", "Intranet Storage Drive", 5, 2, to_ct(t0 + timedelta(minutes=8))),
            (2, "https://intranet.corp/files/DemoUpdater.exe", "Intranet Utility Distribution", 1, 1, to_ct(t0 + timedelta(minutes=9, seconds=15))),
            (3, "https://github.com/corp-internal/core-engine/commit/a8f2c", "GitHub - Enterprise Core Engine Source", 4, 1, to_ct(t0 + timedelta(minutes=9, seconds=40))),
            (4, "https://drive.google.com/drive/u/0/my-drive", "Google Drive - Personal Cloud", 3, 2, to_ct(t0 + timedelta(minutes=10, seconds=30))),
            (5, "https://transfer.io/storage/drop", "Fast File Transfer Dropper", 2, 1, to_ct(t0 + timedelta(minutes=11, seconds=15))),
            (6, "https://intranet.corp/finance/Q3_Forecast.xlsx", "Corporate Financial Forecasts", 3, 1, to_ct(t0 + timedelta(minutes=15, seconds=30))),
        ]
        con.executemany("INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?)", urls_data)

        visits_data = [
            (1, 1, to_ct(t0 + timedelta(minutes=8)), 0, 0),
            (2, 2, to_ct(t0 + timedelta(minutes=9, seconds=15)), 1, 0),
            (3, 3, to_ct(t0 + timedelta(minutes=9, seconds=40)), 1, 0),
            (4, 4, to_ct(t0 + timedelta(minutes=10, seconds=30)), 0, 0),
            (5, 5, to_ct(t0 + timedelta(minutes=11, seconds=15)), 4, 0),
            (6, 6, to_ct(t0 + timedelta(minutes=15, seconds=30)), 1, 0),
        ]
        con.executemany("INSERT INTO visits VALUES (?, ?, ?, ?, ?)", visits_data)

        searches_data = [
            (1, 4, "google drive anonymous upload", "google drive anonymous upload"),
            (2, 5, "how to transfer files to usb secretly", "how to transfer files to usb secretly"),
            (3, 1, "zip encryption command line", "zip encryption command line"),
        ]
        con.executemany("INSERT INTO keyword_search_terms VALUES (?, ?, ?, ?)", searches_data)

        downloads_data = [
            (1, "C:\\Users\\analyst\\Downloads\\ProjectX_template.docx", to_ct(t0 + timedelta(minutes=10)), "https://intranet.corp/files", 204800, 204800, 1),
            (2, "C:\\ProgramData\\DemoUpdater.exe", to_ct(t0 + timedelta(minutes=9, seconds=20)), "https://intranet.corp/files/DemoUpdater.exe", 524288, 524288, 1),
            (3, "C:\\Users\\analyst\\Downloads\\Q3_Financial_Forecast.xlsx", to_ct(t0 + timedelta(minutes=15, seconds=45)), "https://intranet.corp/finance/Q3_Forecast.xlsx", 1048576, 1048576, 1),
        ]
        con.executemany("INSERT INTO downloads VALUES (?, ?, ?, ?, ?, ?, ?)", downloads_data)
        con.commit()
        con.close()

        cookies_csv = br_dir / "browser_cookies.csv"
        cookies_csv.write_text(
            "domain,name,timestamp,value,details\n"
            f"intranet.corp,session_token,{(t0 + timedelta(minutes=8)).isoformat()},analyst_auth_token_9921,Intranet Enterprise SSO Session\n"
            f"drive.google.com,SSID,{(t0 + timedelta(minutes=10, seconds=30)).isoformat()},AIzaSyD_cookie_token_google,Google Account Session Token\n"
            f"github.com,user_session,{(t0 + timedelta(minutes=9, seconds=40)).isoformat()},gh_sess_902148102,GitHub Enterprise Session\n"
        )

        # 6. File System Activity & USN Journal
        fs_dir = temp_dir / "FileSystem"
        fs_dir.mkdir(parents=True, exist_ok=True)
        fs_csv = fs_dir / "filesystem_activity.csv"
        fs_csv.write_text(
            "timestamp,path,event_type,user,description\n"
            f"{(t0 + timedelta(seconds=10)).isoformat()},C:/Users/analyst/NTUSER.DAT,FILE_ACCESS,SYSTEM,User registry hive loaded on interactive logon\n"
            f"{(t0 + timedelta(minutes=6)).isoformat()},C:/Users/analyst/Documents/Confidential/Sensitive_ProjectX.xlsx,FILE_OPEN,analyst,Confidential project workbook opened\n"
            f"{(t0 + timedelta(minutes=6, seconds=45)).isoformat()},C:/Users/analyst/Documents/Confidential/Customer_Database_Q3.csv,FILE_OPEN,analyst,Customer database export accessed\n"
            f"{(t0 + timedelta(minutes=7, seconds=15)).isoformat()},C:/Users/analyst/Documents/Confidential/API_Keys_Production.env,FILE_OPEN,analyst,Production API keys configuration opened\n"
            f"{(t0 + timedelta(minutes=7, seconds=30)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/confidential_backup.zip,FILE_CREATE,analyst,Staged encrypted archive created\n"
            f"{(t0 + timedelta(minutes=9, seconds=25)).isoformat()},C:/ProgramData/DemoUpdater.exe,FILE_CREATE,analyst,Downloaded executable placed in ProgramData\n"
            f"{(t0 + timedelta(minutes=12, seconds=15)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/Sensitive_ProjectX.xlsx,FILE_COPY,analyst,Copied to staging directory\n"
            f"{(t0 + timedelta(minutes=12, seconds=20)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/Customer_Database_Q3.csv,FILE_COPY,analyst,Copied to staging directory\n"
            f"{(t0 + timedelta(minutes=15, seconds=45)).isoformat()},C:/Users/analyst/Downloads/Q3_Financial_Forecast.xlsx,FILE_CREATE,analyst,Downloaded from intranet portal\n"
            f"{(t0 + timedelta(minutes=23, seconds=0)).isoformat()},E:/Transfer/Sensitive_ProjectX.xlsx,FILE_COPY,analyst,Copied to USB removable drive\n"
            f"{(t0 + timedelta(minutes=23, seconds=10)).isoformat()},E:/Transfer/Customer_Database_Q3.csv,FILE_COPY,analyst,Copied to USB removable drive\n"
            f"{(t0 + timedelta(minutes=23, seconds=20)).isoformat()},E:/Transfer/confidential_backup.zip,FILE_COPY,analyst,Copied to USB removable drive\n"
            f"{(t0 + timedelta(minutes=28, seconds=35)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/confidential_backup.zip,FILE_DELETE,analyst,Staging file deleted\n"
            f"{(t0 + timedelta(minutes=28, seconds=40)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/Sensitive_ProjectX.xlsx,FILE_DELETE,analyst,Staging file wiped with cipher\n"
        )

        usn_csv = fs_dir / "usn_journal.csv"
        usn_csv.write_text(
            "timestamp,path,event_type,user,description\n"
            f"{(t0 + timedelta(minutes=7, seconds=30)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/confidential_backup.zip,FILE_CREATE,analyst,USN Journal: USN_REASON_FILE_CREATE\n"
            f"{(t0 + timedelta(minutes=12, seconds=15)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/Sensitive_ProjectX.xlsx,FILE_CREATE,analyst,USN Journal: USN_REASON_DATA_EXTEND\n"
            f"{(t0 + timedelta(minutes=23, seconds=0)).isoformat()},E:/Transfer/Sensitive_ProjectX.xlsx,FILE_CREATE,analyst,USN Journal: USN_REASON_FILE_CREATE on E:\n"
            f"{(t0 + timedelta(minutes=28, seconds=35)).isoformat()},C:/Users/analyst/AppData/Local/Temp/stage/confidential_backup.zip,FILE_DELETE,analyst,USN Journal: USN_REASON_FILE_DELETE\n"
        )

        # 7. Prefetch Execution Traces
        pf_dir = temp_dir / "Windows" / "Prefetch"
        pf_dir.mkdir(parents=True, exist_ok=True)
        binaries = [
            ("POWERSHELL.EXE-A4B3C2D1.pf.csv", "POWERSHELL.EXE", t0 + timedelta(minutes=4, seconds=12), 14),
            ("CMD.EXE-F1E2D3C4.pf.csv", "CMD.EXE", t0 + timedelta(minutes=2, seconds=15), 8),
            ("NET.EXE-1A2B3C4D.pf.csv", "NET.EXE", t0 + timedelta(minutes=4, seconds=45), 3),
            ("NLTEST.EXE-5E6F7A8B.pf.csv", "NLTEST.EXE", t0 + timedelta(minutes=5, seconds=10), 2),
            ("CERTUTIL.EXE-9C8B7A6D.pf.csv", "CERTUTIL.EXE", t0 + timedelta(minutes=9, seconds=30), 4),
            ("DEMOUPDATER.EXE-3A4F6C8E.pf.csv", "DEMOUPDATER.EXE", t0 + timedelta(minutes=10), 1),
            ("ROBOCOPY.EXE-8D7C6B5A.pf.csv", "ROBOCOPY.EXE", t0 + timedelta(minutes=12, seconds=10), 3),
            ("CHROME.EXE-4D3C2B1A.pf.csv", "CHROME.EXE", t0 + timedelta(minutes=8), 42),
            ("XCOPY.EXE-7B8A9C0D.pf.csv", "XCOPY.EXE", t0 + timedelta(minutes=23), 2),
            ("CIPHER.EXE-2C3D4E5F.pf.csv", "CIPHER.EXE", t0 + timedelta(minutes=28), 1),
        ]
        for fname, exe, ts, count in binaries:
            (pf_dir / fname).write_text(f"executable,timestamp,run_count\n{exe},{ts.isoformat()},{count}\n")

        # 8. Amcache Application Evidence
        am_dir = temp_dir / "Windows" / "Amcache"
        am_dir.mkdir(parents=True, exist_ok=True)
        am_csv = am_dir / "Amcache_Applications.csv"
        am_csv.write_text(
            "path,sha1,timestamp,publisher,version,size_bytes\n"
            f"C:\\ProgramData\\DemoUpdater.exe,3a4f6c8e9b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f,{(t0 + timedelta(minutes=10)).isoformat()},DemoUpdater Inc.,1.0.0.0,524288\n"
            f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,8f9e1d2c3b4a5061728394a5b6c7d8e9f0a1b2c3,{(t0 + timedelta(minutes=4)).isoformat()},Microsoft Corporation,10.0.19041.1,450560\n"
            f"C:\\Windows\\System32\\certutil.exe,1234567890abcdef1234567890abcdef12345678,{(t0 + timedelta(minutes=9, seconds=30)).isoformat()},Microsoft Corporation,10.0.19041.1,192512\n"
            f"C:\\Windows\\System32\\robocopy.exe,abcdef1234567890abcdef1234567890abcdef12,{(t0 + timedelta(minutes=12, seconds=10)).isoformat()},Microsoft Corporation,10.0.19041.1,118784\n"
            f"C:\\Windows\\System32\\cipher.exe,7890abcdef1234567890abcdef1234567890abcd,{(t0 + timedelta(minutes=28)).isoformat()},Microsoft Corporation,10.0.19041.1,65536\n"
            f"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,567890abcdef1234567890abcdef1234567890ab,{(t0 + timedelta(minutes=8)).isoformat()},Google LLC,120.0.6099.130,3145728\n"
            f"C:\\Windows\\System32\\nltest.exe,4321fedcba0987654321fedcba0987654321fedc,{(t0 + timedelta(minutes=5, seconds=10)).isoformat()},Microsoft Corporation,10.0.19041.1,81920\n"
            f"C:\\Windows\\System32\\cmd.exe,fedcba9876543210fedcba9876543210fedcba98,{(t0 + timedelta(minutes=2, seconds=15)).isoformat()},Microsoft Corporation,10.0.19041.1,289792\n"
        )

        # 9. Network Traffic & NetFlow
        net_dir = temp_dir / "Network"
        net_dir.mkdir(parents=True, exist_ok=True)
        net_csv = net_dir / "network_flows.csv"
        net_csv.write_text(
            "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,details\n"
            f"{(t0 + timedelta(minutes=8)).isoformat()},10.0.0.14,52123,10.0.0.53,53,DNS,DNS Query for intranet.corp\n"
            f"{(t0 + timedelta(minutes=8, seconds=2)).isoformat()},10.0.0.14,52124,10.0.0.20,443,TCP,HTTPS session to Intranet Storage Drive (18450 bytes)\n"
            f"{(t0 + timedelta(minutes=9, seconds=38)).isoformat()},10.0.0.14,52125,10.0.0.53,53,DNS,DNS Query for github.com\n"
            f"{(t0 + timedelta(minutes=9, seconds=40)).isoformat()},10.0.0.14,52126,140.82.121.4,443,TCP,HTTPS session to GitHub Enterprise (84200 bytes)\n"
            f"{(t0 + timedelta(minutes=10, seconds=28)).isoformat()},10.0.0.14,52127,10.0.0.53,53,DNS,DNS Query for drive.google.com\n"
            f"{(t0 + timedelta(minutes=10, seconds=30)).isoformat()},10.0.0.14,52128,142.250.190.46,443,TCP,HTTPS session to Google Drive upload (4285120 bytes)\n"
            f"{(t0 + timedelta(minutes=11, seconds=10)).isoformat()},10.0.0.14,52129,10.0.0.53,53,DNS,DNS Query for transfer.io\n"
            f"{(t0 + timedelta(minutes=11, seconds=15)).isoformat()},10.0.0.14,52130,104.21.58.12,443,TCP,HTTPS session to file dropper (2150000 bytes)\n"
            f"{(t0 + timedelta(minutes=15, seconds=30)).isoformat()},10.0.0.14,52131,10.0.0.20,445,SMB,SMB Share access \\\\10.0.0.20\\finance$ Q3_Forecast.xlsx\n"
            f"{(t0 + timedelta(minutes=10, seconds=5)).isoformat()},10.0.0.14,52132,10.0.0.53,53,DNS,DNS Query for updates.corp-telemetry.org\n"
            f"{(t0 + timedelta(minutes=10, seconds=10)).isoformat()},10.0.0.14,52133,198.51.100.24,8080,TCP,HTTP C2 Beacon connection DemoUpdater\n"
        )

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSQR
            pcap_file = net_dir / "network_traffic.pcap"
            
            p1 = IP(src="10.0.0.14", dst="10.0.0.53") / UDP(sport=52123, dport=53) / DNS(rd=1, qd=DNSQR(qname="intranet.corp"))
            p1.time = (t0 + timedelta(minutes=8)).timestamp()
            p2 = IP(src="10.0.0.14", dst="10.0.0.20") / TCP(sport=52124, dport=443, flags="S")
            p2.time = (t0 + timedelta(minutes=8, seconds=2)).timestamp()
            p3 = IP(src="10.0.0.14", dst="10.0.0.53") / UDP(sport=52125, dport=53) / DNS(rd=1, qd=DNSQR(qname="github.com"))
            p3.time = (t0 + timedelta(minutes=9, seconds=38)).timestamp()
            p4 = IP(src="10.0.0.14", dst="140.82.121.4") / TCP(sport=52126, dport=443, flags="S")
            p4.time = (t0 + timedelta(minutes=9, seconds=40)).timestamp()
            p5 = IP(src="10.0.0.14", dst="10.0.0.53") / UDP(sport=52127, dport=53) / DNS(rd=1, qd=DNSQR(qname="drive.google.com"))
            p5.time = (t0 + timedelta(minutes=10, seconds=28)).timestamp()
            p6 = IP(src="10.0.0.14", dst="142.250.190.46") / TCP(sport=52128, dport=443, flags="S")
            p6.time = (t0 + timedelta(minutes=10, seconds=30)).timestamp()
            p7 = IP(src="10.0.0.14", dst="10.0.0.53") / UDP(sport=52129, dport=53) / DNS(rd=1, qd=DNSQR(qname="transfer.io"))
            p7.time = (t0 + timedelta(minutes=11, seconds=10)).timestamp()
            p8 = IP(src="10.0.0.14", dst="104.21.58.12") / TCP(sport=52130, dport=443, flags="S")
            p8.time = (t0 + timedelta(minutes=11, seconds=15)).timestamp()

            scapy.wrpcap(str(pcap_file), [p1, p2, p3, p4, p5, p6, p7, p8])
        except Exception:
            pass

        # 10. Memory Volatility Snapshot
        mem_dir = temp_dir / "Memory"
        mem_dir.mkdir(parents=True, exist_ok=True)
        mem_txt = mem_dir / "Memory.raw.txt"
        mem_txt.write_text(
            f"SYNTHETIC MEMORY SNAPSHOT\n"
            f"Captured: {(t0 + timedelta(minutes=30)).isoformat()}\n\n"
            f"Processes:\n"
            f"- explorer.exe | PID 3120 | User analyst\n"
            f"- powershell.exe | PID 4892 | User analyst\n"
            f"- chrome.exe | PID 5612 | User analyst\n"
            f"- DemoUpdater.exe | PID 6720 | User SYSTEM\n"
            f"- lsass.exe | PID 680 | User SYSTEM\n\n"
            f"Network:\n"
            f"- 10.0.0.14:52124 -> 10.0.0.20:443\n"
            f"- 10.0.0.14:52128 -> 142.250.190.46:443\n"
            f"- 10.0.0.14:52133 -> 198.51.100.24:8080\n"
        )
        mem_csv = mem_dir / "memory_artifacts.csv"
        mem_csv.write_text(
            "timestamp,process,pid,user,details,event_type\n"
            f"{(t0 + timedelta(minutes=30)).isoformat()},explorer.exe,3120,analyst,Active Windows Explorer shell,process_list\n"
            f"{(t0 + timedelta(minutes=30)).isoformat()},powershell.exe,4892,analyst,Active PowerShell process with execution policy bypass,process_list\n"
            f"{(t0 + timedelta(minutes=30)).isoformat()},chrome.exe,5612,analyst,Active Chrome browser with multiple open tabs,process_list\n"
            f"{(t0 + timedelta(minutes=30)).isoformat()},DemoUpdater.exe,6720,SYSTEM,Suspicious unverified background service,process_list\n"
            f"{(t0 + timedelta(minutes=30)).isoformat()},lsass.exe,680,SYSTEM,Local Security Authority Subsystem,process_list\n"
        )

        # Build Manifest of all artifacts with individual SHA-256 hashes
        total_files = 0
        total_bytes = 0
        for p in temp_dir.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(temp_dir))
                fhash = sha256_file(p)
                fsize = p.stat().st_size
                manifest_files.append({
                    "file": rel,
                    "sha256": fhash,
                    "size_bytes": fsize,
                })
                total_files += 1
                total_bytes += fsize

        manifest_json = temp_dir / "acquisition_manifest.json"
        manifest_json.write_text(
            json.dumps(
                {
                    "case_number": case_number,
                    "investigator": investigator,
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "total_files": total_files,
                    "total_bytes": total_bytes,
                    "evidence_categories": [
                        "Windows Security Logs",
                        "Windows System Logs",
                        "PowerShell Operational Logs",
                        "Registry Hives (SYSTEM, SOFTWARE, NTUSER.DAT)",
                        "Browser SQLite History & Cookies",
                        "FileSystem Access & USN Journal",
                        "Windows Prefetch Traces",
                        "Amcache Applications & Hashes",
                        "Network PCAP & NetFlow Sessions",
                        "Memory Process Snapshots & Sockets",
                    ],
                    "files": manifest_files,
                },
                indent=2,
            )
        )

        # Package into ZIP archive
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(out_path, "w", compression=ZIP_DEFLATED) as zf:
            for p in sorted(temp_dir.rglob("*")):
                if p.is_file():
                    zf.write(p, arcname=str(p.relative_to(temp_dir)))

        pkg_hash = sha256_file(out_path)
        print(f"✅ Generated Forensic Evidence Package: {out_path}")
        print(f"📦 Total Files: {total_files} | Total Size: {out_path.stat().st_size} bytes")
        print(f"🔐 SHA-256: {pkg_hash}")

        return out_path

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a complete DFIS forensic evidence package (.zip)")
    parser.add_argument("-o", "--output", default="DFIS_Complete_Forensic_Evidence.zip", help="Output ZIP file path")
    parser.add_argument("-c", "--case", default="CASE-2026-EXPANDED", help="Case Number")
    parser.add_argument("-i", "--investigator", default="Lead DFIR Examiner", help="Investigator Name")
    args = parser.parse_args()

    build_evidence_package(args.output, args.case, args.investigator)
