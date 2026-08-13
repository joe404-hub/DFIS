FORENSIC_KB = [
    {
        "id": "kb-usb-exfil",
        "text": "USB mass-storage insertion followed by access to confidential files and creation of archive files is a common data-exfiltration pattern. Correlate Event ID 6416/USBSTOR with file-system timestamps and browser cloud uploads.",
    },
    {
        "id": "kb-4624",
        "text": "Windows Security Event 4624 indicates a successful logon. Logon type 10 is remote interactive (RDP). Type 2 is interactive console. Type 3 is network. Failed 4625 events nearby may indicate credential abuse.",
    },
    {
        "id": "kb-runkeys",
        "text": "Registry Run keys under HKCU/HKLM CurrentVersion\\Run are persistence mechanisms mapped to MITRE ATT&CK T1547.001.",
    },
    {
        "id": "kb-browser",
        "text": "Chrome History stores visits and downloads in SQLite. Cloud storage URLs (drive.google.com, dropbox.com, wetransfer) after sensitive file access may indicate exfiltration (T1567).",
    },
    {
        "id": "kb-ransomware",
        "text": "Ransomware often shows mass file rename/encrypt, ransom notes, service installation, and unusual process creation (4688) from user-writable paths.",
    },
    {
        "id": "kb-integrity",
        "text": "SHA-256 hashes establish evidence integrity. Analysis must use working copies. AI findings are not evidence; they must cite artifact IDs.",
    },
    {
        "id": "kb-timeline",
        "text": "Unified timelines require timezone normalization to UTC, deduplication of repeated log records, and cross-source correlation of the same user/device/file.",
    },
    {
        "id": "kb-mitre",
        "text": "Typical insider theft chain: Initial Access (valid accounts T1078) → Collection (T1005) → Archive (T1560) → Exfiltration via physical media (T1052) or web service (T1567).",
    },
]
