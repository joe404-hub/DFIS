"""Write the real CASE001 layouts used in evaluation (not expected_timeline)."""
from pathlib import Path


def write_case001(root: Path) -> Path:
    root = Path(root)
    (root / "Windows").mkdir(parents=True, exist_ok=True)
    (root / "Registry").mkdir(exist_ok=True)
    (root / "Browser").mkdir(exist_ok=True)
    (root / "Network").mkdir(exist_ok=True)
    (root / "Memory").mkdir(exist_ok=True)
    (root / "FileSystem").mkdir(exist_ok=True)
    (root / "Windows" / "Security_events.csv").write_text(
        "timestamp,source,event_id,event_type,user,host,details\n"
        "2026-08-12T09:00:00+05:30,Security.evtx,4624,SUCCESSFUL_LOGON,analyst,10.0.0.25,User analyst logged on\n"
        "2026-08-12T09:04:00+05:30,Security.evtx,4688,PROCESS_CREATE,analyst,10.0.0.25,powershell.exe started\n"
        "2026-08-12T09:10:00+05:30,System.evtx,7045,SERVICE_INSTALL,analyst,10.0.0.25,Service DemoUpdater installed\n"
        "2026-08-12T09:14:00+05:30,Security.evtx,6416,USB_DEVICE_CONNECTED,analyst,10.0.0.25,USB storage device connected\n"
        "2026-08-12T09:17:00+05:30,Security.evtx,4663,FILE_ACCESS,analyst,10.0.0.25,Sensitive_ProjectX.xlsx accessed\n"
        "2026-08-12T09:20:00+05:30,Security.evtx,4663,FILE_ACCESS,analyst,10.0.0.25,Customer_List.csv accessed\n"
        "2026-08-12T09:23:00+05:30,Security.evtx,4663,FILE_COPY,analyst,10.0.0.25,Sensitive_ProjectX.xlsx copied to E:\\Transfer\n"
        "2026-08-12T09:25:00+05:30,Security.evtx,4663,FILE_COPY,analyst,10.0.0.25,Customer_List.csv copied to E:\\Transfer\n"
        "2026-08-12T09:28:00+05:30,Security.evtx,6416,USB_DEVICE_REMOVED,analyst,10.0.0.25,USB storage device removed\n"
        "2026-08-12T09:31:00+05:30,Security.evtx,4624,SUCCESSFUL_LOGON,admin,10.0.0.25,Administrative logon\n"
        "2026-08-12T09:36:00+05:30,Security.evtx,4634,LOGOFF,analyst,10.0.0.25,User analyst logged off\n"
    )
    (root / "Windows" / "System_events.csv").write_text(
        "timestamp,event_id,event_type,service,details\n"
        "2026-08-12T09:10:00+05:30,7045,SERVICE_INSTALL,DemoUpdater,Service installed\n"
        "2026-08-12T09:12:00+05:30,7036,SERVICE_RUNNING,DemoUpdater,Service entered running state\n"
        "2026-08-12T09:29:00+05:30,7036,SERVICE_STOPPED,DemoUpdater,Service stopped\n"
    )
    (root / "Registry" / "registry_artifacts.csv").write_text(
        "hive,artifact,timestamp,key_or_value,interpretation\n"
        "NTUSER.DAT,USBSTOR,2026-08-12T09:14:00+05:30,USB\\VID_0781&PID_5567,SanDisk Ultra Synthetic\n"
        "NTUSER.DAT,RecentDocs,2026-08-12T09:17:00+05:30,Sensitive_ProjectX.xlsx,Recently opened document\n"
        "NTUSER.DAT,RecentDocs,2026-08-12T09:20:00+05:30,Customer_List.csv,Recently opened document\n"
        "SOFTWARE,InstalledService,2026-08-12T09:10:00+05:30,DemoUpdater,Synthetic service entry\n"
    )
    (root / "FileSystem" / "filesystem_events.csv").write_text(
        "timestamp,path,event_type,user\n"
        "2026-08-12T09:15:00+05:30,C:/Users/analyst/Documents/Sensitive_ProjectX.xlsx,FILE_OPEN,analyst\n"
        "2026-08-12T09:23:00+05:30,E:/Transfer/Sensitive_ProjectX.xlsx,FILE_COPY,analyst\n"
        "2026-08-12T09:20:00+05:30,C:/Users/analyst/Documents/Customer_List.csv,FILE_OPEN,analyst\n"
        "2026-08-12T09:25:00+05:30,E:/Transfer/Customer_List.csv,FILE_COPY,analyst\n"
    )
    (root / "Network" / "Capture_packets.csv").write_text(
        "timestamp,src_ip,dst_ip,protocol,dst_port,app,details\n"
        "2026-08-12T09:30:10+05:30,10.0.0.25,10.0.0.50,TCP,443,TLS,Internal drive connection\n"
        "2026-08-12T09:30:18+05:30,10.0.0.25,10.0.0.50,TCP,443,TLS,\"POST request, synthetic\"\n"
        "2026-08-12T09:30:20+05:30,10.0.0.25,10.0.0.50,TCP,443,TLS,Response received\n"
    )
    (root / "Browser" / "Cookies.csv").write_text(
        "timestamp,domain,name,note\n"
        "2026-08-12T09:30:00+05:30,drive.example.local,session,Synthetic session metadata only\n"
    )
    (root / "Memory" / "Memory.raw.txt").write_text(
        "SYNTHETIC MEMORY SNAPSHOT — NOT A REAL MEMORY IMAGE\n"
        "Case: CASE001\nCaptured: 2026-08-12T09:40:00+05:30\n\n"
        "Processes:\n- explorer.exe | PID 4120 | User analyst\n"
        "- powershell.exe | PID 5288 | User analyst\n"
        "- DemoUpdater.exe | PID 6144 | User analyst\n\n"
        "Network:\n- 10.0.0.25:51520 -> 10.0.0.50:443\n"
    )
    (root / "expected_timeline.csv").write_text("timestamp,event\n")
    (root / "README.txt").write_text("docs\n")
    (root / "case_manifest.json").write_text('{"case_id":"CASE001","synthetic":true}\n')
    return root
