from datetime import datetime
from pathlib import Path

SOURCE = "network"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix in {".pcap", ".pcapng", ".cap"}


def parse(path: Path) -> list[dict]:
    events = []
    try:
        from scapy.all import rdpcap, DNSQR, IP, TCP, UDP
    except Exception:
        return [
            {
                "source_type": SOURCE,
                "event_type": "pcap_ingested",
                "timestamp": None,
                "description": f"PCAP ingested (scapy unavailable): {path.name}",
                "actor": "",
                "target": path.name,
                "raw_data": "",
            }
        ]
    pkts = rdpcap(str(path), count=200)
    for p in pkts:
        ts = datetime.utcfromtimestamp(float(p.time)) if hasattr(p, "time") else None
        src = dst = proto = ""
        if IP in p:
            src, dst = p[IP].src, p[IP].dst
        if p.haslayer(DNSQR):
            q = p[DNSQR].qname.decode(errors="ignore") if isinstance(p[DNSQR].qname, bytes) else str(p[DNSQR].qname)
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": "dns_query",
                    "timestamp": ts,
                    "description": f"DNS query {q} from {src}",
                    "actor": src,
                    "target": q,
                    "raw_data": q,
                }
            )
        elif TCP in p or UDP in p:
            layer = p[TCP] if TCP in p else p[UDP]
            proto = "TCP" if TCP in p else "UDP"
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": "network_flow",
                    "timestamp": ts,
                    "description": f"{proto} {src}:{layer.sport} → {dst}:{layer.dport}",
                    "actor": src,
                    "target": f"{dst}:{layer.dport}",
                    "raw_data": "",
                }
            )
    return events[:300]
