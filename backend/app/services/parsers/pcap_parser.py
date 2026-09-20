"""Network Packet Capture (PCAP & PCAPNG) Forensic Parser.

Extracts DNS queries, HTTP flows, TLS SNI domain handshakes, and TCP/UDP connections
using Scapy into the Common Forensic Event Schema.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

SOURCE = "network"


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if suffix in {".pcap", ".pcapng", ".cap"}:
        return True
    if hint in {"pcap", "network"}:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if header in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}:
                return True
    except Exception:
        pass
    return False


def parse(path: Path) -> list[dict]:
    """Parse PCAP/PCAPNG network packets into normalized forensic events."""
    events: list[dict] = []
    try:
        from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, Raw, TCP, UDP, rdpcap
    except Exception as exc:
        return [
            {
                "event_id": "pcap_unparsed",
                "timestamp": None,
                "timestamp_utc": "",
                "source": f"Network PCAP ({path.name})",
                "source_type": SOURCE,
                "artifact_type": "Network Capture",
                "event_type": "pcap_ingested",
                "user": "",
                "actor": "",
                "host": "",
                "process": "",
                "pid": "",
                "action": "PCAP Ingested",
                "object": path.name,
                "target": path.name,
                "path": str(path),
                "source_path": "",
                "destination_path": "",
                "source_ip": "",
                "source_port": "",
                "destination_ip": "",
                "destination_port": "",
                "description": f"PCAP ingested (scapy error: {exc}): {path.name}",
                "raw_data": str(exc),
                "parser_name": "pcap_fallback",
                "source_file": path.name,
                "time_kind": "event",
                "observation_time": "",
            }
        ]

    try:
        pkts = rdpcap(str(path), count=2000)
    except Exception:
        return []

    seen_flows = set()

    for idx, p in enumerate(pkts):
        ts = datetime.utcfromtimestamp(float(p.time)) if hasattr(p, "time") else None
        ts_utc_str = ts.isoformat() + "Z" if ts else ""

        src_ip = dst_ip = ""
        if IP in p:
            src_ip, dst_ip = p[IP].src, p[IP].dst
        elif IPv6 in p:
            src_ip, dst_ip = p[IPv6].src, p[IPv6].dst
        else:
            continue

        sport = dport = proto = ""
        if TCP in p:
            sport, dport, proto = str(p[TCP].sport), str(p[TCP].dport), "TCP"
        elif UDP in p:
            sport, dport, proto = str(p[UDP].sport), str(p[UDP].dport), "UDP"

        # 1. DNS Query & Response
        if p.haslayer(DNS):
            dns = p[DNS]
            if dns.haslayer(DNSQR) and dns.qr == 0:  # DNS Query
                qname = dns[DNSQR].qname.decode(errors="ignore").rstrip(".") if isinstance(dns[DNSQR].qname, bytes) else str(dns[DNSQR].qname).rstrip(".")
                events.append(
                    {
                        "event_id": f"dns_{idx}",
                        "timestamp": ts,
                        "timestamp_utc": ts_utc_str,
                        "source": f"Network PCAP ({path.name})",
                        "source_type": SOURCE,
                        "artifact_type": "DNS Query",
                        "event_type": "dns_query",
                        "user": "",
                        "actor": src_ip,
                        "host": "",
                        "process": "",
                        "pid": "",
                        "action": f"DNS Query ({qname})",
                        "object": qname,
                        "target": qname,
                        "path": "",
                        "source_path": "",
                        "destination_path": "",
                        "source_ip": src_ip,
                        "source_port": sport,
                        "destination_ip": dst_ip,
                        "destination_port": dport,
                        "description": f"DNS Query | Client: {src_ip} | Domain: {qname} | Server: {dst_ip}",
                        "raw_data": json.dumps({"query": qname, "client": src_ip, "server": dst_ip}),
                        "parser_name": "pcap_dns",
                        "source_file": path.name,
                        "time_kind": "event",
                        "observation_time": "",
                    }
                )
                continue

        # 2. TLS / HTTPS Client Hello SNI Domain Extraction
        if TCP in p and (dport == "443" or sport == "443") and p.haslayer(Raw):
            payload = bytes(p[Raw].load)
            # Check for TLS Handshake (0x16) and Client Hello (0x01)
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                sni = _extract_tls_sni(payload)
                if sni:
                    events.append(
                        {
                            "event_id": f"tls_{idx}",
                            "timestamp": ts,
                            "timestamp_utc": ts_utc_str,
                            "source": f"Network PCAP ({path.name})",
                            "source_type": SOURCE,
                            "artifact_type": "TLS Connection (SNI)",
                            "event_type": "network_flow",
                            "user": "",
                            "actor": src_ip,
                            "host": "",
                            "process": "",
                            "pid": "",
                            "action": f"TLS Handshake ({sni})",
                            "object": sni,
                            "target": sni,
                            "path": "",
                            "source_path": "",
                            "destination_path": "",
                            "source_ip": src_ip,
                            "source_port": sport,
                            "destination_ip": dst_ip,
                            "destination_port": dport,
                            "description": f"TLS SNI Handshake | Domain: {sni} | {src_ip}:{sport} → {dst_ip}:{dport}",
                            "raw_data": json.dumps({"sni": sni, "src": src_ip, "dst": dst_ip, "port": dport}),
                            "parser_name": "pcap_tls",
                            "source_file": path.name,
                            "time_kind": "event",
                            "observation_time": "",
                        }
                    )
                    continue

        # 3. HTTP Request Extraction
        if TCP in p and p.haslayer(Raw):
            raw_bytes = bytes(p[Raw].load)
            for verb in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"CONNECT "):
                if raw_bytes.startswith(verb):
                    try:
                        first_line = raw_bytes.split(b"\r\n")[0].decode(errors="ignore")
                        host_hdr = ""
                        for line in raw_bytes.split(b"\r\n")[1:]:
                            if line.lower().startswith(b"host:"):
                                host_hdr = line.split(b":", 1)[1].strip().decode(errors="ignore")
                                break
                        http_target = f"{host_hdr}{first_line.split()[1]}" if host_hdr else first_line
                        events.append(
                            {
                                "event_id": f"http_{idx}",
                                "timestamp": ts,
                                "timestamp_utc": ts_utc_str,
                                "source": f"Network PCAP ({path.name})",
                                "source_type": SOURCE,
                                "artifact_type": "HTTP Request",
                                "event_type": "url_visit" if "GET" in first_line else "network_flow",
                                "user": "",
                                "actor": src_ip,
                                "host": host_hdr,
                                "process": "",
                                "pid": "",
                                "action": f"HTTP {first_line.split()[0]}",
                                "object": http_target,
                                "target": http_target,
                                "path": first_line.split()[1] if len(first_line.split()) > 1 else "",
                                "source_path": "",
                                "destination_path": "",
                                "source_ip": src_ip,
                                "source_port": sport,
                                "destination_ip": dst_ip,
                                "destination_port": dport,
                                "description": f"HTTP Request | {first_line} | Host: {host_hdr} | Client: {src_ip}",
                                "raw_data": json.dumps({"request": first_line, "host": host_hdr, "src": src_ip, "dst": dst_ip}),
                                "parser_name": "pcap_http",
                                "source_file": path.name,
                                "time_kind": "event",
                                "observation_time": "",
                            }
                        )
                    except Exception:
                        pass
                    break

        # 4. Connection Flow (Aggregated by flow key)
        flow_key = (src_ip, sport, dst_ip, dport, proto)
        if flow_key not in seen_flows:
            seen_flows.add(flow_key)
            events.append(
                {
                    "event_id": f"flow_{idx}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc_str,
                    "source": f"Network PCAP ({path.name})",
                    "source_type": SOURCE,
                    "artifact_type": "Network Flow",
                    "event_type": "network_flow",
                    "user": "",
                    "actor": src_ip,
                    "host": "",
                    "process": "",
                    "pid": "",
                    "action": f"{proto} Connection",
                    "object": f"{dst_ip}:{dport}",
                    "target": f"{dst_ip}:{dport}",
                    "path": "",
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": src_ip,
                    "source_port": sport,
                    "destination_ip": dst_ip,
                    "destination_port": dport,
                    "description": f"{proto} Flow | {src_ip}:{sport} → {dst_ip}:{dport}",
                    "raw_data": json.dumps({"proto": proto, "src_ip": src_ip, "src_port": sport, "dst_ip": dst_ip, "dst_port": dport}),
                    "parser_name": "pcap_flow",
                    "source_file": path.name,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )

    return events[:500]


def _extract_tls_sni(payload: bytes) -> str:
    """Extract Server Name Indication (SNI) string from TLS Client Hello packet."""
    try:
        pos = 43  # Skip record header (5) + handshake header (4) + client version (2) + random (32)
        if len(payload) <= pos:
            return ""
        # Skip session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        # Skip cipher suites
        if len(payload) <= pos + 2:
            return ""
        cipher_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cipher_len
        # Skip compression methods
        if len(payload) <= pos + 1:
            return ""
        comp_len = payload[pos]
        pos += 1 + comp_len
        # Extensions length
        if len(payload) <= pos + 2:
            return ""
        ext_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        ext_end = pos + ext_len

        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_data_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0x00:  # Server Name Extension
                if pos + 5 <= len(payload):
                    server_name_len = int.from_bytes(payload[pos + 3 : pos + 5], "big")
                    sni_bytes = payload[pos + 5 : pos + 5 + server_name_len]
                    return sni_bytes.decode("utf-8", errors="ignore")
            pos += ext_data_len
    except Exception:
        pass
    return ""
