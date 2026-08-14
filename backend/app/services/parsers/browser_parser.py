"""Browser SQLite Forensic Parser.

Extracts URL visits, search terms, downloads, and cookies from Chrome, Edge,
Brave, Opera, and Firefox SQLite databases regardless of file name.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SOURCE = "browser"

CHROME_EPOCH = datetime(1601, 1, 1)
FIREFOX_EPOCH = datetime(1970, 1, 1)


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if suffix in {".sqlite", ".db", ".sqlite3"}:
        return True
    if name.lower() in {"history", "cookies", "places.sqlite", "downloads", "web data", "login data"}:
        return True
    if hint in {"browser_sqlite", "browser"}:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(16)
            if header.startswith(b"SQLite format 3\x00"):
                return True
    except Exception:
        pass
    return False


def _chrome_time(v: Any) -> tuple[datetime | None, str]:
    """Convert Chrome WebKit microseconds since 1601-01-01 to datetime & ISO UTC."""
    if not v:
        return None, ""
    try:
        n = int(v)
        if n <= 0:
            return None, ""
        dt = CHROME_EPOCH + timedelta(microseconds=n)
        return dt, dt.isoformat() + "Z"
    except Exception:
        return None, ""


def _firefox_time(v: Any) -> tuple[datetime | None, str]:
    """Convert Firefox PRTime microseconds since 1970-01-01 to datetime & ISO UTC."""
    if not v:
        return None, ""
    try:
        n = int(v)
        if n <= 0:
            return None, ""
        dt = FIREFOX_EPOCH + timedelta(microseconds=n)
        return dt, dt.isoformat() + "Z"
    except Exception:
        return None, ""


def parse(path: Path) -> list[dict]:
    """Extract browser forensic events from SQLite database file."""
    events: list[dict] = []

    # Make a temporary copy to avoid locked database files
    temp_dir = tempfile.mkdtemp()
    temp_db = Path(temp_dir) / path.name
    try:
        shutil.copy2(path, temp_db)
        con = sqlite3.connect(str(temp_db))
        con.row_factory = sqlite3.Row
    except Exception:
        # Fallback to direct URI open
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            con.row_factory = sqlite3.Row
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return events

    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        # 1. Chrome / Chromium / Edge / Brave History (urls + visits)
        if "urls" in tables and "visits" in tables:
            events.extend(_parse_chrome_history(con, path.name))

        # 2. Chrome / Edge Downloads
        if "downloads" in tables:
            events.extend(_parse_chrome_downloads(con, path.name))

        # 3. Chrome / Edge Search Queries
        if "keyword_search_terms" in tables and "urls" in tables:
            events.extend(_parse_chrome_searches(con, path.name))

        # 4. Chrome / Edge Cookies
        if "cookies" in tables:
            events.extend(_parse_chrome_cookies(con, path.name))

        # 5. Firefox Places (moz_places + moz_historyvisits)
        if "moz_places" in tables:
            events.extend(_parse_firefox_places(con, path.name))

        # 6. Firefox Cookies
        if "moz_cookies" in tables:
            events.extend(_parse_firefox_cookies(con, path.name))

    finally:
        try:
            con.close()
        except Exception:
            pass
        shutil.rmtree(temp_dir, ignore_errors=True)

    return events


def _parse_chrome_history(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    # Query dynamically to support both full Chrome schema and minimal synthetic schemas
    try:
        url_cols = {c[1] for c in con.execute("PRAGMA table_info(urls)")}
        visit_cols = {c[1] for c in con.execute("PRAGMA table_info(visits)")}

        url_fk = "url" if "url" in visit_cols else ("url_id" if "url_id" in visit_cols else "url")
        time_col = "visit_time" if "visit_time" in visit_cols else ("time" if "time" in visit_cols else None)

        if not time_col:
            return events

        q = f"""
        SELECT urls.id as u_id, urls.url as u_url,
               {'urls.title' if 'title' in url_cols else "''"} as u_title,
               {'urls.visit_count' if 'visit_count' in url_cols else '1'} as u_vcount,
               visits.{time_col} as v_time
        FROM visits
        JOIN urls ON visits.{url_fk} = urls.id
        ORDER BY visits.{time_col} ASC
        """
        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = _chrome_time(d.get("v_time"))
            url = d.get("u_url") or ""
            title = d.get("u_title") or ""
            vcount = d.get("u_vcount", 1)

            events.append(
                {
                    "event_id": f"visit_{d.get('u_id')}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc,
                    "source": f"Chrome History ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Browser History",
                    "event_type": "url_visit",
                    "user": "browser_user",
                    "actor": "browser_user",
                    "host": "",
                    "process": "chrome.exe",
                    "pid": "",
                    "action": "URL Visit",
                    "object": url,
                    "target": url,
                    "path": url,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Browser visit | Title: {title or '(No title)'} | URL: {url} | Visits: {vcount}",
                    "raw_data": json.dumps(d, default=str),
                    "parser_name": "browser_chrome_history",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    except Exception:
        pass
    return events


def _parse_chrome_downloads(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    try:
        cols = {c[1] for c in con.execute("PRAGMA table_info(downloads)")}
        target_col = "target_path" if "target_path" in cols else ("current_path" if "current_path" in cols else ("full_path" if "full_path" in cols else None))
        start_col = "start_time" if "start_time" in cols else ("start" if "start" in cols else None)

        if target_col:
            q = f"SELECT * FROM downloads ORDER BY {start_col or 'id'} ASC"
            for row in con.execute(q):
                d = dict(row)
                ts, ts_utc = _chrome_time(d.get(start_col)) if start_col else (None, "")
                target_path = str(d.get(target_col) or "")
                tab_url = d.get("tab_url") or d.get("referrer") or d.get("site_url") or ""
                bytes_total = d.get("total_bytes", 0)

                events.append(
                    {
                        "event_id": f"download_{d.get('id')}",
                        "timestamp": ts,
                        "timestamp_utc": ts_utc,
                        "source": f"Chrome Downloads ({filename})",
                        "source_type": SOURCE,
                        "artifact_type": "Browser Download",
                        "event_type": "download",
                        "user": "browser_user",
                        "actor": "browser_user",
                        "host": "",
                        "process": "chrome.exe",
                        "pid": "",
                        "action": "File Downloaded",
                        "object": Path(target_path).name or target_path,
                        "target": target_path,
                        "path": target_path,
                        "source_path": tab_url,
                        "destination_path": target_path,
                        "source_ip": "",
                        "source_port": "",
                        "destination_ip": "",
                        "destination_port": "",
                        "description": f"Browser download | File: {target_path} | Source: {tab_url} | Size: {bytes_total} bytes",
                        "raw_data": json.dumps(d, default=str),
                        "parser_name": "browser_chrome_downloads",
                        "source_file": filename,
                        "time_kind": "event",
                        "observation_time": "",
                    }
                )
    except Exception:
        pass
    return events


def _parse_chrome_searches(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    try:
        q = """
        SELECT keyword_search_terms.term, urls.url, urls.last_visit_time
        FROM keyword_search_terms
        JOIN urls ON keyword_search_terms.url_id = urls.id
        ORDER BY urls.last_visit_time ASC
        """
        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = _chrome_time(d.get("last_visit_time"))
            term = d.get("term") or ""
            url = d.get("url") or ""

            events.append(
                {
                    "event_id": f"search_{abs(hash(term)) % 100000}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc,
                    "source": f"Chrome Search ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Browser Search Query",
                    "event_type": "search_query",
                    "user": "browser_user",
                    "actor": "browser_user",
                    "host": "",
                    "process": "chrome.exe",
                    "pid": "",
                    "action": f"Search Query: {term}",
                    "object": term,
                    "target": term,
                    "path": url,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Browser search query | Term: '{term}' | URL: {url}",
                    "raw_data": json.dumps(d, default=str),
                    "parser_name": "browser_chrome_searches",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    except Exception:
        pass
    return events


def _parse_chrome_cookies(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    try:
        cols = {c[1] for c in con.execute("PRAGMA table_info(cookies)")}
        host_col = "host_key" if "host_key" in cols else ("host" if "host" in cols else "domain")
        time_col = "creation_utc" if "creation_utc" in cols else ("creation_time" if "creation_time" in cols else None)

        q = f"SELECT {host_col} as host, name, path, {'creation_utc' if 'creation_utc' in cols else '0'} as creation_utc FROM cookies"
        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = _chrome_time(d.get("creation_utc")) if time_col else (None, "")
            host = d.get("host") or ""
            name = d.get("name") or ""

            events.append(
                {
                    "event_id": f"cookie_{abs(hash(f'{host}:{name}')) % 100000}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc,
                    "source": f"Chrome Cookies ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Browser Cookie",
                    "event_type": "cookie",
                    "user": "browser_user",
                    "actor": "browser_user",
                    "host": host,
                    "process": "chrome.exe",
                    "pid": "",
                    "action": "Cookie Created / Stored",
                    "object": f"{host}:{name}",
                    "target": host,
                    "path": d.get("path") or "",
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Browser cookie created | Host: {host} | Name: {name}",
                    "raw_data": json.dumps(d, default=str),
                    "parser_name": "browser_chrome_cookies",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    except Exception:
        pass
    return events


def _parse_firefox_places(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "moz_historyvisits" in tables:
            q = """
            SELECT moz_places.id, moz_places.url, moz_places.title, moz_places.visit_count,
                   moz_historyvisits.visit_date
            FROM moz_historyvisits
            JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
            ORDER BY moz_historyvisits.visit_date ASC
            """
        else:
            q = "SELECT id, url, title, visit_count, last_visit_date as visit_date FROM moz_places WHERE last_visit_date IS NOT NULL"

        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = _firefox_time(d.get("visit_date"))
            url = d.get("url") or ""
            title = d.get("title") or ""
            vcount = d.get("visit_count", 1)

            events.append(
                {
                    "event_id": f"moz_visit_{d.get('id')}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc,
                    "source": f"Firefox Places ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Browser History",
                    "event_type": "url_visit",
                    "user": "browser_user",
                    "actor": "browser_user",
                    "host": "",
                    "process": "firefox.exe",
                    "pid": "",
                    "action": "URL Visit",
                    "object": url,
                    "target": url,
                    "path": url,
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Firefox visit | Title: {title or '(No title)'} | URL: {url} | Visits: {vcount}",
                    "raw_data": json.dumps(d, default=str),
                    "parser_name": "browser_firefox_places",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    except Exception:
        pass
    return events


def _parse_firefox_cookies(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    try:
        for row in con.execute("SELECT baseDomain, name, path, host, creationTime, isSecure FROM moz_cookies"):
            d = dict(row)
            ts, ts_utc = _firefox_time(d.get("creationTime"))
            domain = d.get("baseDomain") or d.get("host") or ""
            name = d.get("name") or ""

            events.append(
                {
                    "event_id": f"moz_cookie_{abs(hash(f'{domain}:{name}')) % 100000}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc,
                    "source": f"Firefox Cookies ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Browser Cookie",
                    "event_type": "cookie",
                    "user": "browser_user",
                    "actor": "browser_user",
                    "host": domain,
                    "process": "firefox.exe",
                    "pid": "",
                    "action": "Cookie Created / Stored",
                    "object": f"{domain}:{name}",
                    "target": domain,
                    "path": d.get("path") or "",
                    "source_path": "",
                    "destination_path": "",
                    "source_ip": "",
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "description": f"Firefox cookie created | Domain: {domain} | Name: {name}",
                    "raw_data": json.dumps(d, default=str),
                    "parser_name": "browser_firefox_cookies",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    except Exception:
        pass
    return events
