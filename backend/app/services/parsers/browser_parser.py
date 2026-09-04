"""Browser SQLite Forensic Parser.

Extracts URL visits, search terms, downloads, cookies, and autofill records from
Chrome, Edge, Brave, Opera, Firefox, Safari, and custom SQLite databases regardless of file name.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from dateutil import parser as dtp

SOURCE = "browser"

CHROME_EPOCH = datetime(1601, 1, 1)
FIREFOX_EPOCH = datetime(1970, 1, 1)
MAC_EPOCH = datetime(2001, 1, 1)


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    if suffix in {".sqlite", ".db", ".sqlite3"}:
        return True
    if name.lower() in {"history", "cookies", "places.sqlite", "downloads", "web data", "login data", "favicons"}:
        return True
    if hint in {"browser_sqlite", "browser", "sqlite_database"}:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(16)
            if header.startswith(b"SQLite format 3\x00"):
                return True
    except Exception:
        pass
    return False


def parse_browser_timestamp(v: Any) -> tuple[datetime | None, str]:
    """Dynamically parse timestamp in WebKit microseconds, PRTime, Unix seconds/ms, Mac Absolute Time, or ISO string."""
    if v in (None, "", 0, "0"):
        return None, ""
    if isinstance(v, datetime):
        return v.replace(tzinfo=None) if v.tzinfo else v, v.isoformat() + "Z"

    # Numeric timestamp heuristic
    try:
        n = float(v)
        if n > 10**14:  # Chrome WebKit timestamp (microseconds since 1601-01-01)
            dt = CHROME_EPOCH + timedelta(microseconds=n)
            return dt, dt.isoformat() + "Z"
        if n > 10**12:  # Unix timestamp in microseconds or high millisecond
            dt = FIREFOX_EPOCH + timedelta(microseconds=n)
            return dt, dt.isoformat() + "Z"
        if n > 10**10:  # Unix timestamp in milliseconds
            dt = datetime.utcfromtimestamp(n / 1000)
            return dt, dt.isoformat() + "Z"
        if n > 10**8:  # Unix timestamp in seconds
            dt = datetime.utcfromtimestamp(n)
            return dt, dt.isoformat() + "Z"
        if 0 < n < 10**8:  # Mac Cocoa/WebKit seconds since 2001-01-01
            dt = MAC_EPOCH + timedelta(seconds=n)
            return dt, dt.isoformat() + "Z"
    except (ValueError, TypeError):
        pass

    # String date parsing
    try:
        dt = dtp.parse(str(v), fuzzy=True)
        clean_dt = dt.replace(tzinfo=None) if dt.tzinfo else dt
        return clean_dt, clean_dt.isoformat() + "Z"
    except Exception:
        return None, ""


def parse(path: Path) -> list[dict]:
    """Extract browser forensic events from SQLite database file."""
    events, _ = parse_with_diagnostics(path)
    return events


def parse_with_diagnostics(path: Path) -> tuple[list[dict], dict[str, Any]]:
    """Extract browser events and return detailed schema inspection diagnostics."""
    events: list[dict] = []
    diagnostics: dict[str, Any] = {
        "tables": [],
        "row_counts": {},
        "parsers_attempted": [],
        "schema_matched": False,
    }

    # Make a temporary copy to avoid locked database files
    temp_dir = tempfile.mkdtemp()
    temp_db = Path(temp_dir) / path.name
    try:
        shutil.copy2(path, temp_db)
        con = sqlite3.connect(str(temp_db))
        con.row_factory = sqlite3.Row
    except Exception as exc:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            con.row_factory = sqlite3.Row
        except Exception as exc2:
            shutil.rmtree(temp_dir, ignore_errors=True)
            diagnostics["error"] = f"Failed to connect to SQLite: {exc2}"
            return events, diagnostics

    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        diagnostics["tables"] = sorted(tables)

        for t in tables:
            try:
                cnt = con.execute(f"SELECT COUNT(*) FROM `{t}`").fetchone()[0]
                diagnostics["row_counts"][t] = cnt
            except Exception:
                pass

        # 1. Chrome / Chromium / Edge / Brave History (urls + visits or urls standalone)
        if "urls" in tables or "visits" in tables:
            diagnostics["parsers_attempted"].append("chrome_history")
            ch_events = _parse_chrome_history(con, path.name)
            if ch_events:
                events.extend(ch_events)
                diagnostics["schema_matched"] = True

        # 2. Chrome / Edge Downloads
        if "downloads" in tables or "downloads_url_chains" in tables:
            diagnostics["parsers_attempted"].append("chrome_downloads")
            dl_events = _parse_chrome_downloads(con, path.name)
            if dl_events:
                events.extend(dl_events)
                diagnostics["schema_matched"] = True

        # 3. Chrome / Edge Search Queries
        if "keyword_search_terms" in tables and "urls" in tables:
            diagnostics["parsers_attempted"].append("chrome_searches")
            s_events = _parse_chrome_searches(con, path.name)
            if s_events:
                events.extend(s_events)
                diagnostics["schema_matched"] = True

        # 4. Chrome / Edge Cookies
        if "cookies" in tables:
            diagnostics["parsers_attempted"].append("chrome_cookies")
            ck_events = _parse_chrome_cookies(con, path.name)
            if ck_events:
                events.extend(ck_events)
                diagnostics["schema_matched"] = True

        # 5. Firefox Places (moz_places + moz_historyvisits)
        if "moz_places" in tables or "moz_historyvisits" in tables:
            diagnostics["parsers_attempted"].append("firefox_places")
            ff_events = _parse_firefox_places(con, path.name)
            if ff_events:
                events.extend(ff_events)
                diagnostics["schema_matched"] = True

        # 6. Firefox Cookies
        if "moz_cookies" in tables:
            diagnostics["parsers_attempted"].append("firefox_cookies")
            fc_events = _parse_firefox_cookies(con, path.name)
            if fc_events:
                events.extend(fc_events)
                diagnostics["schema_matched"] = True

        # 7. Safari History (history_items + history_visits)
        if "history_items" in tables or "history_visits" in tables:
            diagnostics["parsers_attempted"].append("safari_history")
            safari_events = _parse_safari_history(con, path.name)
            if safari_events:
                events.extend(safari_events)
                diagnostics["schema_matched"] = True

        # 8. Generic SQLite Table Scanner (Fallback for custom browser or activity databases)
        if not events and tables:
            diagnostics["parsers_attempted"].append("generic_sqlite_scanner")
            gen_events = _parse_generic_sqlite_tables(con, path.name, tables)
            if gen_events:
                events.extend(gen_events)
                diagnostics["schema_matched"] = True

    finally:
        try:
            con.close()
        except Exception:
            pass
        shutil.rmtree(temp_dir, ignore_errors=True)

    return events, diagnostics


def _parse_chrome_history(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    
    # Path A: JOIN visits and urls
    if "urls" in tables and "visits" in tables:
        try:
            url_cols = {c[1] for c in con.execute("PRAGMA table_info(urls)")}
            visit_cols = {c[1] for c in con.execute("PRAGMA table_info(visits)")}

            url_fk = "url" if "url" in visit_cols else ("url_id" if "url_id" in visit_cols else "url")
            time_col = "visit_time" if "visit_time" in visit_cols else ("time" if "time" in visit_cols else ("timestamp" if "timestamp" in visit_cols else None))

            if time_col:
                title_expr = "urls.title" if "title" in url_cols else "''"
                vcount_expr = "urls.visit_count" if "visit_count" in url_cols else "1"
                url_expr = "urls.url" if "url" in url_cols else "urls.name"

                q = f"""
                SELECT urls.id as u_id, {url_expr} as u_url,
                       {title_expr} as u_title,
                       {vcount_expr} as u_vcount,
                       visits.{time_col} as v_time
                FROM visits
                JOIN urls ON visits.{url_fk} = urls.id
                ORDER BY visits.{time_col} ASC
                """
                for row in con.execute(q):
                    d = dict(row)
                    ts, ts_utc = parse_browser_timestamp(d.get("v_time"))
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

    # Path B: If visits join yielded 0 events, query urls table directly (using last_visit_time or timestamp)
    if not events and "urls" in tables:
        try:
            url_cols = {c[1] for c in con.execute("PRAGMA table_info(urls)")}
            time_col = None
            for cand in ("last_visit_time", "visit_time", "timestamp", "time", "date", "created"):
                if cand in url_cols:
                    time_col = cand
                    break

            url_expr = "url" if "url" in url_cols else "name"
            title_expr = "title" if "title" in url_cols else "''"
            vcount_expr = "visit_count" if "visit_count" in url_cols else "1"

            q = f"SELECT id, {url_expr} as u_url, {title_expr} as u_title, {vcount_expr} as u_vcount{f', {time_col} as v_time' if time_col else ''} FROM urls"
            for row in con.execute(q):
                d = dict(row)
                raw_time = d.get("v_time") if time_col else None
                ts, ts_utc = parse_browser_timestamp(raw_time) if raw_time else (None, "")
                url = d.get("u_url") or ""
                title = d.get("u_title") or ""
                vcount = d.get("u_vcount", 1)

                events.append(
                    {
                        "event_id": f"url_entry_{d.get('id')}",
                        "timestamp": ts,
                        "timestamp_utc": ts_utc,
                        "source": f"Browser URL Record ({filename})",
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
                        "description": f"Browser URL Record | Title: {title or '(No title)'} | URL: {url} | Visits: {vcount}",
                        "raw_data": json.dumps(d, default=str),
                        "parser_name": "browser_urls_table",
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
        target_col = None
        for cand in ("target_path", "current_path", "full_path", "file_path", "path", "filename", "destination", "target"):
            if cand in cols:
                target_col = cand
                break
        start_col = None
        for cand in ("start_time", "start", "start_date", "time", "timestamp", "created", "creation_time"):
            if cand in cols:
                start_col = cand
                break

        if target_col:
            q = f"SELECT * FROM downloads ORDER BY {start_col or 'id'} ASC"
            for row in con.execute(q):
                d = dict(row)
                ts, ts_utc = parse_browser_timestamp(d.get(start_col)) if start_col else (None, "")
                target_path = str(d.get(target_col) or "")
                tab_url = d.get("tab_url") or d.get("referrer") or d.get("site_url") or d.get("url") or ""
                bytes_total = d.get("total_bytes", d.get("received_bytes", 0))

                events.append(
                    {
                        "event_id": f"download_{d.get('id', abs(hash(target_path)) % 100000)}",
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
                        "object": Path(target_path.replace('\\', '/')).name or target_path,
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
            ts, ts_utc = parse_browser_timestamp(d.get("last_visit_time"))
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
        time_col = "creation_utc" if "creation_utc" in cols else ("creation_time" if "creation_time" in cols else ("timestamp" if "timestamp" in cols else None))

        q = f"SELECT {host_col} as host, name, path, {f'{time_col} as creation_utc' if time_col else '0 as creation_utc'} FROM cookies"
        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = parse_browser_timestamp(d.get("creation_utc")) if time_col else (None, "")
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
        if "moz_historyvisits" in tables and "moz_places" in tables:
            q = """
            SELECT moz_places.id, moz_places.url, moz_places.title, moz_places.visit_count,
                   moz_historyvisits.visit_date
            FROM moz_historyvisits
            JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
            ORDER BY moz_historyvisits.visit_date ASC
            """
        elif "moz_places" in tables:
            q = "SELECT id, url, title, visit_count, last_visit_date as visit_date FROM moz_places WHERE last_visit_date IS NOT NULL"
        else:
            return events

        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = parse_browser_timestamp(d.get("visit_date"))
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
            ts, ts_utc = parse_browser_timestamp(d.get("creationTime"))
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


def _parse_safari_history(con: sqlite3.Connection, filename: str) -> list[dict]:
    events: list[dict] = []
    try:
        q = """
        SELECT history_items.id, history_items.url, history_visits.visit_time, history_visits.title
        FROM history_visits
        JOIN history_items ON history_visits.history_item = history_items.id
        ORDER BY history_visits.visit_time ASC
        """
        for row in con.execute(q):
            d = dict(row)
            ts, ts_utc = parse_browser_timestamp(d.get("visit_time"))
            url = d.get("url") or ""
            title = d.get("title") or ""

            events.append(
                {
                    "event_id": f"safari_visit_{d.get('id')}",
                    "timestamp": ts,
                    "timestamp_utc": ts_utc,
                    "source": f"Safari History ({filename})",
                    "source_type": SOURCE,
                    "artifact_type": "Browser History",
                    "event_type": "url_visit",
                    "user": "browser_user",
                    "actor": "browser_user",
                    "host": "",
                    "process": "safari",
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
                    "description": f"Safari visit | Title: {title or '(No title)'} | URL: {url}",
                    "raw_data": json.dumps(d, default=str),
                    "parser_name": "browser_safari_history",
                    "source_file": filename,
                    "time_kind": "event",
                    "observation_time": "",
                }
            )
    except Exception:
        pass
    return events


def _parse_generic_sqlite_tables(con: sqlite3.Connection, filename: str, tables: set[str]) -> list[dict]:
    """Fallback scanner for custom/alternative SQLite tables with URL/Path/Time columns."""
    events: list[dict] = []
    for t in tables:
        if t.startswith("sqlite_"):
            continue
        try:
            cols = {c[1].lower() for c in con.execute(f"PRAGMA table_info(`{t}`)")}
            url_col = next((c for c in ("url", "target", "path", "uri", "link", "query") if c in cols), None)
            time_col = next((c for c in ("timestamp", "time", "date", "created", "visit_time", "mtime") if c in cols), None)

            if url_col or time_col:
                for row in con.execute(f"SELECT * FROM `{t}` LIMIT 200"):
                    d = dict(row)
                    val = str(d.get(url_col) or d.get("id") or "")
                    ts, ts_utc = parse_browser_timestamp(d.get(time_col)) if time_col else (None, "")

                    events.append(
                        {
                            "event_id": f"sqlite_{t}_{len(events)+1}",
                            "timestamp": ts,
                            "timestamp_utc": ts_utc,
                            "source": f"SQLite [{t}] ({filename})",
                            "source_type": SOURCE,
                            "artifact_type": "Database Record",
                            "event_type": "url_visit" if "http" in val.lower() else "data_entry",
                            "user": "analyst",
                            "actor": "analyst",
                            "host": "",
                            "process": "",
                            "pid": "",
                            "action": f"SQLite Table Record ({t})",
                            "object": val,
                            "target": val,
                            "path": val,
                            "source_path": "",
                            "destination_path": "",
                            "source_ip": "",
                            "source_port": "",
                            "destination_ip": "",
                            "destination_port": "",
                            "description": f"SQLite Table [{t}] Record: {val}",
                            "raw_data": json.dumps(d, default=str),
                            "parser_name": "generic_sqlite_scanner",
                            "source_file": filename,
                            "time_kind": "event",
                            "observation_time": "",
                        }
                    )
        except Exception:
            continue
    return events
