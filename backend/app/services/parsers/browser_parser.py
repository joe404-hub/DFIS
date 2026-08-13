import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

SOURCE = "browser"

CHROME_EPOCH = datetime(1601, 1, 1)


def can_parse(path: Path, name: str, suffix: str, hint: str) -> bool:
    return suffix in {".sqlite", ".db"} or name.lower() in {"history", "cookies", "places.sqlite", "downloads"}


def _chrome_time(v):
    if not v:
        return None
    try:
        return CHROME_EPOCH + timedelta(microseconds=int(v))
    except Exception:
        return None


def parse(path: Path) -> list[dict]:
    events = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
    except Exception:
        return events
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "urls" in tables and "visits" in tables:
        q = """
        SELECT urls.url, urls.title, visits.visit_time
        FROM visits JOIN urls ON visits.url = urls.id
        ORDER BY visits.visit_time
        """
        for row in con.execute(q):
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": "url_visit",
                    "timestamp": _chrome_time(row["visit_time"]),
                    "description": f"Browser visit: {row['title'] or ''} {row['url']}",
                    "actor": "browser_user",
                    "target": row["url"],
                    "raw_data": str(dict(row)),
                }
            )
    if "downloads" in tables:
        cols = [c[1] for c in con.execute("PRAGMA table_info(downloads)")]
        target_col = "target_path" if "target_path" in cols else ("current_path" if "current_path" in cols else None)
        start_col = "start_time" if "start_time" in cols else None
        if target_col:
            for row in con.execute(f"SELECT * FROM downloads"):
                d = dict(row)
                events.append(
                    {
                        "source_type": SOURCE,
                        "event_type": "download",
                        "timestamp": _chrome_time(d.get(start_col)) if start_col else None,
                        "description": f"Download: {d.get(target_col)} {d.get('tab_url') or d.get('referrer') or ''}",
                        "actor": "browser_user",
                        "target": str(d.get(target_col) or ""),
                        "raw_data": str(d)[:2000],
                    }
                )
    if "moz_places" in tables:
        for row in con.execute("SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL"):
            ts = datetime(1970, 1, 1) + timedelta(microseconds=row[2]) if row[2] else None
            events.append(
                {
                    "source_type": SOURCE,
                    "event_type": "url_visit",
                    "timestamp": ts,
                    "description": f"Firefox visit: {row[1] or ''} {row[0]}",
                    "actor": "browser_user",
                    "target": row[0],
                    "raw_data": "",
                }
            )
    con.close()
    return events
