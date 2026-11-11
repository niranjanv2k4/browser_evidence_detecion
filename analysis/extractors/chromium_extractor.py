import ntpath
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from analysis.core.logger import AnalysisLogger
from analysis.core.models import CookieRecord, DownloadRecord, VisitRecord
from analysis.core.utils import chrome_time_to_string, sha256_file
from analysis.core.constants import (
    _DOWNLOAD_COLUMNS, DANGER_TYPES, DOWNLOAD_STATES, INTERRUPT_REASONS
)

class HistoryAccessError(Exception):
    pass

def _with_history(source: str, logger: AnalysisLogger,
                  reader: Callable[[sqlite3.Connection], Any]) -> Tuple[Any, str, Optional[str]]:
    temp_dir = tempfile.mkdtemp(prefix="bfa_chromium_")
    try:
        copy_path = os.path.join(temp_dir, "History")
        connection: Optional[sqlite3.Connection] = None
        digest: Optional[str] = None
        method = ""
        try:
            shutil.copyfile(source, copy_path)
            digest = sha256_file(copy_path)
            included = []
            for suffix in ("-wal", "-journal"):
                if os.path.isfile(source + suffix):
                    shutil.copyfile(source + suffix, copy_path + suffix)
                    included.append(suffix[1:])
            method = "temporary copy" + (f" + {', '.join(included)}" if included else "")
            connection = sqlite3.connect(copy_path)
        except OSError as exc:
            logger.warning(f"Could not copy History database ({exc}); is browser running? Trying read-only direct access.")
        if connection is None:
            try:
                uri = Path(source).resolve().as_uri() + "?mode=ro&immutable=1"
                connection, method = sqlite3.connect(uri, uri=True), "direct read-only (immutable)"
            except sqlite3.Error as exc:
                raise HistoryAccessError(f"database locked or inaccessible ({exc})")
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        try:
            return reader(connection), method, digest
        except sqlite3.DatabaseError as exc:
            raise HistoryAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def _columns(connection: sqlite3.Connection, table: str) -> set:
    try:
        return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()

def _read_history(connection: sqlite3.Connection, profile: str, logger: AnalysisLogger) -> Dict[str, Any]:
    url_cols = _columns(connection, "urls")
    has_visits = bool(_columns(connection, "visits"))
    hidden = " AND u.hidden = 0" if "hidden" in url_cols else ""
    visits: List[VisitRecord] = []

    if has_visits:
        for url, title, count, first, last in connection.execute(
                "SELECT u.url, u.title, COUNT(*), MIN(v.visit_time), MAX(v.visit_time) "
                "FROM visits v JOIN urls u ON u.id = v.url "
                f"WHERE (v.transition & 255) NOT IN (4, 5){hidden} "
                "GROUP BY u.id"):
            visits.append(VisitRecord(
                url=url or "", title=title or "",
                visit_time=chrome_time_to_string(last),
                first_visit_time=chrome_time_to_string(first),
                visit_count=int(count or 0), profile=profile))
    else:
        logger.warning(f"'visits' table unavailable for {profile}; using last-visit times only.")

    extra = ("SELECT u.url, u.title, u.visit_count, u.last_visit_time FROM urls u "
             "WHERE u.visit_count > 0" + hidden)
    if has_visits:
        extra += " AND u.id NOT IN (SELECT url FROM visits)"
    for url, title, count, last in connection.execute(extra):
        visits.append(VisitRecord(
            url=url or "", title=title or "",
            visit_time=chrome_time_to_string(last),
            first_visit_time=None,
            visit_count=int(count or 0), profile=profile))
    visits.sort(key=lambda v: v.visit_time or "", reverse=True)

    downloads = 0
    try:
        downloads = int(connection.execute("SELECT COUNT(*) FROM downloads").fetchone()[0] or 0)
    except sqlite3.Error as exc:
        logger.warning(f"Download records unavailable for {profile}: {exc}")

    return {"visits": visits, "downloads": downloads,
            "download_records": read_downloads(connection, profile, logger)}

def _enum_label(mapping: Dict[int, str], value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "Unknown"
    return mapping.get(number, f"Unknown ({number})")

def _download_file_name(target: str, current: str, url: str) -> str:
    for path in (target, current):
        if path:
            name = ntpath.basename(path)
            if name:
                return name
    try:
        name = os.path.basename(urlparse(url).path)
    except ValueError:
        name = ""
    return name or "(unknown)"

def read_downloads(connection: sqlite3.Connection, profile_name: str,
                   logger: AnalysisLogger) -> List[DownloadRecord]:
    try:
        available = {row[1] for row in connection.execute("PRAGMA table_info(downloads)")}
    except sqlite3.Error as exc:
        logger.warning(f"Could not inspect downloads table for {profile_name}: {exc}")
        return []
    if not available:
        logger.info(f"{profile_name}: no 'downloads' table in History database.")
        return []

    columns = [c for c in _DOWNLOAD_COLUMNS if c in available]
    query = f"SELECT {', '.join(columns)} FROM downloads"
    if "start_time" in available:
        query += " ORDER BY start_time DESC"

    chains: Dict[int, List[str]] = {}
    try:
        for dl_id, url in connection.execute(
                "SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index"):
            chains.setdefault(dl_id, []).append(url or "")
    except sqlite3.Error:
        logger.warning(f"'downloads_url_chains' unavailable for {profile_name}; "
                       "download source URLs may be missing.")

    records: List[DownloadRecord] = []
    try:
        for values in connection.execute(query):
            row = dict(zip(columns, values))
            chain = chains.get(row.get("id"), [])
            target = row.get("target_path") or ""
            current = row.get("current_path") or ""
            url = chain[-1] if chain else ""
            records.append(DownloadRecord(
                download_id=row.get("id"),
                guid=row.get("guid") or "",
                file_name=_download_file_name(target, current, url),
                target_path=target,
                current_path=current,
                url=url,
                url_chain=chain,
                referrer=row.get("referrer") or "",
                site_url=row.get("site_url") or "",
                tab_url=row.get("tab_url") or "",
                tab_referrer_url=row.get("tab_referrer_url") or "",
                start_time=chrome_time_to_string(row.get("start_time")),
                end_time=chrome_time_to_string(row.get("end_time")),
                last_access_time=chrome_time_to_string(row.get("last_access_time")),
                received_bytes=int(row.get("received_bytes") or 0),
                total_bytes=int(row.get("total_bytes") or 0),
                state=_enum_label(DOWNLOAD_STATES, row.get("state")),
                danger_type=_enum_label(DANGER_TYPES, row.get("danger_type")),
                interrupt_reason=_enum_label(INTERRUPT_REASONS, row.get("interrupt_reason")),
                opened=bool(row.get("opened")),
                mime_type=row.get("mime_type") or "",
                original_mime_type=row.get("original_mime_type") or "",
                etag=row.get("etag") or "",
                last_modified=row.get("last_modified") or "",
                http_method=row.get("http_method") or "",
                by_extension=row.get("by_ext_name") or "",
                profile=profile_name,
            ))
    except sqlite3.Error as exc:
        logger.warning(f"Downloads could not be fully read for {profile_name}: {exc}")
    return records

def _read_cookies(connection: sqlite3.Connection, profile: str) -> List[CookieRecord]:
    records = []
    try:
        for host, name, path, creation, expires, secure, httponly in connection.execute(
                "SELECT host_key, name, path, creation_utc, expires_utc, is_secure, is_httponly FROM cookies"):
            records.append(CookieRecord(
                host=host or "", name=name or "", path=path or "",
                creation_time=chrome_time_to_string(creation),
                expiry_time=chrome_time_to_string(expires),
                is_secure=bool(secure), is_httponly=bool(httponly), profile=profile
            ))
    except sqlite3.Error:
        pass
    return records