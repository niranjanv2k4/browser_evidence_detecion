import json
import ntpath
import os
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from analysis.core.logger import AnalysisLogger
from analysis.core.models import CookieRecord, DownloadRecord, VisitRecord
from analysis.core.utils import (
    _firefox_seconds_to_string,
    _ms_epoch_to_string,
    firefox_time_to_string,
    read_text_file,
    sha256_file,
)
from analysis.core.constants import FIREFOX_DOWNLOAD_STATES

class DatabaseAccessError(Exception):
    pass


def _with_database(source: str, logger: AnalysisLogger,
                   reader: Callable[[sqlite3.Connection], Any]) -> Tuple[Any, str, Optional[str]]:
    temp_dir = tempfile.mkdtemp(prefix="bfa_ff_")
    try:
        copy_path = os.path.join(temp_dir, os.path.basename(source))
        connection: Optional[sqlite3.Connection] = None
        digest: Optional[str] = None
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
            logger.warning(f"Could not copy {os.path.basename(source)} ({exc}); is Firefox running? "
                           "Trying read-only direct access (recent entries in the -wal file will be missing).")
        if connection is None:
            try:
                uri = Path(source).resolve().as_uri() + "?mode=ro&immutable=1"
                connection, method = sqlite3.connect(uri, uri=True), "direct read-only (immutable, WAL ignored)"
            except sqlite3.Error as exc:
                raise DatabaseAccessError(f"database locked or inaccessible ({exc})")
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        try:
            return reader(connection), method, digest
        except sqlite3.DatabaseError as exc:
            raise DatabaseAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _read_places(connection: sqlite3.Connection, profile: str, logger: AnalysisLogger) -> Dict[str, Any]:
    visits: List[VisitRecord] = []
    visits_table_ok = True

    try:
        for url, title, count, first, last in connection.execute(
                "SELECT p.url, p.title, COUNT(*), MIN(v.visit_date), MAX(v.visit_date) "
                "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id "
                "WHERE p.hidden = 0 GROUP BY p.id"):
            visits.append(VisitRecord(
                url=url or "", title=title or "",
                visit_time=firefox_time_to_string(last),
                first_visit_time=firefox_time_to_string(first),
                visit_count=int(count or 0), profile=profile))
    except sqlite3.Error:
        visits_table_ok = False
        logger.warning(f"'moz_historyvisits' unavailable for {profile}; using last-visit times only.")

    query = ("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE hidden = 0 "
             "AND (visit_count > 0 OR last_visit_date IS NOT NULL)")
    if visits_table_ok:
        query += " AND id NOT IN (SELECT place_id FROM moz_historyvisits)"
    for url, title, count, last in connection.execute(query):
        visits.append(VisitRecord(
            url=url or "", title=title or "",
            visit_time=firefox_time_to_string(last),
            first_visit_time=None,
            visit_count=max(int(count or 0), 1), profile=profile))
    visits.sort(key=lambda v: v.visit_time or "", reverse=True)

    bookmarks = downloads = 0
    try:
        bookmarks = connection.execute(
            "SELECT COUNT(*) FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk "
            "WHERE b.type = 1 AND p.url NOT LIKE 'place:%'").fetchone()[0]
    except sqlite3.Error as exc:
        logger.warning(f"Bookmarks unavailable for {profile}: {exc}")
    try:
        downloads = connection.execute(
            "SELECT COUNT(DISTINCT a.place_id) FROM moz_annos a "
            "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
            "WHERE n.name = 'downloads/destinationFileURI'").fetchone()[0]
    except sqlite3.Error as exc:
        logger.warning(f"Download records unavailable for {profile}: {exc}")

    return {"visits": visits, "bookmarks": int(bookmarks or 0), "downloads": int(downloads or 0),
            "download_records": _read_firefox_downloads(connection, profile, logger)}


def _file_uri_to_path(uri: str) -> str:
    if not uri:
        return ""
    lowered = uri.lower()
    if lowered.startswith("file:///"):
        rest = unquote(uri[8:])
        return rest.replace("/", "\\") if re.match(r"^[A-Za-z]:", rest) else "/" + rest
    if lowered.startswith("file://"):
        return "\\\\" + unquote(uri[7:]).replace("/", "\\")
    return unquote(uri)


def _read_firefox_downloads(connection: sqlite3.Connection, profile: str,
                            logger: AnalysisLogger) -> List[DownloadRecord]:
    try:
        rows = connection.execute(
            "SELECT p.id, p.url, p.title, d.content, d.dateAdded, m.content "
            "FROM moz_places p "
            "JOIN moz_annos d ON d.place_id = p.id AND d.anno_attribute_id = "
            "(SELECT id FROM moz_anno_attributes WHERE name = 'downloads/destinationFileURI') "
            "LEFT JOIN moz_annos m ON m.place_id = p.id AND m.anno_attribute_id = "
            "(SELECT id FROM moz_anno_attributes WHERE name = 'downloads/metaData') "
            "ORDER BY d.dateAdded DESC").fetchall()
    except sqlite3.Error as exc:
        logger.warning(f"Download details unavailable for {profile}: {exc}")
        return []

    starts: Dict[int, Any] = {}
    referrers: Dict[int, str] = {}
    try:
        for place_id, when in connection.execute(
                "SELECT place_id, MAX(visit_date) FROM moz_historyvisits "
                "WHERE visit_type = 7 GROUP BY place_id"):
            starts[place_id] = when
        for place_id, ref_url in connection.execute(
                "SELECT v.place_id, p2.url FROM moz_historyvisits v "
                "JOIN moz_historyvisits fv ON fv.id = v.from_visit "
                "JOIN moz_places p2 ON p2.id = fv.place_id "
                "WHERE v.visit_type = 7 ORDER BY v.visit_date"):
            referrers[place_id] = ref_url or ""
    except sqlite3.Error:
        logger.warning(f"Download visit/referrer data unavailable for {profile}.")

    records: List[DownloadRecord] = []
    for place_id, url, title, destination, added, meta_text in rows:
        meta: Dict[str, Any] = {}
        if meta_text:
            try:
                parsed = json.loads(meta_text)
                meta = parsed if isinstance(parsed, dict) else {}
            except ValueError:
                logger.warning(f"Unreadable download metadata for {profile} (place {place_id}).")
        target = _file_uri_to_path(destination or "")
        name = ntpath.basename(target) or os.path.basename(urlparse(url or "").path) or "(unknown)"
        state = meta.get("state")
        try:
            size = int(meta.get("fileSize") or 0)
        except (TypeError, ValueError):
            size = 0
        extra: Dict[str, str] = {}
        if title:
            extra["Page Title"] = title
        added_text = firefox_time_to_string(added)
        if added_text:
            extra["Annotation Added"] = added_text
        if "deleted" in meta:
            extra["File Deleted"] = "Yes" if meta.get("deleted") else "No"
        if meta.get("reputationCheckVerdict"):
            extra["Reputation Verdict"] = str(meta["reputationCheckVerdict"])
        records.append(DownloadRecord(
            download_id=place_id, file_name=name, target_path=target, url=url or "",
            referrer=referrers.get(place_id, ""),
            start_time=firefox_time_to_string(starts.get(place_id)) or added_text,
            end_time=_ms_epoch_to_string(meta.get("endTime")),
            total_bytes=max(size, 0),
            state=(FIREFOX_DOWNLOAD_STATES.get(state, f"Unknown ({state})")
                   if state is not None else "Unknown (no metadata)"),
            profile=profile, extra=extra))
    return records


def _count_extensions(profile_path: str, profile: str, logger: AnalysisLogger) -> int:
    path = os.path.join(profile_path, "extensions.json")
    text, error = read_text_file(path)
    if error:
        if error != "file not found":
            logger.warning(f"extensions.json unavailable for {profile}: {error}")
        return 0
    try:
        addons = json.loads(text).get("addons")
        return len(addons) if isinstance(addons, list) else 0
    except (ValueError, AttributeError):
        logger.warning(f"extensions.json is not valid JSON for {profile}.")
        return 0


def _read_firefox_cookies(connection: sqlite3.Connection, profile: str) -> List[CookieRecord]:
    records = []
    try:
        for host, name, path, creation, expiry, secure, httponly in connection.execute(
                "SELECT host, name, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookies"):
            records.append(CookieRecord(
                host=host or "", name=name or "", path=path or "",
                creation_time=firefox_time_to_string(creation),
                expiry_time=_firefox_seconds_to_string(expiry),
                is_secure=bool(secure), is_httponly=bool(httponly), profile=profile
            ))
    except sqlite3.Error:
        pass
    return records