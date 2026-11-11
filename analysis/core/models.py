from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

@dataclass(frozen=True)
class BrowserSpec:
    name: str
    exe_name: str
    system_install_dirs: tuple
    per_user_install_dirs: tuple
    per_user_data_dir: str

@dataclass
class BrowserLocation:
    name: str
    drive: str
    executable_paths: List[str] = field(default_factory=list)
    user_data_dirs: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class BrowserInfo:
    name: str
    version: Optional[str] = None
    version_source: Optional[str] = None
    channel: Optional[str] = None
    executable_path: Optional[str] = None
    installation_path: Optional[str] = None
    executable_exists: bool = False
    install_scope: Optional[str] = None
    install_path_for_hash: Optional[str] = None
    install_hash_candidates: Dict[str, str] = field(default_factory=dict)
    matched_install_hash: Optional[str] = None
    install_hash_match_kind: Optional[str] = None
    user_data_paths: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

@dataclass
class VisitRecord:
    url: str
    title: str
    visit_time: Optional[str]
    profile: str
    first_visit_time: Optional[str] = None
    visit_count: int = 1

@dataclass
class HistoryStatistics:
    history_record_count: int = 0
    total_visits: int = 0
    unique_url_count: int = 0
    unique_domain_count: int = 0
    first_visit: Optional[str] = None
    last_visit: Optional[str] = None

@dataclass
class CookieRecord:
    host: str
    name: str
    path: str
    creation_time: Optional[str]
    expiry_time: Optional[str]
    is_secure: bool
    is_httponly: bool
    profile: str

@dataclass
class DownloadRecord:
    download_id: Optional[int] = None
    guid: str = ""
    file_name: str = ""
    target_path: str = ""
    current_path: str = ""
    url: str = ""
    url_chain: List[str] = field(default_factory=list)
    referrer: str = ""
    site_url: str = ""
    tab_url: str = ""
    tab_referrer_url: str = ""
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    last_access_time: Optional[str] = None
    received_bytes: int = 0
    total_bytes: int = 0
    state: str = "Unknown"
    danger_type: str = "Unknown"
    interrupt_reason: str = "None"
    opened: bool = False
    mime_type: str = ""
    original_mime_type: str = ""
    etag: str = ""
    last_modified: str = ""
    http_method: str = ""
    by_extension: str = ""
    profile: str = ""
    extra: Dict[str, str] = field(default_factory=dict)

@dataclass
class ProfileResult:
    directory_name: str
    path: str
    windows_user: str
    profile_name: str = ""
    display_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    attribution: str = "unattributed"
    attribution_basis: str = ""
    history_db_path: Optional[str] = None
    history_status: str = "Not analyzed"
    history_db_sha256: Optional[str] = None
    visits: List[VisitRecord] = field(default_factory=list)
    visit_count: int = 0
    unique_url_count: int = 0
    unique_domain_count: int = 0
    bookmark_count: int = 0
    download_count: int = 0
    extension_count: int = 0
    statistics: HistoryStatistics = field(default_factory=HistoryStatistics)
    downloads: List[DownloadRecord] = field(default_factory=list)
    cookie_count: int = 0
    cookies: List[CookieRecord] = field(default_factory=list)

@dataclass
class AnalysisResult:
    drive: str
    browser: Optional[BrowserInfo] = None
    profiles: List[ProfileResult] = field(default_factory=list)
    unattributed_profiles: List[ProfileResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    started_utc: Optional[str] = None
    finished_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def websites_visited(self) -> List[Dict[str, Any]]:
        rows = [{"profile": v.profile, "url": v.url, "title": v.title,
                 "visit_time": v.visit_time, "first_visit_time": v.first_visit_time,
                 "visit_count": v.visit_count}
                for p in self.profiles for v in p.visits]
        rows.sort(key=lambda r: r["visit_time"] or "", reverse=True)
        return rows