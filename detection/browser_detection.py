"""
browser_checker.py  -  Reliable browser executable detector for Windows
========================================================================

Detection logic
---------------
This program uses deterministic, rule-based identification.  There is no
weighted scoring.  A file is classified as a browser executable if and
only if ALL of the following conditions are simultaneously true:

    1. The file is a valid Windows PE executable  (MZ + PE\0\0 signature)
    2. The file is NOT a DLL                      (IMAGE_FILE_DLL flag clear)
    3. The PE subsystem is GUI                    (IMAGE_SUBSYSTEM_WINDOWS_GUI)
    4. The embedded CompanyName matches a known browser vendor
    5. The embedded ProductName matches a known browser product
    6. The embedded OriginalFilename matches a known main launcher filename
    7. The embedded FileDescription matches the browser's own description

If conditions 4 and 5 pass but 6 or 7 fail, the file is classified as a
"browser component" (helper utility, installer, diagnostic tool, etc.).

If none of the conditions match any signature, the file is classified as
"unknown".

Why this works
--------------
Browser vendors ship many executables in the same directory as the main
browser.  These helper executables (chrome_proxy.exe, iediagcmd.exe,
ExtExport.exe, etc.) share the same CompanyName and ProductName as the
browser they belong to, which is why matching CompanyName+ProductName
alone produces false positives.

The OriginalFilename and FileDescription are the key discriminators.
The OriginalFilename is set at compile time and embedded inside the PE
resource section — it does not change when the file is renamed on disk.
The FileDescription for the main browser executable always matches the
browser's product name, while helper tools have unique descriptions
like "Internet Explorer ImpExp FF exporter" or "Brave Browser" with an
OriginalFilename of "chrome_proxy.exe".

Both checks together eliminate false positives without needing arbitrary
numeric weights or keyword-based heuristics.

Usage
-----
    python browser_checker.py                    # scan script directory
    python browser_checker.py C:\\some\\dir       # scan specific directory
    python browser_checker.py --show-all         # include components + unknowns
    python browser_checker.py --no-recursive     # don't scan subdirectories
"""

import argparse
import ctypes
import ctypes.wintypes as wintypes
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ===================================================================
# Data structures
# ===================================================================

@dataclass(frozen=True)
class BrowserSignature:
    """
    Defines the exact conditions for identifying a specific browser.

    Every field is a frozenset of lowercased values.  ALL corresponding
    metadata fields must match for the file to be classified as the
    browser (logical AND of all conditions).
    """
    name: str
    companies: frozenset         # CompanyName values
    products: frozenset          # ProductName values
    launchers: frozenset         # OriginalFilename values for the main exe
    descriptions: frozenset      # FileDescription values for the main exe
    expected_internals: frozenset = frozenset()
    known_signers: frozenset = frozenset()


@dataclass
class PEInfo:
    """Structural characteristics from the PE header."""
    is_valid: bool = False
    is_dll: bool = False
    subsystem: int = 0        # 2 = GUI, 3 = Console
    is_32bit: bool = True
    machine: int = 0


@dataclass
class Detection:
    """Analysis result for a single file."""
    path: Path
    classification: str = "unknown"    # "browser" | "component" | "unknown"
    browser_name: str = ""
    pe_info: PEInfo = field(default_factory=PEInfo)
    metadata: dict = field(default_factory=dict)
    signer: str = ""
    evidence: list = field(default_factory=list)
    disqualifiers: list = field(default_factory=list)


# ===================================================================
# Browser signatures
# ===================================================================
# Each signature defines the EXACT embedded metadata values that
# identify the main browser executable.  Order matters only for the
# Tor/Firefox disambiguation (see note below).

SIGNATURES = [
    # ----------------------------------------------------------
    # Tor Browser  (must come before Firefox)
    #
    # Tor bundles a modified Firefox.  When Tor customises the
    # build, CompanyName is set to "The Tor Project".  If a Tor
    # build retains Mozilla's CompanyName, it is indistinguishable
    # from regular Firefox by metadata alone; in that case it will
    # correctly fall through to the Firefox signature and the
    # Authenticode signer in the evidence output will reveal the
    # Tor origin.
    # ----------------------------------------------------------
    BrowserSignature(
        name="Tor Browser",
        companies=frozenset({
            "the tor project", "the tor project, inc.",
        }),
        products=frozenset({"tor browser", "firefox"}),
        launchers=frozenset({"firefox.exe", "torbrowser.exe"}),
        descriptions=frozenset({"tor browser", "firefox"}),
        expected_internals=frozenset({"firefox", "torbrowser"}),
        known_signers=frozenset({"the tor project, inc"}),
    ),

    BrowserSignature(
        name="Google Chrome",
        companies=frozenset({
            "google llc", "google inc.", "google inc",
        }),
        products=frozenset({"google chrome"}),
        launchers=frozenset({"chrome.exe"}),
        descriptions=frozenset({"google chrome"}),
        expected_internals=frozenset({"chrome_exe"}),
        known_signers=frozenset({"google llc"}),
    ),

    BrowserSignature(
        name="Microsoft Edge",
        companies=frozenset({"microsoft corporation"}),
        products=frozenset({"microsoft edge"}),
        launchers=frozenset({"msedge.exe"}),
        descriptions=frozenset({"microsoft edge"}),
        expected_internals=frozenset({"msedge_exe", "msedge"}),
        known_signers=frozenset({"microsoft corporation"}),
    ),

    BrowserSignature(
        name="Mozilla Firefox",
        companies=frozenset({"mozilla corporation", "mozilla"}),
        products=frozenset({"firefox", "mozilla firefox"}),
        launchers=frozenset({"firefox.exe"}),
        descriptions=frozenset({"firefox"}),
        expected_internals=frozenset({"firefox"}),
        known_signers=frozenset({"mozilla corporation"}),
    ),

    BrowserSignature(
        name="Brave Browser",
        companies=frozenset({
            "brave software, inc.", "brave software",
        }),
        products=frozenset({"brave browser", "brave"}),
        launchers=frozenset({"brave.exe"}),
        descriptions=frozenset({"brave browser", "brave"}),
        expected_internals=frozenset({"brave_exe", "brave"}),
        known_signers=frozenset({"brave software, inc."}),
    ),

    BrowserSignature(
        name="Opera",
        companies=frozenset({
            "opera software", "opera software asa", "opera norway as",
        }),
        products=frozenset({
            "opera", "opera stable", "opera browser",
            "opera gx", "opera gx stable",
        }),
        launchers=frozenset({"opera.exe", "launcher.exe"}),
        descriptions=frozenset({
            "opera internet browser", "opera",
            "opera browser", "opera gx",
        }),
        expected_internals=frozenset({"opera", "launcher"}),
        known_signers=frozenset({
            "opera norway as", "opera software asa",
        }),
    ),

    BrowserSignature(
        name="Internet Explorer",
        companies=frozenset({"microsoft corporation"}),
        products=frozenset({"internet explorer"}),
        launchers=frozenset({"iexplore.exe"}),
        descriptions=frozenset({"internet explorer"}),
        expected_internals=frozenset({"iexplore"}),
        known_signers=frozenset({
            "microsoft windows", "microsoft corporation",
        }),
    ),

    BrowserSignature(
        name="Vivaldi",
        companies=frozenset({
            "vivaldi technologies as", "vivaldi technologies",
        }),
        products=frozenset({"vivaldi", "vivaldi browser"}),
        launchers=frozenset({"vivaldi.exe"}),
        descriptions=frozenset({"vivaldi", "vivaldi browser"}),
        expected_internals=frozenset({"vivaldi_exe", "vivaldi"}),
        known_signers=frozenset({"vivaldi technologies as"}),
    ),
]


# ===================================================================
# PE header parsing
# ===================================================================

IMAGE_FILE_DLL = 0x2000
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3


def parse_pe(path: Path) -> PEInfo:
    """
    Parse the PE header of *path*.
    Returns ``PEInfo`` with ``is_valid=True`` if the file is a valid PE.
    Works regardless of the file extension.
    """
    info = PEInfo()
    try:
        with path.open("rb") as f:
            if f.read(2) != b"MZ":
                return info
            f.seek(0x3C)
            raw = f.read(4)
            if len(raw) != 4:
                return info
            pe_off = struct.unpack("<I", raw)[0]
            f.seek(pe_off)
            if f.read(4) != b"PE\x00\x00":
                return info

            info.is_valid = True

            # COFF header (20 bytes)
            coff = f.read(20)
            if len(coff) < 20:
                return info
            info.machine = struct.unpack_from("<H", coff, 0)[0]
            chars = struct.unpack_from("<H", coff, 18)[0]
            info.is_dll = bool(chars & IMAGE_FILE_DLL)

            # Optional header magic
            opt_start = f.tell()
            magic_raw = f.read(2)
            if len(magic_raw) < 2:
                return info
            info.is_32bit = (struct.unpack("<H", magic_raw)[0] == 0x10B)

            # Subsystem at offset 68 from optional-header start
            f.seek(opt_start + 68)
            sub_raw = f.read(2)
            if len(sub_raw) == 2:
                info.subsystem = struct.unpack("<H", sub_raw)[0]

    except (OSError, ValueError, struct.error):
        pass
    return info


# ===================================================================
# Version-info extraction  (Windows version.dll)
# ===================================================================

def extract_version_info(path: Path) -> dict[str, str]:
    """
    Extract version-resource string fields from a PE file using the
    Windows version.dll API.
    """
    try:
        ver = ctypes.WinDLL("version", use_last_error=True)
    except OSError:
        return {}

    gs = ver.GetFileVersionInfoSizeW
    gs.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint)]
    gs.restype = ctypes.c_uint
    dummy = ctypes.c_uint(0)
    size = gs(str(path), ctypes.byref(dummy))
    if not size:
        return {}

    buf = ctypes.create_string_buffer(size)
    gi = ver.GetFileVersionInfoW
    gi.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint,
        ctypes.c_uint, ctypes.c_void_p,
    ]
    gi.restype = ctypes.c_bool
    if not gi(str(path), 0, size, buf):
        return {}

    qv = ver.VerQueryValueW
    qv.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint),
    ]
    qv.restype = ctypes.c_bool

    def qs(block: str) -> str | None:
        vp, vl = ctypes.c_void_p(), ctypes.c_uint()
        if not qv(buf, block, ctypes.byref(vp), ctypes.byref(vl)):
            return None
        if not vp.value:
            return None
        return ctypes.wstring_at(vp.value)

    # Discover translation blocks
    tp, tl = ctypes.c_void_p(), ctypes.c_uint()
    if not qv(buf, r"\VarFileInfo\Translation",
              ctypes.byref(tp), ctypes.byref(tl)) or not tp.value:
        return {}

    raw = ctypes.string_at(tp.value, tl.value)
    fields = [
        "CompanyName", "ProductName", "ProductVersion",
        "FileDescription", "OriginalFilename", "InternalName",
        "FileVersion",
    ]
    for off in range(0, len(raw), 4):
        if off + 4 > len(raw):
            break
        lang, cp = struct.unpack_from("<HH", raw, off)
        t = f"{lang:04x}{cp:04x}"
        result: dict[str, str] = {}
        for fld in fields:
            v = qs(rf"\StringFileInfo\{t}\{fld}")
            if v:
                result[fld] = v
        if result:
            return result
    return {}


# ===================================================================
# Authenticode signer extraction  (Windows crypt32.dll)
# ===================================================================

def extract_signer(path: Path) -> str:
    """
    Extract the signer display-name from the file's embedded
    Authenticode PKCS#7 signature.  Returns ``""`` if unsigned.
    """
    try:
        c32 = ctypes.WinDLL("crypt32", use_last_error=True)
    except OSError:
        return ""

    c32.CryptQueryObject.argtypes = [
        wintypes.DWORD, ctypes.c_wchar_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    c32.CryptQueryObject.restype = wintypes.BOOL

    enc = wintypes.DWORD()
    ct = wintypes.DWORD()
    ft = wintypes.DWORD()
    store = ctypes.c_void_p()
    msg = ctypes.c_void_p()

    # CERT_QUERY_OBJECT_FILE = 0x1
    # CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
    # CERT_QUERY_FORMAT_FLAG_BINARY = 0x2
    if not c32.CryptQueryObject(
        0x1, str(path), 0x400, 0x2, 0,
        ctypes.byref(enc), ctypes.byref(ct), ctypes.byref(ft),
        ctypes.byref(store), ctypes.byref(msg), None,
    ):
        return ""

    name = ""
    try:
        c32.CertEnumCertificatesInStore.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        c32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
        c32.CertGetNameStringW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD,
        ]
        c32.CertGetNameStringW.restype = wintypes.DWORD

        # CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
        cert = c32.CertEnumCertificatesInStore(store.value, None)
        if cert:
            nb = ctypes.create_unicode_buffer(256)
            c32.CertGetNameStringW(cert, 4, 0, None, nb, 256)
            name = nb.value or ""
            c32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
            c32.CertFreeCertificateContext.restype = wintypes.BOOL
            c32.CertFreeCertificateContext(cert)
    except Exception:
        pass
    finally:
        try:
            if msg.value:
                c32.CryptMsgClose.argtypes = [ctypes.c_void_p]
                c32.CryptMsgClose.restype = wintypes.BOOL
                c32.CryptMsgClose(msg)
        except Exception:
            pass
        try:
            if store.value:
                c32.CertCloseStore.argtypes = [
                    ctypes.c_void_p, wintypes.DWORD,
                ]
                c32.CertCloseStore.restype = wintypes.BOOL
                c32.CertCloseStore(store, 0)
        except Exception:
            pass
    return name


# ===================================================================
# Core identification logic  (rule-based, no scoring)
# ===================================================================

def _subsystem_label(code: int) -> str:
    if code == IMAGE_SUBSYSTEM_WINDOWS_GUI:
        return "GUI"
    if code == IMAGE_SUBSYSTEM_WINDOWS_CUI:
        return "Console"
    return f"Other ({code})"


def identify(
    pe: PEInfo,
    metadata: dict[str, str],
    signer: str,
) -> tuple[str, str, list[str], list[str]]:
    """
    Classify a PE file as ``"browser"``, ``"component"``, or
    ``"unknown"`` using deterministic rules.

    Returns ``(classification, browser_name, evidence, disqualifiers)``.

    A file is identified as a browser if and only if ALL of these pass:

        1. Not a DLL
        2. GUI subsystem
        3. CompanyName matches a known browser vendor
        4. ProductName matches a known browser product
        5. OriginalFilename matches a known main launcher
        6. FileDescription matches the browser's description

    If only gates 3-4 pass, the file is a "component".
    If nothing matches, the file is "unknown".
    """
    company = metadata.get("CompanyName", "").strip().lower()
    product = metadata.get("ProductName", "").strip().lower()
    description = metadata.get("FileDescription", "").strip().lower()
    original = metadata.get("OriginalFilename", "").strip().lower()

    for sig in SIGNATURES:

        # ---- Gate 1-2: Company + Product (hard prerequisite) ----
        if company not in sig.companies or product not in sig.products:
            continue

        # Past this point the file is at least *related* to this browser.
        # Build the evidence list from the raw (un-lowered) metadata.
        version = metadata.get(
            "ProductVersion", metadata.get("FileVersion", "N/A")
        )
        evidence = [
            f"Company Name     : {metadata.get('CompanyName', 'N/A')}",
            f"Product Name     : {metadata.get('ProductName', 'N/A')}",
            f"Original Name    : {metadata.get('OriginalFilename', 'N/A')}",
            f"File Description : {metadata.get('FileDescription', 'N/A')}",
            f"Internal Name    : {metadata.get('InternalName', 'N/A')}",
            f"Version          : {version}",
        ]
        if signer:
            evidence.append(f"Digital Signer   : {signer}")
        evidence.append(
            f"PE Subsystem     : {_subsystem_label(pe.subsystem)}"
        )

        disqualifiers: list[str] = []

        # ---- Gate 3: must not be a DLL ----
        if pe.is_dll:
            disqualifiers.append("File is a DLL, not a standalone executable")
            return "component", sig.name, evidence, disqualifiers

        # ---- Gate 4: must be a GUI application ----
        if pe.subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI:
            disqualifiers.append(
                f"Subsystem is {_subsystem_label(pe.subsystem)}, not GUI "
                f"-- browsers are GUI applications"
            )
            return "component", sig.name, evidence, disqualifiers

        # ---- Gate 5: OriginalFilename must match ----
        if original not in sig.launchers:
            launcher_list = ", ".join(sorted(sig.launchers))
            disqualifiers.append(
                f"OriginalFilename "
                f"'{metadata.get('OriginalFilename', '')}' "
                f"does not match known launcher(s): {launcher_list}"
            )
            return "component", sig.name, evidence, disqualifiers

        # ---- Gate 6: FileDescription must match ----
        if description not in sig.descriptions:
            disqualifiers.append(
                f"FileDescription "
                f"'{metadata.get('FileDescription', '')}' "
                f"does not match the browser's own description"
            )
            return "component", sig.name, evidence, disqualifiers

        # ---- All gates passed ----
        return "browser", sig.name, evidence, []

    # No signature matched at all
    if metadata:
        evidence = [
            f"Company Name     : {metadata.get('CompanyName', 'N/A')}",
            f"Product Name     : {metadata.get('ProductName', 'N/A')}",
            f"File Description : {metadata.get('FileDescription', 'N/A')}",
        ]
    else:
        evidence = ["No version metadata found in this PE file"]

    return "unknown", "", evidence, []


# ===================================================================
# Directory scanner
# ===================================================================

def scan(directory: Path, recursive: bool = True) -> list[Detection]:
    """
    Enumerate files in *directory*, test each for PE validity, extract
    metadata and signer, then classify.
    """
    results: list[Detection] = []
    script_path = Path(__file__).resolve()

    files = sorted(
        directory.rglob("*") if recursive else directory.iterdir()
    )

    for path in files:
        if not path.is_file():
            continue
        if path.resolve() == script_path:
            continue

        pe = parse_pe(path)
        if not pe.is_valid:
            continue

        meta = extract_version_info(path)
        signer = extract_signer(path)
        cls, name, ev, disq = identify(pe, meta, signer)

        results.append(Detection(
            path=path,
            classification=cls,
            browser_name=name,
            pe_info=pe,
            metadata=meta,
            signer=signer,
            evidence=ev,
            disqualifiers=disq,
        ))

    return results


# ===================================================================
# Output formatting
# ===================================================================

# ANSI colour codes (safe: we enable VT processing on Win10+)
_G = "\033[92m"     # green
_R = "\033[91m"     # red
_Y = "\033[93m"     # yellow
_C = "\033[96m"     # cyan
_B = "\033[1m"      # bold
_D = "\033[2m"      # dim
_X = "\033[0m"      # reset


def _bar(width: int = 64) -> None:
    print(f"{_C}{'=' * width}{_X}")


def _heading(text: str) -> None:
    print()
    _bar()
    print(f"  {_B}{text}{_X}")
    _bar()
    print()


def _show_results(
    results: list[Detection],
    show_all: bool = False,
) -> None:
    browsers = [d for d in results if d.classification == "browser"]
    components = [d for d in results if d.classification == "component"]
    unknowns = [d for d in results if d.classification == "unknown"]

    # ---- Browsers ----
    if browsers:
        _heading(f"Browser Executables  ({len(browsers)})")
        for d in browsers:
            name = d.path.name
            orig = d.metadata.get("OriginalFilename", "")
            renamed = orig and name.lower() != orig.lower()

            print(f"  {_G}[BROWSER]{_X}  {_B}{d.browser_name}{_X}")
            print(f"    Path     : {d.path}")
            if renamed:
                print(
                    f"               {_Y}"
                    f"(file renamed -- original: {orig}){_X}"
                )
            print(f"    Evidence :")
            for line in d.evidence:
                print(f"      {line}")
            print()
    else:
        _heading("Browser Executables  (0)")
        print(f"  {_Y}No browser executables found.{_X}")
        print()

    if not show_all:
        # Even in compact mode, mention component/unknown counts
        if components or unknowns:
            print(
                f"  {_D}({len(components)} browser component(s) and "
                f"{len(unknowns)} unknown PE file(s) not shown -- "
                f"use --show-all to display){_X}"
            )
            print()
    else:
        # ---- Components ----
        if components:
            _heading(f"Browser Components  ({len(components)})")
            for d in components:
                print(f"  {_Y}[COMPONENT]{_X}  {_D}{d.path.name}{_X}")
                print(f"    Related to : {d.browser_name}")
                print(f"    Path       : {d.path}")
                desc = d.metadata.get("FileDescription", "")
                if desc:
                    print(f"    Description: {desc}")
                for dq in d.disqualifiers:
                    print(f"    Reason     : {dq}")
                print()

        # ---- Unknown ----
        if unknowns:
            _heading(f"Unknown PE Files  ({len(unknowns)})")
            for d in unknowns:
                print(f"  {_R}[UNKNOWN]{_X}  {_D}{d.path.name}{_X}")
                print(f"    Path : {d.path}")
                for line in d.evidence:
                    print(f"    {line}")
                print()

    # ---- Summary ----
    _bar()
    total = len(results)
    print(f"  PE files scanned  : {total}")
    print(f"  {_G}Browsers        : {len(browsers)}{_X}")
    print(f"  {_Y}Components      : {len(components)}{_X}")
    print(f"  {_R}Unknown         : {len(unknowns)}{_X}")
    _bar()
    print()


# ===================================================================
# Main
# ===================================================================

def main() -> None:
    # Ensure UTF-8 on Windows terminals that default to a legacy codepage
    import io
    if (sys.platform == "win32"
            and hasattr(sys.stdout, "buffer")
            and sys.stdout.encoding
            and sys.stdout.encoding.lower().replace("-", "") != "utf8"):
        try:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace",
            )
        except Exception:
            pass

    # Enable ANSI escape processing on Windows 10+
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description=(
            "Reliable browser executable detector for Windows.  "
            "Examines PE metadata to distinguish browser executables "
            "from helper utilities, regardless of filename."
        ),
    )
    parser.add_argument(
        "directory", nargs="?", type=Path, default=None,
        help="Directory to scan (default: script's own directory)",
    )
    parser.add_argument(
        "--show-all", "-a", action="store_true",
        help="Also display browser components and unknown PE files",
    )
    parser.add_argument(
        "--no-recursive", action="store_true",
        help="Only scan the top-level directory (no subdirectories)",
    )
    args = parser.parse_args()

    scan_dir = (
        args.directory or Path(__file__).resolve().parent
    ).resolve()

    if not scan_dir.is_dir():
        print(
            f"Error: '{scan_dir}' is not a directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    recursive = not args.no_recursive
    mode = "Recursive" if recursive else "Single directory"

    _heading("Browser Executable Detector")
    print(f"  Directory : {scan_dir}")
    print(f"  Mode      : {mode}")

    results = scan(scan_dir, recursive=recursive)

    if not results:
        print()
        print(f"  {_Y}No PE executables found in this directory.{_X}")
        print()
        return

    _show_results(results, show_all=args.show_all)


if __name__ == "__main__":
    main()
