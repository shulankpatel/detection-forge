# forge/ingest.py
from __future__ import annotations

import re

# Re-fang common defanging so indicators match.
def _refang(text: str) -> str:
    return (
        text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
        .replace("[:]", ":").replace("hxxps", "https").replace("hxxp", "http")
        .replace("hXXps", "https").replace("hXXp", "http")
    )

# File extensions that the domain regex would otherwise mis-match as TLDs.
_FILE_EXT = {
    "exe", "dll", "php", "ps1", "js", "vbs", "bat", "cmd", "txt", "html", "htm",
    "doc", "docx", "xls", "xlsx", "pdf", "zip", "rar", "png", "jpg", "gif", "py",
    "sys", "bin", "dat", "tmp", "log", "json", "xml", "aspx", "jsp",
}
_CMD_HINTS = (
    "powershell", "cmd.exe", "cmd /", "schtasks", "rundll32", "regsvr32",
    "wscript", "cscript", "mshta", "certutil", "bitsadmin", "wmic", "net use",
)
_PATTERNS = {
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url": r"https?://[^\s\"'<>)\]]+",
    "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "regkey": r"\bHK(?:LM|CU|CR|U|CC)\\[^\s\"'<>]+",
    "filepath": r"\b[A-Za-z]:\\[^\s\"'<>|]+",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
}

def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def extract_attack(text: str) -> list:
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)
    return _dedupe(i.upper() for i in ids)

def extract_iocs(text: str) -> dict:
    text = _refang(text)
    iocs = {}
    for name, pat in _PATTERNS.items():
        iocs[name] = _dedupe(re.findall(pat, text))
    # domains: drop anything whose final label is a known file extension,
    # and drop bare domains already contained in an extracted email (the email
    # already captures that host). URL hosts are kept as standalone domain IOCs.
    blob = " ".join(iocs["email"])
    iocs["domain"] = [
        d for d in iocs["domain"]
        if d.rsplit(".", 1)[-1].lower() not in _FILE_EXT and d not in blob
    ]
    # command lines: whole lines that mention a known shell / LOLBin.
    iocs["cmdline"] = _dedupe(
        ln.strip() for ln in text.splitlines()
        if any(h in ln.lower() for h in _CMD_HINTS) and ln.strip()
    )
    return iocs
