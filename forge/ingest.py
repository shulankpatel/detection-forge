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

import json
import uuid
from pathlib import Path
import yaml

# IOC type -> (selection name, Sigma field expression)
_FIELD_MAP = [
    (("sha256", "sha1", "md5"), "selection_hash", "Hashes|contains"),
    (("cmdline",), "selection_cmdline", "CommandLine|contains"),
    (("filepath",), "selection_file", "Image|endswith"),
    (("regkey",), "selection_registry", "TargetObject|contains"),
    (("domain", "ipv4", "url"), "selection_network", "DestinationHostname|contains"),
]

def _label(source_ref: str) -> str:
    m = re.search(r"https?://([^/]+)", source_ref)
    return m.group(1) if m else source_ref[:40]

def draft_rule(source_ref: str, iocs: dict, attack: list, title=None) -> dict:
    selections = {}
    for types, name, field in _FIELD_MAP:
        values = []
        for t in types:
            values.extend(iocs.get(t, []))
        if values:
            selections[name] = {field: _dedupe(values)}
    if not selections:
        raise ValueError("no actionable indicators found to draft a rule")
    if any(n in selections for n in ("selection_hash", "selection_cmdline", "selection_file")):
        logsource = {"product": "windows", "category": "process_creation"}
    elif "selection_registry" in selections:
        logsource = {"product": "windows", "category": "registry_event"}
    else:
        logsource = {"category": "network_connection"}
    tags = ["ingested.auto-extracted"] + [f"attack.{t.lower()}" for t in attack]
    return {
        "title": title or f"Indicators from {_label(source_ref)}",
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, source_ref)),
        "status": "experimental",
        "description": (
            f"Auto-drafted by `forge ingest` from {source_ref}. "
            "REVIEW REQUIRED: verify the logsource and field mappings."
        ),
        "references": [source_ref],
        "logsource": logsource,
        "detection": {**selections, "condition": "1 of them"},
        "level": "medium",
        "tags": tags,
    }

def make_fixtures(rule: dict):
    detection = rule["detection"]
    positive = {}
    for name, sel in detection.items():
        if name == "condition":
            continue
        for key, vals in sel.items():
            field = key.split("|")[0]
            positive[field] = vals[0] if isinstance(vals, list) else vals
        break  # one satisfied selection is enough for `1 of them`
    return [positive], [{}]  # empty event matches nothing -> does not fire

def ingest(text: str, source_ref: str, out_dir, fixtures_dir) -> dict:
    iocs = extract_iocs(text)
    attack = extract_attack(text)
    rule = draft_rule(source_ref, iocs, attack)
    slug = (re.sub(r"[^a-z0-9]+", "-", _label(source_ref).lower()).strip("-") or "report")[:50]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rule_path = out / f"{slug}.yml"
    banner = (
        f"# AUTO-EXTRACTED by `forge ingest` from {source_ref} - REVIEW REQUIRED.\n"
        "# Indicators were extracted literally from the source; verify logsource\n"
        "# and field mappings before trusting this detection.\n"
    )
    rule_path.write_text(banner + yaml.safe_dump(rule, sort_keys=False))
    pos, neg = make_fixtures(rule)
    fx = Path(fixtures_dir) / rule["id"]
    fx.mkdir(parents=True, exist_ok=True)
    (fx / "positive.json").write_text(json.dumps(pos, indent=2))
    (fx / "negative.json").write_text(json.dumps(neg, indent=2))
    return {"rule": rule_path, "id": rule["id"], "iocs": iocs, "attack": attack}

import html.parser
import urllib.request

_MAX_BYTES = 2_000_000

class _TextExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip = 0
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())

def to_plain_text(raw: str) -> str:
    if "<" in raw and ">" in raw:
        p = _TextExtractor()
        p.feed(raw)
        return "\n".join(p.parts)
    return raw

def load_source(url=None, file=None, text=None):
    provided = [x for x in (url, file, text) if x]
    if len(provided) != 1:
        raise ValueError("provide exactly one of: url, file, text")
    if text:
        return text, "inline-text"
    if file:
        p = Path(file)
        return p.read_text(errors="replace"), str(p)
    req = urllib.request.Request(url, headers={"User-Agent": "detection-forge-ingest"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec - user-supplied URL, local CLI
        return resp.read(_MAX_BYTES).decode("utf-8", errors="replace"), url
