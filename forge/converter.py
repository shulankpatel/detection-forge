# forge/converter.py
from __future__ import annotations

from pathlib import Path

# pySigma core may not be installed in all environments (e.g. offline CI bootstrap
# or local dev without the optional dependency). Import defensively so this module
# is always import-safe; convert_rule() raises a clear error if it is actually used
# without pySigma present.
try:
    from sigma.collection import SigmaCollection

    _PYSIGMA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when pySigma is absent
    SigmaCollection = None  # type: ignore[assignment]
    _PYSIGMA_AVAILABLE = False

_BACKENDS = {}

if _PYSIGMA_AVAILABLE:
    try:
        from sigma.backends.splunk import SplunkBackend

        _BACKENDS["splunk"] = (SplunkBackend, "spl")
    except ImportError:
        pass
    try:
        from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend

        _BACKENDS["elastic"] = (LuceneBackend, "ndjson")
    except ImportError:
        pass
    try:
        from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

        _BACKENDS["sentinel"] = (Microsoft365DefenderBackend, "kql")
    except ImportError:
        pass
    # Wazuh: best-effort; falls back to Elastic export if no dedicated backend is installed.

AVAILABLE_BACKENDS = list(_BACKENDS)


def convert_rule(rule, backend_name: str) -> str:
    if not _PYSIGMA_AVAILABLE:
        raise RuntimeError("pySigma is not installed")
    if backend_name not in _BACKENDS:
        raise ValueError(f"backend '{backend_name}' not available; have {AVAILABLE_BACKENDS}")
    backend_cls, _ext = _BACKENDS[backend_name]
    collection = SigmaCollection.from_yaml(rule.path.read_text())
    queries = backend_cls().convert(collection)
    return "\n".join(queries)


def build_all(rules, dist_dir: Path) -> dict[str, int]:
    counts = {}
    if not AVAILABLE_BACKENDS:
        print("[info] no pySigma backends available; skipping conversion")
        return counts
    for backend_name, (_cls, ext) in _BACKENDS.items():
        out_dir = Path(dist_dir) / backend_name
        out_dir.mkdir(parents=True, exist_ok=True)
        for rule in rules:
            try:
                query = convert_rule(rule, backend_name)
            except Exception as exc:  # one bad rule must not abort the whole backend
                print(f"[warn] {rule.id} -> {backend_name}: {exc}")
                continue
            (out_dir / f"{rule.path.stem}.{ext}").write_text(query + "\n")
            counts[backend_name] = counts.get(backend_name, 0) + 1
    return counts
