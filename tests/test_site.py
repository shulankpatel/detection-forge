# tests/test_site.py
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"

def test_index_references_assets():
    html = (SITE / "index.html").read_text()
    assert "assets/app.js" in html
    assert "assets/styles.css" in html
    for anchor in ("stats", "catalog", "heatmap", "filter-platform", "filter-tactic"):
        assert f'id="{anchor}"' in html, f"missing #{anchor}"

def test_app_fetches_data_and_renders():
    js = (SITE / "assets" / "app.js").read_text()
    assert "data.json" in js
    for fn in ("renderStats", "renderCatalog", "renderHeatmap", "applyFilters"):
        assert fn in js, f"missing {fn}"
