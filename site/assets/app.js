// site/assets/app.js
const PLATFORM_LABELS = { windows: "Windows", aws: "AWS", azure: "Azure" };
const BACKEND_TABS = [
  ["sigma", "Sigma"], ["splunk", "Splunk"], ["sentinel", "Sentinel"],
  ["elastic", "Elastic"], ["wazuh", "Wazuh"], ["tests", "Tests"],
];
let DATA = null;

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function init() {
  try {
    const res = await fetch("data.json");
    DATA = await res.json();
  } catch (e) {
    document.getElementById("catalog").innerHTML =
      '<p class="empty">Could not load data.json. Run <code>python3 -m forge.cli export</code> first.</p>';
    return;
  }
  renderStats(DATA);
  renderFilters(DATA);
  renderCatalog(DATA.detections);
  renderHeatmap(DATA.coverage);
}

function renderStats(data) {
  const s = data.stats;
  document.getElementById("stats").innerHTML = `
    <div class="stat"><span class="num">${s.detections}</span><span class="lbl">Detections</span></div>
    <div class="stat"><span class="num">${s.techniques}</span><span class="lbl">ATT&amp;CK techniques</span></div>
    <div class="stat"><span class="num">${s.backends.length}</span><span class="lbl">SIEM targets</span></div>`;
}

function renderFilters(data) {
  const platforms = ["all", ...new Set(data.detections.map(d => d.platform))];
  const tactics = ["all", ...new Set(data.detections.flatMap(d => d.attack.map(a => a.tactic)))];
  const pf = document.getElementById("filter-platform");
  const tf = document.getElementById("filter-tactic");
  pf.innerHTML = platforms.map(p =>
    `<option value="${esc(p)}">${p === "all" ? "All platforms" : esc(PLATFORM_LABELS[p] || p)}</option>`).join("");
  tf.innerHTML = tactics.map(t =>
    `<option value="${esc(t)}">${t === "all" ? "All tactics" : esc(t)}</option>`).join("");
  pf.addEventListener("change", applyFilters);
  tf.addEventListener("change", applyFilters);
}

function applyFilters() {
  const p = document.getElementById("filter-platform").value;
  const t = document.getElementById("filter-tactic").value;
  renderCatalog(DATA.detections.filter(d =>
    (p === "all" || d.platform === p) &&
    (t === "all" || d.attack.some(a => a.tactic === t))));
}

function renderCatalog(detections) {
  const root = document.getElementById("catalog");
  if (!detections.length) { root.innerHTML = '<p class="empty">No detections match.</p>'; return; }
  root.innerHTML = detections.map((d, i) => cardHTML(d, i)).join("");
  detections.forEach((d, i) => wireCard(d, i));
}

function cardHTML(d, i) {
  const chips = d.attack.map(a => `<span class="chip">${esc(a.id)}</span>`).join("");
  return `
  <article class="card" data-i="${i}">
    <header>
      <span class="platform ${esc(d.platform)}">${esc(PLATFORM_LABELS[d.platform] || d.platform)}</span>
      <span class="level">${esc(d.level)}</span>
    </header>
    <h3>${esc(d.title)}</h3>
    <p class="desc">${esc(d.description)}</p>
    <div class="chips">${chips}</div>
    <div class="tabs" hidden></div>
  </article>`;
}

function wireCard(d, i) {
  const card = document.querySelector(`.card[data-i="${i}"]`);
  const tabsEl = card.querySelector(".tabs");
  card.addEventListener("click", () => {
    if (!tabsEl.hidden) { tabsEl.hidden = true; card.classList.remove("open"); return; }
    tabsEl.innerHTML =
      `<div class="tab-bar">` +
      BACKEND_TABS.map(([k, label], idx) =>
        `<button class="tab-btn${idx === 0 ? " active" : ""}" data-tab="${k}">${label}</button>`).join("") +
      `</div><div class="tab-body"></div>`;
    tabsEl.hidden = false;
    card.classList.add("open");
    tabsEl.addEventListener("click", e => e.stopPropagation());
    const body = tabsEl.querySelector(".tab-body");
    const show = key => { body.innerHTML = tabContent(d, key); wireCopy(body); };
    tabsEl.querySelectorAll(".tab-btn").forEach(btn =>
      btn.addEventListener("click", () => {
        tabsEl.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        show(btn.dataset.tab);
      }));
    show("sigma");
  });
}

function tabContent(d, key) {
  if (key === "sigma") return codeBlock(d.sigma);
  if (key === "tests") {
    return `<h4>Should fire</h4>${codeBlock(JSON.stringify(d.tests.positive, null, 2))}` +
           `<h4>Should NOT fire</h4>${codeBlock(JSON.stringify(d.tests.negative, null, 2))}`;
  }
  const q = d.conversions[key];
  if (!q) return '<p class="note">This conversion is generated during the GitHub Pages build (requires pySigma).</p>';
  return codeBlock(q);
}

function codeBlock(text) {
  return `<div class="codewrap"><button class="copy">Copy</button><pre><code>${esc(text)}</code></pre></div>`;
}

function wireCopy(scope) {
  scope.querySelectorAll(".copy").forEach(btn =>
    btn.addEventListener("click", () => {
      const code = btn.parentElement.querySelector("code").textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(code);
      btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy"), 1200);
    }));
}

function renderHeatmap(coverage) {
  document.getElementById("heatmap").innerHTML = coverage.tactics.map(tactic => {
    const cells = coverage.techniques.filter(t => t.tactic === tactic).map(t =>
      `<div class="cell s${Math.min(t.score, 3)}" title="${esc(t.id)} ${esc(t.name)} — ${t.score} detection(s)">
         <span class="tid">${esc(t.id)}</span><span class="tname">${esc(t.name)}</span></div>`).join("");
    return `<div class="col"><h4>${esc(tactic)}</h4>${cells}</div>`;
  }).join("");
}

document.addEventListener("DOMContentLoaded", init);
