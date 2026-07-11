// site/assets/app.js
const PLATFORM_LABELS = { windows: "Windows", aws: "AWS", azure: "Azure" };
const BACKEND_TABS = [
  ["sigma", "Sigma"], ["splunk", "Splunk"], ["sentinel", "Sentinel"],
  ["elastic", "Elastic"], ["wazuh", "Wazuh"], ["compliance", "Compliance"], ["tests", "Tests"],
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
  initIngest();
}

// === Threat Report Ingestion ===
function initIngest() {
  // Tab switching
  document.querySelectorAll(".ingest-tab-btn").forEach(btn =>
    btn.addEventListener("click", () => {
      document.querySelectorAll(".ingest-tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".ingest-tab").forEach(t => t.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
    }));

  // Submit button
  document.querySelector(".ingest-submit").addEventListener("click", analyzeThreats);
}

async function analyzeThreats() {
  const statusDiv = document.getElementById("ingest-status");
  const resultsDiv = document.getElementById("ingest-results");
  statusDiv.innerHTML = "";
  resultsDiv.hidden = true;

  let sourceType, content;
  const activeTab = document.querySelector(".ingest-tab.active");

  if (activeTab.id === "url-tab") {
    const url = document.getElementById("ingest-url").value.trim();
    if (!url) { statusDiv.innerHTML = '<p class="error">Please enter a URL.</p>'; return; }
    sourceType = "url";
    content = url;
  } else if (activeTab.id === "text-tab") {
    const text = document.getElementById("ingest-text").value.trim();
    if (!text) { statusDiv.innerHTML = '<p class="error">Please paste some text.</p>'; return; }
    sourceType = "text";
    content = text;
  } else if (activeTab.id === "file-tab") {
    const file = document.getElementById("ingest-file").files[0];
    if (!file) { statusDiv.innerHTML = '<p class="error">Please select a file.</p>'; return; }
    sourceType = "file";
    const reader = new FileReader();
    reader.onload = async (e) => {
      const base64 = btoa(e.target.result);
      await doIngest(sourceType, base64, file.name, statusDiv, resultsDiv);
    };
    reader.readAsText(file);
    return;
  }

  await doIngest(sourceType, content, null, statusDiv, resultsDiv);
}

async function doIngest(sourceType, content, filename, statusDiv, resultsDiv) {
  statusDiv.innerHTML = '<p class="loading">Analyzing threat report...</p>';

  try {
    const payload = { source: sourceType, content };
    if (filename) payload.filename = filename;

    const res = await fetch("/api/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (data.status !== "success") {
      statusDiv.innerHTML = `<p class="error">Error: ${esc(data.message)}</p>`;
      return;
    }

    statusDiv.innerHTML = `<p class="success">✓ Generated detection rule: <strong>${esc(data.title)}</strong></p>`;
    renderIngestResults(data, resultsDiv);
  } catch (e) {
    statusDiv.innerHTML = `<p class="error">Error: ${esc(e.message)}</p>`;
  }
}

function renderIngestResults(data, resultsDiv) {
  const iocsList = Object.entries(data.iocs)
    .filter(([_, vals]) => vals && vals.length > 0)
    .map(([type, vals]) => `<div><strong>${esc(type)}:</strong> ${vals.slice(0, 5).map(v => `<code>${esc(v)}</code>`).join(" ")}</div>`)
    .join("");

  const techniques = data.attack_techniques.map(t => `<span class="chip">${esc(t)}</span>`).join("");

  const tabs = [
    ["sigma", "Sigma", codeBlock(data.sigma_yaml)],
    ["splunk", "Splunk", codeBlock(data.conversions.splunk)],
    ["sentinel", "Sentinel", codeBlock(data.conversions.sentinel)],
    ["elastic", "Elastic", codeBlock(data.conversions.elastic)],
    ["wazuh", "Wazuh", codeBlock(data.conversions.wazuh)],
    ["compliance", "Compliance", renderComplianceTab(data.compliance)],
  ];

  resultsDiv.innerHTML = `
    <div class="ingest-rule-card">
      <h3>${esc(data.title)}</h3>
      <p>${esc(data.description)}</p>
      <div class="ingest-meta">
        <div><strong>Level:</strong> ${esc(data.level)}</div>
        <div><strong>Rule ID:</strong> <code>${esc(data.rule_id)}</code></div>
        <div><strong>Logsource:</strong> ${esc(JSON.stringify(data.logsource))}</div>
      </div>
      <div><strong>ATT&CK Techniques:</strong><br>${techniques}</div>
      <div><strong>Extracted IOCs:</strong><br>${iocsList || "<p>No IOCs extracted.</p>"}</div>
      <div class="tabs" style="margin-top: 1rem;">
        <div class="tab-bar">
          ${tabs.map(([k, label], i) => `<button class="tab-btn${i === 0 ? " active" : ""}" data-tab="${k}">${label}</button>`).join("")}
        </div>
        <div class="tab-body"></div>
      </div>
    </div>
  `;
  resultsDiv.hidden = false;

  // Wire up result tabs
  const body = resultsDiv.querySelector(".tab-body");
  resultsDiv.querySelectorAll(".tab-btn").forEach((btn, idx) => {
    btn.addEventListener("click", () => {
      resultsDiv.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      body.innerHTML = tabs[idx][2];
      wireCopy(body);
    });
  });
  body.innerHTML = tabs[0][2];
  wireCopy(body);
}

function renderComplianceTab(compliance) {
  return `<div><h4>NIST 800-53</h4><p>${compliance.nist.map(id => `<code>${esc(id)}</code>`).join(" ")}</p><h4>SOC 2</h4><p>${compliance.soc2.map(id => `<code>${esc(id)}</code>`).join(" ")}</p></div>`;
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
      <span class="level" data-level="${esc(d.level)}"${d.level ? "" : " data-empty"}>${esc(d.level)}</span>
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
  if (key === "compliance") {
    const c = d.compliance;
    return `<h4>NIST 800-53</h4><p>${c.nist.map(id => `<code>${esc(id)}</code>`).join(" ")}</p>` +
           `<h4>SOC 2</h4><p>${c.soc2.map(id => `<code>${esc(id)}</code>`).join(" ")}</p>`;
  }
  if (key === "tests") {
    return `<h4>Should fire</h4>${codeBlock(JSON.stringify(d.tests.positive, null, 2))}` +
           `<h4>Should NOT fire</h4>${codeBlock(JSON.stringify(d.tests.negative, null, 2))}`;
  }
  const q = d.conversions[key];
  if (!q) return '<p class="note">This conversion is generated during the GitHub Pages build (requires pySigma).</p>';
  return codeBlock(q);
}

// Lightweight, dependency-free syntax flavor for the code blocks.
// Operates on ALREADY-ESCAPED text, so it cannot introduce markup/XSS, and
// .copy reads code.textContent which strips these spans — copied text stays raw.
function highlight(escaped) {
  return escaped
    // line comments (# ... ) — common in Sigma/SPL
    .replace(/(^|\n)(\s*)(#.*?)(?=\n|$)/g, '$1$2<span class="tok-cmt">$3</span>')
    // double-quoted strings
    .replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)/g, '<span class="tok-str">$1</span>')
    // single-quoted strings
    .replace(/(&#39;(?:[^&]|&(?!#39;))*?&#39;)/g, '<span class="tok-str">$1</span>')
    // YAML/JSON keys at start of a (indented) line, before a colon
    .replace(/(^|\n)(\s*)([\w.$-]+)(\s*:)/g, '$1$2<span class="tok-key">$3</span>$4')
    // technique ids / standalone numbers
    .replace(/\b(T\d{4}(?:\.\d{3})?|\d+(?:\.\d+)?)\b/g, '<span class="tok-num">$1</span>')
    // pipes & key operators (SPL / Sigma condition glue)
    .replace(/(\s)(\||=|\bAND\b|\bOR\b|\bNOT\b|\bby\b|\bwhere\b|\bstats\b)(\s)/g,
             '$1<span class="tok-punc">$2</span>$3');
}

function codeBlock(text) {
  return `<div class="codewrap"><button class="copy">Copy</button><pre><code>${highlight(esc(text))}</code></pre></div>`;
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
