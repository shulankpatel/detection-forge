# Threat Report Ingestion Guide

The **Threat Report Analyzer** is a powerful feature that automatically extracts indicators and generates detection rules from threat intelligence reports, blog posts, and security advisories.

## Getting Started

### 1. Start the web server

```bash
pip install flask
python3 app.py
```

Then visit: **http://localhost:5000**

### 2. Navigate to "Threat report analyzer"

At the top of the page, you'll see the threat analyzer with three input tabs.

## Three Ways to Ingest Threats

### Method 1: Paste a URL

1. Click the **"Paste URL"** tab
2. Enter a threat report URL (e.g., `https://blog.example.com/ransomware-attack-analysis`)
3. Click **"Analyze Threat"**

The tool will:
- Fetch the URL
- Extract plain text (strips HTML)
- Find IOCs and ATT&CK techniques
- Generate a Sigma rule
- Convert to all 4 SIEM backends

### Method 2: Paste Text or HTML

1. Click the **"Paste Text"** tab
2. Copy/paste from a blog post, advisory, or alert
3. Click **"Analyze Threat"**

Example text that works well:
```
The APT group used PowerShell.exe -enc to execute encoded commands.
They also created scheduled tasks for persistence.
IOCs: 192.0.2.50, sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
MITRE ATT&CK: T1059.001, T1053.005
```

### Method 3: Upload a File

1. Click the **"Upload File"** tab
2. Select an HTML, TXT, or MD file from your computer
3. Click **"Analyze Threat"**

## What You Get

After analysis, you'll see:

### Rule Metadata
- Rule title (auto-generated from the threat report)
- Rule ID (deterministic UUID based on source URL)
- Detection level (low, medium, high, critical)
- Logsource (what logs to monitor)

### Extracted IOCs
- **hashes** (MD5, SHA1, SHA256)
- **domains** (C2 servers, malicious sites)
- **IPs** (attacker infrastructure)
- **urls** (malicious links)
- **emails** (phishing addresses)
- **filepaths** (dropped files)
- **registry keys** (persistence mechanisms)
- **cmdline** (command-line indicators)
- **CVEs** (vulnerabilities exploited)

### ATT&CK Techniques
Extracted technique IDs automatically mapped from the text.

### Generated Detections

Six tabs show the auto-generated rule in different formats:

1. **Sigma** — The canonical Sigma YAML rule
2. **Splunk** — SPL search query
3. **Sentinel** — KQL (Azure) query
4. **Elastic** — Elasticsearch detection rule
5. **Wazuh** — Native Wazuh XML rule
6. **Compliance** — NIST 800-53 & SOC 2 controls

Each tab has a **"Copy"** button to copy the query to your clipboard.

## Example Workflow

```
User Input (Threat Report)
         ↓
  [Analyze Threat Button]
         ↓
  IOC Extraction (regex-based)
         ↓
  ATT&CK Technique Extraction
         ↓
  Draft Sigma Rule Generation
         ↓
  Multi-SIEM Conversion
         ↓
  Compliance Mapping
         ↓
[Display Results with Copy Buttons]
         ↓
User: Copy Splunk query → paste into search
User: Copy Sentinel KQL → deploy as analytics rule
User: Copy detection to SIEM
```

## FAQ

### Q: Does it use AI or LLMs?
**A:** No. The feature is **rule-based** using regex patterns. It extracts indicators and ATT&CK technique IDs explicitly stated in the text, not free-form behavioral prose. This keeps it fast, offline-capable, and deterministic.

### Q: How accurate is the extraction?
**A:** It captures:
- ✅ Explicit IOCs (hashes, IPs, domains, CVEs, file paths, registry keys)
- ✅ Explicit ATT&CK IDs (T1234, T1234.001)
- ✅ Command-line indicators (lines mentioning cmd.exe, powershell, etc.)
- ❌ Implicit threats ("attackers used DNS tunneling" → won't extract T1048.003 unless explicitly stated)

### Q: Can I import generated rules directly into my SIEM?
**A:** Yes! The **Sigma** tab shows the canonical rule. You can:
1. Copy it
2. Save as `my_threat.yml`
3. Run `python3 -m forge.cli build` to regenerate all formats
4. Deploy the SIEM-specific queries from `dist/`

### Q: How do I refine the generated rule?
**A:** The rule starts as `status: experimental`. To refine:
1. Save the Sigma YAML
2. Edit the `detection` section to fix field mappings
3. Add/remove IOCs as needed
4. Move to `status: test` or `status: stable`
5. Add test fixtures (positive/negative JSON events)
6. Re-run `python3 -m forge.cli build && pytest`

### Q: Can I use this in production?
**A:** Generated rules are starting points, not production-ready. Always:
1. Review the extracted IOCs
2. Verify the logsource is correct for your environment
3. Add tuning based on your logs
4. Test with real events before deploying
5. Monitor for false positives in your SIEM

## Command-Line Alternative

If you prefer the CLI:

```bash
python3 -m forge.cli ingest https://example.com/threat-report
```

This writes the draft rule to `rules/ingested/` and fixtures to `tests/fixtures/`. Then:

```bash
python3 -m forge.cli build  # Convert to all SIEM formats
pytest                      # Verify the rule fires correctly
```

## Tips & Tricks

1. **Defang IOCs**: The tool automatically "refangs" defanged IOCs:
   - `hxxps://example[.]com` → `https://example.com`
   - `192.0.2[.]50` → `192.0.2.50`
   - `admin@malicious(.com)` → `admin@malicious.com`

2. **Domain Filtering**: Domains found in email addresses or file extensions are automatically excluded (e.g., `evil.exe` won't be treated as a domain).

3. **Multiple Techniques**: If the report mentions multiple techniques (e.g., "T1059.001 and T1053.005"), both will be tagged.

4. **Compliance Mapping**: The generated rule automatically includes NIST 800-53 and SOC 2 controls for its techniques.

---

**Questions?** Check the main [README.md](README.md) or open an issue on GitHub.
