# Live demo: Elastic + Atomic Red Team (optional)

> **This runbook is OPTIONAL and is NOT part of CI.** The repository's automated
> backbone (rule validation + per-rule fixture tests + conversion) runs entirely
> in CI with no infrastructure. This walkthrough exists only to produce "live SIEM"
> evidence — real attack telemetry triggering the bundled detections in Kibana — for
> a demo or write-up. It requires Docker and a Windows test host you are willing to
> run attack simulations on.

The detections in this demo (`T1059.001` encoded PowerShell, `T1003.001` LSASS
access) rely on **Sysmon** process-creation / process-access events. Make sure
[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) and an Elastic
agent/Winlogbeat are forwarding Windows logs from the test host into the Elastic stack
below before you expect alerts to fire.

## Prerequisites

- Docker (with enough memory allocated — Elasticsearch wants ~2 GB).
- A **disposable Windows VM** for the attack simulations (never run Atomic Red Team on a machine you care about).
- Sysmon installed on the Windows VM, with logs shipped into the Elastic stack (Elastic Agent or Winlogbeat).
- The converted Elastic rules in `dist/elastic/*.ndjson`. Generate them with the backends installed:

  ```bash
  pip install -r requirements-backends.txt
  python3 -m forge.cli build      # writes dist/elastic/*.ndjson
  ```

## 1. Start single-node Elasticsearch + Kibana

Create a Docker network and run a single-node Elasticsearch and a matching Kibana.
(Security is disabled here purely to keep the demo short — do **not** do this outside
a throwaway lab.)

```bash
docker network create forge-demo

docker run -d --name forge-es --net forge-demo \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms1g -Xmx1g" \
  docker.elastic.co/elasticsearch/elasticsearch:8.14.1

docker run -d --name forge-kibana --net forge-demo \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://forge-es:9200" \
  docker.elastic.co/kibana/kibana:8.14.1
```

Wait until Elasticsearch answers and Kibana is up:

```bash
curl -s http://localhost:9200 | grep cluster_name      # ES is ready
# Then open Kibana in a browser:
open http://localhost:5601                              # macOS (or just browse to it)
```

## 2. Import the converted detection rules

The Elastic backend emits detection rules as NDJSON (`dist/elastic/*.ndjson`), which is
exactly the format Kibana's Security app imports.

In Kibana: **Security → Rules → Detection rules (SIEM) → Import rules**, then upload the
files from `dist/elastic/` (start with `powershell_encoded_command.ndjson` and
`lsass_credential_access.ndjson`). After import, open each rule and **Enable** it.

> If your Kibana version offers no Security/Rules UI (e.g. a Basic license without the
> security trial enabled), start the 30-day trial under **Stack Management → License
> management**, or load the rules via the detection-engine API
> (`POST /api/detection_engine/rules/_import`) with an NDJSON file.

## 3. Install Atomic Red Team and run matching atomics

On the **disposable Windows VM**, in an elevated PowerShell session, install the
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) framework:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module Invoke-AtomicRedTeam
```

Run one or two atomics that map to the bundled detections:

```powershell
# T1059.001 — encoded PowerShell command (fires the "Encoded PowerShell" rule)
Invoke-AtomicTest T1059.001 -ShowDetails        # review what it will do first
Invoke-AtomicTest T1059.001 -TestNumbers 1      # run a single test

# T1003.001 — LSASS memory access (fires the "LSASS credential access" rule)
Invoke-AtomicTest T1003.001 -ShowDetails
Invoke-AtomicTest T1003.001 -TestNumbers 1      # e.g. dumping LSASS via comsvcs/procdump
```

> Some T1003.001 atomics download tooling (procdump, Mimikatz) that endpoint AV will
> quarantine. In a lab, either exclude the Atomics folder from AV or pick an atomic that
> uses a built-in technique. The goal is only to generate an LSASS process-access event
> with a high-privilege access mask.

After running, clean up any atomic-created artifacts:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

## 4. View and screenshot the alert in Kibana

Give the Elastic agent/Winlogbeat a minute to ship the Sysmon events and the detection
engine a rule-interval to evaluate them. Then in Kibana:

**Security → Alerts.** You should see alerts for **PowerShell Encoded Command Execution**
and/or **LSASS Memory Credential Access**. Open an alert to inspect the matched event
fields (`process.command_line`, `winlog.event_data.GrantedAccess`, etc.).

Take a screenshot of the firing alert for your write-up and save it to
`docs/img/attack-coverage.png` (or another name of your choosing).

## 5. Teardown

```bash
docker rm -f forge-kibana forge-es
docker network rm forge-demo
```

And on the Windows VM, revert it to a clean snapshot (recommended) or confirm the
`-Cleanup` steps above ran.
