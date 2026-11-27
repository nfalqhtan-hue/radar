# RADAR CTI upgrade: technical report

Date: 27 November 2026. Scope: the upgrade brief "RADAR into a Cyber Threat Intelligence Platform" plus the three-pillar and localisation requirements. The work was an extension of the existing project, done phase by phase, each phase tested and deployed before the next. Plan and audit: `CTI_PLAN.md`.

## 1. Summary of what was delivered

| Feature | Status | Where |
|---|---|---|
| Intelligent risk scoring engine | Live | badges on Home and Alerts, risk sort and filter, breakdown in every vulnerability dialog, distribution on Statistics, formula on About |
| Security-updates pillar (pillar 3) | Live | new page `updates.html`, updates in the Home feed, card on Statistics |
| Security news split from general tech news (pillar 2 balance) | Live | news types `sec` and `gen` |
| Cyber threat trends and analytics | Live | new page `trends.html` |
| Automated daily intelligence report | Live | new page `report.html`, archive `site/reports/` |
| Global cyber threat map | Live | new page `map.html` |
| RADAR AI assistant | Built, then removed at the owner's request | in git history (commit `1299fed`), removed in `266a78d` |

The existing features (agent, Arabic summaries, quality checks, Telegram alerts, CISA KEV handling, search and filters, English version, dark mode, PDF export, hourly deployment) were kept and re-tested.

## 2. Files

Created:
- `site/updates.html`, `site/trends.html`, `site/report.html`, `site/map.html`
- `site/assets/updates.js`, `updates.css`, `trends.js`, `trends.css`, `report.js`, `report.css`, `map.js`, `map.css`, `world.json`
- `quality/build_world_map.py` (one-time converter for the map borders)
- `CTI_PLAN.md`, `CTI_TECHNICAL_REPORT.md`
- Generated every cycle: `site/trends.json`, `site/map.json`, `site/reports/index.json`, `site/reports/YYYY-MM-DD.json`

Modified: `radar_pipeline.py` (+661 lines), `test_pipeline.py` (+196), `update_site.bat` (one line), `.gitignore`, all existing pages and shared assets (`core.js`, `app.css`, `home.js`, `alerts.js`, `dashboard.js`, `about.html`, …).

Local only, not in git: `geo_src/countries-110m.json` (map source), `_work/` (scratch), `backup_phase3/` (database and code backups taken before each phase).

## 3. Backend changes (`radar_pipeline.py`)

- **NVD enrichment.** `parse_nvd` now keeps reference links tagged `Exploit`, `Patch`, `Vendor Advisory` or `Mitigation` (`nvd_refs`), the CWE ids and the NVD analysis status. Stored vulnerabilities were back-filled once (`--backfill-refs`), and the hourly refresh re-checks unanalysed CVEs daily for 30 days, since NVD adds tags later.
- **Risk engine** `risk_score(row, now)`: 0 to 100, reproducible for the same inputs and reference time. Weights: CVSS 35, exploitation 50 (1.0 if in CISA KEV, 0.7 if a public exploit is documented by an NVD `Exploit` tag or the reporting CNA's description, else 0), age and exposure 10 (recency plus attack vector), patch 5 (0 when an official fix is referenced). Unknown factors are removed from both the sum and the total weight. No CVSS and no KEV listing gives "not enough data" instead of a number. Levels: 90+ critical, 70+ high, 40+ medium, below 40 low. The weights were validated against 1,190 stored vulnerabilities and adjusted with the owner (the first version let only KEV items reach "high").
- **Security updates** `fetch_updates` / `parse_update`: official feeds from Chrome Releases, Ubuntu USN, Debian DSA (RSS 1.0 support added to `parse_feed`), Cisco PSIRT, Fortinet PSIRT and Oracle CPU, last 30 days. Each entry becomes kind `update` with type `patch` / `advisory` / `release`, its CVEs, and affected and fixed versions only when the vendor states them. `action` is set when a fixed CVE is in CISA KEV or the vendor reports exploitation. Summaries are built from these facts (`update_summary`), not by the language model. Updates never trigger Telegram alerts.
- **News balance.** The security keyword rule now yields type `sec`, so general tech news (`gen`) is visible. Stored news was reclassified once through `requality` (`QUALITY_VERSION` 10).
- **Trends** `trends()`: daily series for 90 Riyadh days per pillar, hourly series for 48 hours, product and CWE rankings for 1, 7, 30 and 90 days, and coverage dates (days before a source was collected are `null`, never 0). History comes from the new `vuln_history` table, loaded once with `--backfill-history` (47,658 NVD records, metadata only) and then kept current every cycle. KEV additions per day come from the dates in the full CISA catalog.
- **Daily report** `make_reports` / `build_report` / `export_reports`: one report per finished Riyadh day, built at the first cycle after midnight, catching up to 7 missed days, kept 90 days. It stores facts only: counts, top 5 by risk, KEV additions, important updates, security and tech news, and collection health per source (cycles, failures with their error text, records collected).
- **Threat map** `geo_facts` / `threat_map`: a country is placed only when a sentence about an attack states its role: attributed origin ("China-linked hackers") or victim location ("breached a Russian organization", "South Korea's power giant confirms data breach"). The matched words are kept as evidence. No IP geolocation, no company headquarters, no vendor nationality. Everything else is listed as unlocated. Severity is shown only when the story cites a CVE the radar tracks.

## 4. Frontend changes

- `core.js`: risk labels and badge, risk breakdown table and rule-based recommended action in the vulnerability dialog, official NVD links, update fields, new content types, risk column in the PDF export.
- Home: risk badge, "highest risk" sort, risk-level filter, updates in the feed.
- Alerts: risk column, "critical or high risk (70+)" tab, risk sort.
- New pages as listed in section 1. Navigation now has 8 items: الرئيسية، التنبيهات، التحديثات، الإحصائيات، الاتجاهات، التقرير اليومي، الخريطة، عن المشروع.
- All new pages: Arabic RTL by default, English via `?lang=en`, light and dark themes, mobile layout, table views for charts and the map, empty and error states, no external scripts.

## 5. Dependencies, services and integrations

- No new Python packages (standard library only). No JavaScript libraries; charts and the map are plain SVG.
- New public data sources, all free and read-only: the six vendor feeds above. Not used, because no feed a script can read was available: Mozilla advisories, Microsoft MSRC (per-CVE feed, already covered by NVD), Apple security releases, CISA advisories (HTTP 403 for scripts).
- One static data file: Natural Earth 1:110m borders (public domain) via `world-atlas@2.0.2`, downloaded once with the owner's approval and converted to `site/assets/world.json` (127 KB). The site makes no request to any third party at runtime.
- Cost: 0.

## 6. Database changes and migration

All automatic and non-destructive: `migrate()` adds missing columns, and `CREATE TABLE IF NOT EXISTS` adds new tables. No historical record was deleted or overwritten.
- New `items` columns: `refs`, `cwe`, `nvd_status` (risk engine); `utype`, `cves`, `fixed_ver`, `affected_ver`, `vendor_flag`, `product` (updates).
- New tables: `vuln_history(uid, published, score, severity, cwe, system)`, which prunes records older than 120 days, and `reports(day, generated_at, body)`, which keeps 90 days.
- New `meta` key: `kev_added_daily`.
- One-time commands, already run: `python radar_pipeline.py --backfill-refs` and `python radar_pipeline.py --backfill-history`.

## 7. Security

- No secrets in the repository or the site (scan of every tracked file: no token, key, private key or personal email).
- Every page keeps the strict Content-Security-Policy (`script-src 'self'` plus the hash of the one inline theme script, verified on all 8 pages; `connect-src 'self'`). No `innerHTML`, `eval` or `document.write` in any script. All external data is rendered with `textContent`, and every link passes `R.safeUrl` (http/https only).
- Data files scanned for `<script`, `javascript:`, `onerror=`, `<iframe`. The only hit is the text of a CVE description (CVE-2026-131578), rendered as plain text.
- External requests have timeouts. A failed source is recorded per cycle and disclosed in the daily report and on the Updates page.
- `update_site.bat` changed (it now also pushes `trends.json`, `map.json` and `site/reports`). The daily read-only security review task was updated with its new fingerprint (`32c2ad26aedaa1be`) and the new files, so this does not raise a false alarm.

## 8. Testing results (27 November 2026)

- Automated: `python test_pipeline.py` passes **122 checks** (77 before the upgrade). New checks cover risk reproducibility and missing values, severity versus exploitation, update parsing and versions, KEV linkage, no Telegram alerts for updates, trend aggregation with Riyadh days and null coverage, report building, failure disclosure, archive export, and map placement, including a negative test (a company's nationality is not a victim location).
- Live site: all 8 pages, 16 data and asset files and every versioned script and stylesheet return HTTP 200. Published pages and scripts match the repository byte for byte. Zero browser console errors on every page in a fresh tab.
- Regression: search, type filter, clear filters, risk sort, the "new only" switch, the details dialog (open, risk table, link cleanup on close), English mode (no Arabic left in the interface), dark mode, PDF export of Alerts and of the daily report, and no horizontal overflow at 375 px on all 8 pages.
- Links: all internal links resolve. A sample of source links from every content type returns 200; BleepingComputer and TechCrunch answer 403 to scripts but open normally in a browser.
- Agent: the hourly task is Ready, its last run returned 0, the last 4 cycles pushed with no errors in the log, the database integrity check is ok, and there is no duplicate scheduled job.

## 9. Limits and what would need more infrastructure

- **AI assistant with a live model.** GitHub Pages cannot run a model or hide an API key. A real chat model would need a backend: a serverless function with a protected key (a hosted model, possibly with cost and data leaving the machine), or a bot answered by the local Ollama that only works while the PC is on. A data-only assistant was built and then removed at the owner's request.
- **Always-on collection.** The agent runs on a student PC. While it is off nothing updates. NVD and CISA gaps are recovered on the next run, and reports for days the radar did not run are not produced; partial days are disclosed in the report.
- **History depth.** Vulnerability trends cover 90 days from NVD. News and update history only starts when collection started (25 November and 29 October 2026), and longer comparisons become available over time.
- **Map coverage.** Placement depends on explicit wording, so most security news stays unlocated (9 placed, 83 unlocated in the last 30 days).
- **Vendor coverage.** No Microsoft, Apple or Mozilla bulletins (no readable feed). Their vulnerabilities still arrive through NVD.

## 10. Deployment

Nothing extra is needed. The existing pipeline is used:
1. Task Scheduler "Radar hourly update" runs `update_site.bat` at :05 every hour: it runs the agent, then commits and pushes the data files (`data.json`, `details.json`, `events.json`, `stats.json`, `trends.json`, `map.json`, `site/reports/`).
2. GitHub Actions (`.github/workflows/pages.yml`, unchanged) publishes `site/` to GitHub Pages on every push.
3. For a site code change: edit, run `python test_pipeline.py`, bump the `?v=` tag on the changed assets in every page (currently `r6`), and commit and push while the hourly task is not running.
4. To rebuild the map borders, run `python -I quality/build_world_map.py` (needs `geo_src/countries-110m.json`).
5. On a new machine: Python 3, Ollama with `qwen3:8b`, git with push access, the `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` environment variables, and the scheduled task. Copy `radar.db` to keep history; otherwise run the two backfill commands.
