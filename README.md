# Spidy

A local website security assessment agent with a browser dashboard, command-line scans, evidence-based findings, and explicit scope approvals. Python 3.10+; no Python runtime dependencies, API keys, or accounts. It uses **nmap** for service/version detection when installed, and can run an **optional local open-source LLM (via Ollama)** over its findings — both run on your machine; nothing is sent to a hosted AI service.

Spidy 0.3 gives every assessment a **service inventory** (open ports, the services behind them, and the software versions they advertise), broader basic checks, an optional known-vulnerability lookup, and a **PDF report**. See [Service inventory, versions, and known vulnerabilities](#service-inventory-versions-and-known-vulnerabilities).

Spidy 0.2 added a **Write-up** tab with grouped findings, a prioritized action list, testing rationale, and verification steps. The **Email draft** tab generates a professional message you can edit, save locally, copy, or download. It never sends mail. Existing scan history also gets these views; older scans may lack per-check execution tags.

The analysis is local and rule based: it organizes recorded evidence and selects a finite set of checks. It does not invent exploitability, use a language model, or claim to discover every unusual vulnerability.

## Start

```bash
python3 -m spidy serve
```

Open **http://127.0.0.1:8765**. Enter a target, select checks, confirm permission, and start. Scan history is saved in `.spidy/` and survives restarts. Keep the terminal running while using the dashboard. Press Ctrl+C to stop the server. Change the port with `--port 9000`.

Try a fully local demonstration with deliberately insecure fixtures:

```bash
python3 -m spidy demo --data-dir .spidy-demo
```

Click **Load demo target**, confirm permission, and start. The demo supplies form issues, a simulated SQL error, inert input reflection, server metadata, and an external-origin approval request. It runs only on loopback: dashboard on 8765, test target on 8766, additional origin on 8767. These ports must be available. Demo mode enables private-address testing; use `serve` for the normal public-target policy.

## What it checks

| Check | Behavior | Interpretation |
| --- | --- | --- |
| Headers & cookies | Inspect CSP, framing controls, HSTS presence, nosniff, and cookie attributes | Missing hardening controls; application context matters |
| Forms | Inspect form methods, password transport, and conventional CSRF token names | Unsafe password handling or manual-review signals; forms are never POSTed |
| SQL injection signals | Compare a GET baseline against a single-quote mutation | A newly introduced database-error signature is a possible SQL injection, not proven exploitation |
| Input reflection | Submit a unique, inert HTML marker in GET parameters | Unescaped reflection; no executable JavaScript is submitted and XSS is not proven |
| Server exposure | Inspect TLS validation, plaintext HTTP, technology headers, and error/stack-trace signatures | Metadata or possible debug disclosure; no version-based CVE claims |
| Service inventory | TCP connect to 34 common ports (or 113 expanded, or your own list) on the target hostname; read greeting banners from SSH, FTP, mail, and MySQL; collect product/version strings from HTTP headers and markup | Runs in every assessment unless switched off. Reachable database, remote-administration, and plaintext legacy ports become review findings. A port number alone does not prove which software is listening |
| Transport & browser exposure | Inspect the served certificate's expiry, HSTS validity, script policy weaknesses, mixed content, and Basic authentication over plaintext | Observed configuration; one negotiated TLS connection does not enumerate every supported protocol or cipher |
| HTTP method exposure | One OPTIONS request per approved origin; inspect `Allow` | PUT, DELETE, TRACE, CONNECT, or PATCH being advertised deserves an authorization review; the methods are never executed |
| Known vulnerability lookup | Query NIST NVD for up to three detected product/version pairs (on by default; `--no-advisories` to skip) | Candidates to verify, never confirmed vulnerabilities. Only the product and version are sent |
| WAF / CDN detection | Run `wafw00f` against the target (needs the bundled installer) | Names the firewall/CDN in front of the site; a few fingerprinting requests, no exploitation |
| Template vuln scan | Run `nuclei` detection templates against the target, rate-limited (needs the installer; requires active probes) | Known CVEs, misconfigurations, exposures, default creds. Detection only — Spidy never enables code-execution templates. Matches are signals to verify |
| Bounded path discovery | Up to 12 curated guesses for environment files, Git metadata, source/config backups, API descriptions, and diagnostic endpoints; technology hints prioritize the list | Requires recognizable response structure and comparison against a random missing-path control; a 200 status alone is not a finding |
| Cross-origin policy | Compare a normal response with one carrying an arbitrary reserved `.invalid` Origin | CORS reflection is a signal; no credentialed request or cross-origin browser read is performed |
| Redirect validation | Test existing redirect-like GET parameters with a reserved `.invalid` destination | Inspect Location only; destination is never resolved or contacted; intentional outbound-link behavior needs review |

SQL, reflection, CORS, redirect, and HTTP method checks require **Enable active probes**. **Bounded path discovery** is a separate opt-in check with its own path limit and uses the same HTTP request budget. Here, brute-force discovery means a small curated set of path guesses, not login/password guessing or an unrestricted wordlist. The focus text field routes keywords to check categories, which remain editable; it is not a general-purpose language model. Passive mode still sends HTTP GETs to discover pages. Active mode may additionally submit simple GET search/text/number fields. Password and token-bearing forms are excluded. Known destructive route names are skipped, but GET requests can still have side effects on poorly designed sites.

Every finding has a severity, confidence, affected URL, evidence, explanation, suggested remediation, and OWASP reference. The report includes the full request/decision log, failed checks, configured limits, scope decisions, and coverage. Download the PDF report, Markdown, or JSON from the dashboard. No finding does **not** imply no vulnerability.

The write-up groups repeated observations while retaining evidence IDs. **Fix first** highlights clearly observed high-severity configuration problems; **Validate next** contains higher-impact signals that need confirmation; **Hardening** and **Context only** keep lesser observations in perspective. It explains why each selected check was useful, what actually ran, and what was skipped. Sensitive file-discovery findings retain structural evidence, not configuration values, file contents, branch names, or hashes.

Generated email drafts remove all query values, include authorization/sender placeholders, and describe observations without claiming a compromise. Draft edits are local until you send the message yourself using your own email application. The report attachment is also added manually; review it for sensitive URLs and evidence before sharing. Save your draft to preserve edits across browser reloads.

## Service inventory, versions, and known vulnerabilities

The **Inventory** tab and the PDF's "Exposed services and software" section show what answered on the target hostname: each open port, the service and product/version where one was identified, how confident that identification is, and the evidence behind it. Closed and silent ports are listed by number.

- **Port coverage.** Choose *Common* (34 ports), *Expanded* (113), or enter your own, such as `22, 80, 8000-8010` (up to 128). The target URL's own port is always included. UDP and the full 65,535-port range are not covered.
- **Scanner.** When [nmap](https://nmap.org) is installed, Spidy uses `nmap -sV` for service and version detection — the standard tool, and far better than a hand-rolled scan. nmap is given only the target's validated, scope-checked IP with DNS resolution disabled (`-n`), so it never looks up or touches anything but the authorized address. The page crawl runs **before** the port scan so that scanning can't throttle the target and block page retrieval, and nmap is time-bounded (one representative address, ~30s). Behind a CDN/WAF the inventory is slow and low-value — there is no real origin to fingerprint — which the proxy/CDN finding calls out. Without nmap, Spidy falls back to its built-in TCP connect scan plus TLS/banner identification. Disable nmap with `--no-nmap`.
- **Versions.** They come from what the server advertises: `Server` / `X-Powered-By` headers, a WordPress generator tag, jQuery filenames, and SSH, FTP, and MySQL greeting banners. On HTTPS/TLS ports Spidy also completes a TLS handshake (no HTTP request) to confirm the service and read the presented certificate's subject, issuer, and expiry. Servers can hide or fake these, and Linux distributions patch software without changing its version number.
- **Known vulnerabilities.** Every assessment queries [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities) for the detected product/version pairs. Only the product and version go out, for example `nginx 1.18.0`; never the target, its addresses, banners, or page content. Lookups are spaced six seconds apart to respect NVD's public rate limit and cover at most three products and twenty records each, so they add a few seconds to a scan. Results are listed as **candidates to verify**, never confirmed vulnerabilities: version strings can be spoofed or backport-patched, and Spidy does not test exploitability. Untick **Look up known vulnerabilities** (CLI: `--no-advisories`) to keep a scan fully offline except for the target itself.
- **When everything looks open.** If nearly every probed port accepts a connection, or several mutually-exclusive data services (MySQL, PostgreSQL, Redis, Elasticsearch…) all answer on one edge address, a proxy, firewall, or CDN is almost certainly answering for the target. Spidy reports that once, as a single caveat, instead of listing each port as a real exposure — behind a CDN the origin's own ports usually aren't visible from the internet at all.
- **More websites on the same host.** Open web ports and hostnames named in the TLS certificate appear under **Scope requests**. Spidy assesses them only after you confirm you have permission for each one.

### Processes and installed packages

A scan from the outside cannot see which processes a server runs; only someone logged in to that server can. To add this to an assessment, run the collector **on the server you are assessing** and import its output:

```bash
python3 -m spidy host-inventory your-website.com --output host-inventory.json
```

Then use **Inventory → Import host inventory** in the dashboard, or `scan --host-inventory host-inventory.json`. The collector records process names, the Debian/Ubuntu package that owns each executable, and installed package versions (up to 500 processes and 2000 packages). It does not read command-line arguments, environment variables, or memory. On non-Debian systems it records process names only. Run it as root to see other users' processes.

## External tools (nmap, nuclei, wafw00f, …)

Run `bash install-tools.sh` (Linux/macOS) or `install-tools.bat` (Windows) to install common open-source scanners into `./tools/bin` — `nuclei`, `wafw00f`, `httpx`, `katana`, `subfinder`, `naabu`, `ffuf`, `feroxbuster`, `gau`, `amass`, `nikto`, `testssl.sh`, and more. No sudo; delete `./tools` to uninstall.

Spidy finds these in `./tools/bin` (or on PATH) and uses two directly as assessment checks:

- **WAF / CDN detection** (`wafw00f`) — select the check to name the firewall/CDN in front of the site. It appears as a finding and in the inventory.
- **Template vuln scan** (`nuclei`) — select the check *and* enable active probes. Spidy runs nuclei's detection templates against the target with rate limiting (15 req/s by default) and folds each match into the findings. It runs **detection templates only**; Spidy never passes nuclei's code-execution flags. A full template run is thorough but slow (up to a few minutes) and, against a WAF/CDN, will likely be rate-limited — expect fewer results and coordinate testing. These tools resolve DNS themselves, so Spidy's strict address pinning does not cover them; only point them at targets you are clearly authorized to assess.

## Autopilot (the model proposes, you approve)

In the **Deep scans** tab, **Autopilot** lets a local model propose any tool, shell command, script, or manual investigation. There is no proposal allowlist. Built-in tool adapters remain optional shortcuts; custom commands can use other tools, targets, and flags. Review the reasoning and the read-only command, then click **Approve & run**, **Skip**, or **Stop**. There is no command-entry field. Spidy requests structured JSON proposals from Ollama, recovers common proposal-format mistakes and makes up to three model attempts per planning request to repair incomplete replies or replace duplicate actions. If a draft still needs work, **Prepare runnable action** turns it into a fresh proposal to review. Preparation never executes a command; **Approve & run** remains a separate decision. Unknown tools are allowed when the model supplies a complete command.

Each execution requires an explicit human approval tied to a stored, single-use proposal. Planning never executes anything, and the former automatic loop now only proposes a step. Refreshing the page preserves pending proposals. After execution, the model receives the assessment evidence, a working record spanning all saved decisions, and recent command output when proposing the next step; that next step requires its own approval. The **Assessment working record** in the Write-up tab and PDF/Markdown reports records completed work, failed commands, skips, repeated attempts, and findings added. Both planning and model analysis receive this record. Nonzero exit codes and timeouts are recorded as unsuccessful checks; custom command output is never treated as proof of a vulnerability. Previously attempted or declined actions are rejected before they can be queued again. Spidy asks for different work and pauses if the model keeps repeating itself; a pause does not mean the assessment is complete. Simple-command whitespace/quoting differences, equivalent built-in defaults, and ffuf option order or rate-only changes do not bypass this check. Different targets and substantive options remain eligible. The server checks the submitted action again at execution time, so stale or edited approvals cannot rerun recorded work. Deliberate built-in reruns remain available through the manual Deep scans controls.

Custom commands run verbatim in the local system shell, from the Spidy project directory, with the server user's permissions and `tools/bin` on PATH. The approval covers all targets and effects in the displayed command, including local changes. Commands have a five-minute execution timeout; history retains the exit status and up to 64 KB of combined output. Custom output is evidence for human/model review, not automatically classified as vulnerability findings. Built-in adapters still normalize their findings and use their existing target and parameter handling. This removes Spidy's proposal restrictions; the selected model's own behavior is unchanged.

## Deep scans (run more tools after the scan, your parameters)

After the main scan finishes, the **Deep scans** tab lets you run any installed tool against the same target on demand, adjust its parameters, and fold its findings into the assessment — no re-scan needed. Built-in shortcuts: `nuclei` (severity/tags/rate), `wafw00f`, `httpx`, `naabu` (ports/rate), `subfinder`, `katana` (depth), `ffuf` (wordlist/extensions, ships a bundled list), `testssl.sh`, `nikto` (web-server scanner), and `gau` (passive historical URLs from public archives). The catalog is a curated set of detection/recon tools and can be extended with more of the same — custom commands are available separately through human-approved Autopilot proposals. Each run adds normalized findings (deduped against existing ones), so deeper tools surface the higher-severity issues the built-in checks don't. Detection/fingerprinting only — no tool is given exploitation flags. These tools resolve DNS themselves, so only run them against targets you are authorized to assess.

## Local model analysis (optional, open source)

Spidy can run a local open-source LLM over an assessment to produce a write-up specific to the site — what the detected stack and exposures imply together, which items matter most, what to verify, and how to fix. It is **off until you run it**, you **choose the model**, and it stays on your machine.

- Install [Ollama](https://ollama.com) and pull any open model, e.g. `ollama pull llama3.1` (or mistral, qwen, gemma, an uncensored community model — your choice; Spidy calls whatever you select).
- Dashboard: open a finished assessment → **Write-up** tab → **Analyze with a local model**, pick a model, click **Analyze findings**.
- CLI: `python3 -m spidy models` lists installed models; `spidy scan … --llm-model llama3.1` adds the analysis to the report. Point at a non-default Ollama with `--llm-host`.
- Only Spidy's own findings are sent to the local model (query values are redacted first) — never the raw target traffic, and never to a hosted service. Both the write-up and Autopilot allow open-ended assessment proposals, without a tool allowlist or detection-only prompt restriction. Each proposed command or tool invocation needs its own human approval in Autopilot; a write-up cannot execute anything or grant permission. Spidy supplies these instructions explicitly for each model request. This configures the app's behavior; it does not change the model's learned weights or guarantee that it will comply with every request. Treat the output as analysis to verify, not fact.

## Scope behavior

- The initial hostname is approved for standard HTTP and HTTPS, plus the exact port in the target URL. Subdomains are separate. Other ports/origins require explicit approval for HTTP requests.
- Every HTTP request, redirect destination, and port-check hostname is checked against scope before DNS. Out-of-scope HTML links, resource references, form actions, and redirects become approval requests. Spidy never fetches third-party assets automatically.
- Only public IP addresses are accepted by default. Private, loopback, reserved, and link-local answers are rejected, including mixed public/private DNS results. Connections use the validated numeric address directly, preserving TLS hostname verification, to prevent DNS rebinding between validation and connection. Environment proxy settings are ignored.
- **Scope requests → Approve & run follow-up** requires your confirmation of permission for that exact origin. A new scan records the added origin and its parent report. Each follow-up gets a new bounded budget. **Keep blocked** records a denial without network activity; denials carry into follow-up scans. Scope decisions become available after the active scan ends.
- Approval does not forward cookies, authorization headers, or credentials: Spidy does not manage authenticated sessions. Ports are checked only on the original target hostname, not newly approved origins.
- For an authorized private lab, explicitly launch `python3 -m spidy serve --allow-private`. This setting applies to all scans in that process and is never enabled by a target response.

The default assessment is capped at 15 page URLs and 80 HTTP attempts; you can raise the page limit and request budget on the setup form (up to 5000 pages and 50000 requests). Higher values mean more traffic and a greater chance a WAF/CDN throttles the scan. HTTP starts are spaced at least 250 ms apart. Responses are capped at 512 KB and a five-second network deadline; system DNS resolution follows the operating system's resolver timeouts. Input probes cover at most 10 distinct path/parameter sets and three parameters per set. The service inventory probes the selected ports on up to two resolved addresses (at most 256 connections), four at a time, with a 650 ms connect timeout and a 60-second overall limit. Only one assessment runs at a time. Stop requests take effect between operations.

## Command line

```bash
python3 -m spidy scan https://your-authorized-site.example \
  --authorized --checks headers forms server --output assessment.md

python3 -m spidy scan https://your-authorized-site.example \
  --authorized --focus 'SQL injection and forms' --active --max-pages 10

python3 -m spidy scan https://your-authorized-site.example \
  --authorized --checks headers server cors redirects --active \
  --discover --max-paths 8 --output assessment.md --email-output owner-email.txt

python3 -m spidy scan http://127.0.0.1:8000 \
  --authorized --allow-private --checks headers forms --json --output assessment.json

python3 -m spidy scan https://your-authorized-site.example \
  --authorized --port-profile expanded --no-advisories --output assessment.md

python3 -m spidy scan https://your-authorized-site.example \
  --authorized --ports 22,80,443,8000-8010 --host-inventory host-inventory.json

python3 -m spidy scan https://your-authorized-site.example \
  --authorized --no-nmap --llm-model llama3.1 --output assessment.md
```

Every CLI scan writes a PDF next to the report (`assessment.pdf`; choose another path with `--pdf-output`). The service inventory runs unless you pass `--no-inventory`, for engagements where only the web application is in scope.

CLI scans never automatically approve new origins. Open `serve` with the same `--data-dir` to review their reports and approve discoveries. Exit status is 0 for completed scans, 2 for partial/failed/cancelled scans; findings alone do not change the exit status.

Every CLI scan also writes an email draft beside the report (`assessment.email.txt` by default). Use `--email-output` to choose its path. `--discover` enables and selects the discovery category; `--checks discovery` by itself selects the category but does not authorize path guesses without `--discover`.

Optionally install the `spidy` console command with `python3 -m pip install -e .` inside a virtual environment. Installation may fetch build tooling; running directly with `python3 -m spidy` needs no package downloads.

## Limits and local security

Spidy is an initial assessment tool. It does not execute JavaScript, authenticate, inspect application source, identify hidden backend servers behind a CDN, verify business logic, prove SQL injection/XSS/CSRF, enumerate every port, see a server's processes without an owner-run host inventory, confirm that a published advisory applies, or replace a manual penetration test. Header values are checked only as described above, not exhaustively parsed. Some vulnerabilities require browser rendering, authenticated roles, or application-specific tests. Open ports may be on a shared edge or CDN address.

The dashboard binds only to `127.0.0.1`, blocks cross-origin/invalid-Host requests, and requires a per-process token for mutations. It uses no external fonts, scripts, analytics, or hosted AI services. nmap and the optional Ollama model run locally. The only outbound connection besides the target is the NVD lookup; disable it with `--no-advisories` or the dashboard checkbox to stay fully offline. Target-provided text is rendered as text, never as dashboard HTML. It is a single-user local tool, not a remotely exposed multiuser service. Scan bodies and cookie values are not persisted; request URLs and limited evidence can still contain sensitive values. Treat reports as sensitive. Storage directories/files are created with owner-only permissions; downloaded or CLI reports use your normal filesystem permissions. Delete a data directory manually when its reports are no longer needed.

## Tests

```bash
python3 -m unittest discover -s tests -v
node --check spidy/static/app.js  # optional JavaScript syntax check
```

Tests use local HTTP fixtures and mock DNS. They cover scope matching, redirect blocking, external base URLs, private-address rejection, DNS pinning, request budgets, cancellation, passive/active behavior, probe signals, approvals/denials, persistence, reports, and dashboard API protection. No external targets are scanned by the tests.

Inventory tests cover port selection, banner recognition, original-host-only probing, exposure findings, the opt-in advisory lookup (mocked; no test contacts NVD), host-inventory collection and import validation, and PDF structure and redaction.

Additional tests cover discovery signatures, catch-all/soft-404 suppression, path limits, rate-limit handling, redaction, synthetic CORS/redirect probes, grouping, rationale, and local draft persistence.

The checks are informed by the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/), [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), and [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
