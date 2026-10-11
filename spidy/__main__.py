import argparse
import json
import sys
from pathlib import Path

from .scanner import CHECKS, DEFAULT_CHECKS, Scanner, focus_checks, validate_config
from .server import create_server
from .store import Store, markdown_report
from .analysis import email_draft
from .host_inventory import collect_host, validate_host_inventory
from .pdf_report import pdf_report
from . import llm


def main():
    parser = argparse.ArgumentParser(description="Spidy — scope-aware website security assessments")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("models", help="List the local open models available through Ollama")
    host = sub.add_parser("host-inventory", help="Run on your own server to list its processes and packages for an assessment")
    host.add_argument("target", help="Hostname of the assessment this inventory belongs to")
    host.add_argument("--output", default="spidy-host-inventory.json")
    host.add_argument("--no-packages", action="store_true", help="Record process names only, without dpkg package versions")
    for name in ("serve", "demo", "scan"):
        p = sub.add_parser(name)
        p.add_argument("--data-dir", default=".spidy", help="Local scan history directory")
        if name in ("serve", "demo"):
            p.add_argument("--port", type=int, default=8765)
        if name != "demo":
            p.add_argument("--allow-private", action="store_true", help="Allow private addresses for authorized lab targets")
        if name == "scan":
            p.add_argument("target")
            p.add_argument("--authorized", action="store_true", help="Confirm permission to assess the target")
            p.add_argument("--checks", nargs="+", choices=CHECKS)
            p.add_argument("--focus", default="", help="Keywords such as SQL, forms, backend, ports")
            p.add_argument("--active", action="store_true", help="Enable bounded input, CORS, and redirect probes")
            p.add_argument("--discover", action="store_true", help="Enable at most twelve curated path guesses, with no password guessing")
            p.add_argument("--max-paths", type=int, default=12)
            p.add_argument("--max-pages", type=int, default=15)
            p.add_argument("--max-requests", type=int, default=80)
            p.add_argument("--no-inventory", action="store_true", help="Skip the TCP service inventory that otherwise runs in every scan")
            p.add_argument("--port-profile", choices=("common", "expanded"), default="common", help="34 common or 113 expanded TCP ports")
            p.add_argument("--ports", default="", help="Custom TCP ports instead of a profile, such as 22,80,8000-8010")
            p.add_argument("--advisories", action=argparse.BooleanOptionalAction, default=True, help="Look up known vulnerabilities: send detected product/version pairs (nothing else) to NIST NVD. On by default; pass --no-advisories to skip it")
            p.add_argument("--nmap", action=argparse.BooleanOptionalAction, default=True, help="Use nmap for service/version detection when installed (default); --no-nmap forces the built-in connect scan")
            p.add_argument("--host-inventory", help="Attach a JSON file produced by 'spidy host-inventory' on the target server")
            p.add_argument("--llm-model", help="After the scan, analyze the findings with this local Ollama model (open source, your choice)")
            p.add_argument("--llm-host", default=llm.DEFAULT_HOST, help="Ollama server URL (default local)")
            p.add_argument("--output", default="spidy-report.md")
            p.add_argument("--pdf-output", help="PDF report file; defaults to the report filename with .pdf suffix")
            p.add_argument("--email-output", help="Email draft file; defaults to the report filename with .email.txt suffix")
            p.add_argument("--json", action="store_true", help="Write JSON rather than Markdown")
    args = parser.parse_args()
    if args.command == "models":
        try:
            names = llm.models()
        except llm.LLMError as exc:
            print(exc)
            return 1
        print("Local models available through Ollama:" if names else "Ollama is running but no models are pulled yet (try: ollama pull llama3.1).")
        for name in names:
            print(f"  {name}")
        return 0
    if args.command == "host-inventory":
        try:
            inventory = collect_host(args.target, include_packages=not args.no_packages)
        except ValueError as exc:
            parser.error(str(exc))
        Path(args.output).write_text(json.dumps(inventory, indent=2))
        print(f"Recorded {len(inventory['processes'])} processes and {len(inventory['packages'])} packages for {inventory['target_host']}.")
        print(f"Host inventory: {Path(args.output).resolve()}")
        print("Process arguments, environment variables, and memory were not read. Import it in the dashboard's Inventory tab or with scan --host-inventory.")
        return 0
    store = Store(args.data_dir)
    if args.command == "scan":
        email_output = Path(args.email_output) if args.email_output else Path(args.output).with_suffix(".email.txt")
        pdf_output = Path(args.pdf_output) if args.pdf_output else Path(args.output).with_suffix(".pdf")
        if len({p.resolve() for p in (Path(args.output), email_output, pdf_output)}) < 3:
            parser.error("Report, PDF, and email draft must have different output paths.")
        try:
            checks = args.checks or focus_checks(args.focus) or list(DEFAULT_CHECKS)
            if args.discover and "discovery" not in checks:
                checks.append("discovery")
            config = validate_config({"target": args.target, "checks": checks,
                "focus": args.focus, "authorized": args.authorized, "active": args.active, "max_pages": args.max_pages, "max_requests": args.max_requests,
                "discovery": args.discover, "max_paths": args.max_paths, "inventory": not args.no_inventory,
                "port_profile": args.port_profile, "custom_ports": args.ports, "advisory_lookup": args.advisories,
                "use_nmap": args.nmap})
            host_inventory = None
            if args.host_inventory:
                # Validate before any network activity so a bad file does not waste a scan.
                host_inventory = validate_host_inventory(json.loads(Path(args.host_inventory).read_text()), config["target"])
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
        scan = store.create(config)
        scanner = Scanner(store, scan["id"], args.allow_private)
        try:
            result = scanner.run()
        except KeyboardInterrupt:
            store.update(scan["id"], status="cancelled", summary="Interrupted from the command line. Results are partial.")
            result = store.get(scan["id"])
        if host_inventory:
            store.update(scan["id"], inventory={**(result.get("inventory") or {}), "process_inventory": host_inventory})
            result = store.get(scan["id"])
        if args.llm_model:
            try:
                analysis = llm.analyze_scan(result, args.llm_model, args.llm_host)
                store.update(scan["id"], llm_analysis=analysis)
                result = store.get(scan["id"])
                print(f"Model analysis ({args.llm_model}) added to the report.")
            except llm.LLMError as exc:
                print(f"Model analysis skipped: {exc}")
        Path(args.output).write_text(json.dumps(result, indent=2) if args.json else markdown_report(result))
        pdf_output.write_bytes(pdf_report(result))
        email_output.write_text(email_draft(result, attachment_name=pdf_output.name))
        print(result["summary"])
        print(f"PDF report: {pdf_output.resolve()}")
        print(f"{'JSON' if args.json else 'Markdown'} report: {Path(args.output).resolve()}")
        print(f"Email draft (not sent): {email_output.resolve()}")
        if result["pending_origins"]:
            print("Additional origins were not contacted. Open the dashboard with the same --data-dir to review and approve them.")
        return 0 if result["status"] == "completed" else 2
    demo_servers = []
    server = None
    try:
        if args.command == "demo":
            from .demo import start_demo
            demo_servers = start_demo()
        server = create_server(store, args.port, args.command == "demo" or args.allow_private,
                               "http://127.0.0.1:8766/" if demo_servers else None)
        print(f"Spidy is ready at http://127.0.0.1:{server.server_address[1]}", flush=True)
        if demo_servers:
            print("Local demo mode: target on port 8766; separate approval-only origin on port 8767.", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"Could not start Spidy: {exc}", file=sys.stderr)
        return 1
    finally:
        if server:
            if server.manager.stop:
                server.manager.stop.set()
            if server.manager.worker:
                server.manager.worker.join(timeout=6)
            server.server_close()
        for demo in demo_servers:
            demo.shutdown()
            demo.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
