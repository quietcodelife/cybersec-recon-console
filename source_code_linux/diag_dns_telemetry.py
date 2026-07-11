#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import subprocess
import time

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
PUBLIC_RESOLVERS = [
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
]


def safe_run(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
    except Exception:
        return None


def normalize_domain(raw_value):
    raw_value = (raw_value or "").strip()
    if not raw_value:
        raise ValueError("No domain was provided.")
    return core_utils.validate_host(raw_value).lower()


def parse_system_resolvers():
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith("nameserver"):
                    value = stripped.split()[1]
                    if value not in resolvers:
                        resolvers.append(value)
    except Exception:
        return []
    return resolvers


def parse_answer_ips(output):
    ips = []
    for line in (output or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("address:"):
            value = stripped.split(":", 1)[1].strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", value) and value not in ips:
                ips.append(value)
    return ips


def query_resolver(domain, resolver=None):
    command = ["nslookup", domain]
    label = "System Default"
    resolver_ip = "system"
    if resolver:
        label, resolver_ip = resolver
        command.append(resolver_ip)

    start = time.perf_counter()
    result = safe_run(command)
    duration_ms = int((time.perf_counter() - start) * 1000)

    if not result:
        return {
            "label": label,
            "resolver": resolver_ip,
            "duration_ms": duration_ms,
            "status": "ERROR",
            "answers": [],
            "notes": ["Resolver command did not complete."],
        }

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    answers = parse_answer_ips(output)
    lowered = output.lower()

    if "nxdomain" in lowered or "can't find" in lowered or "non-existent domain" in lowered:
        status = "NXDOMAIN"
    elif answers:
        status = "OK"
    elif "timed out" in lowered:
        status = "TIMEOUT"
    else:
        status = "NOANSWER"

    notes = []
    if "timed out" in lowered:
        notes.append("Resolver timed out.")
    if "server can't find" in lowered:
        notes.append("Resolver returned NXDOMAIN.")

    return {
        "label": label,
        "resolver": resolver_ip,
        "duration_ms": duration_ms,
        "status": status,
        "answers": answers,
        "notes": notes,
    }


def assess_results(results, system_resolvers):
    findings = []
    recommendations = []

    ok_results = [item for item in results if item["status"] == "OK"]
    if ok_results:
        findings.append(f"[OK] {len(ok_results)} resolver path(s) returned valid answers.")
    else:
        findings.append("[WARN] No resolver path returned a valid answer.")
        recommendations.append("Review local resolver configuration and upstream reachability.")

    if system_resolvers:
        findings.append(f"[INFO] System resolvers detected: {len(system_resolvers)}")
    else:
        findings.append("[WARN] No system resolvers were detected from local DNS configuration.")

    answer_sets = {tuple(item["answers"]) for item in ok_results if item["answers"]}
    if len(answer_sets) > 1:
        findings.append("[WARN] Resolver answer sets differ across tested resolvers.")
        recommendations.append("Review DNS consistency across system and public resolvers.")
    elif len(answer_sets) == 1 and ok_results:
        findings.append("[OK] Resolver answers were consistent across successful resolver paths.")

    slow_paths = [item for item in results if item["duration_ms"] >= 800]
    if slow_paths:
        findings.append(f"[WARN] {len(slow_paths)} resolver path(s) exceeded 800 ms.")
        recommendations.append("Investigate slow resolver response times or packet loss on the current network path.")

    nxdomain_paths = [item for item in results if item["status"] == "NXDOMAIN"]
    if nxdomain_paths and not ok_results:
        findings.append("[WARN] All tested resolvers returned NXDOMAIN.")

    return findings, list(dict.fromkeys(recommendations))


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                      {Y}DNS TELEMETRY{RESET}")
        print(f"{C}================================================================{RESET}")

        if not core_utils.command_exists("nslookup"):
            print(f"\n {R}[ERROR]{RESET} Missing required command: 'nslookup'.")
            input("\n Enter...")
            break

        target = input("\n Domain (for example example.com) [0=back]: ").strip()
        if target in ("", "0"):
            break

        try:
            domain = normalize_domain(target)
            system_resolvers = parse_system_resolvers()
            results = [query_resolver(domain)]
            for resolver in PUBLIC_RESOLVERS:
                results.append(query_resolver(domain, resolver=resolver))

            findings, recommendations = assess_results(results, system_resolvers)
            fastest = min(results, key=lambda item: item["duration_ms"]) if results else None

            print(f"\n {G}>>> DNS TELEMETRY SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" DOMAIN:         {domain}")
            print(f" SYSTEM DNS:     {', '.join(system_resolvers[:3]) if system_resolvers else 'No data'}")
            print(f" PATHS TESTED:   {len(results)}")
            print(f" FASTEST PATH:   {fastest['label']} ({fastest['duration_ms']} ms)" if fastest else " FASTEST PATH:   No data")
            print(" ----------------------------------------------------------------")

            print(f"\n {Y}RESOLVER PATHS:{RESET}")
            for item in results:
                answers = ", ".join(item["answers"][:4]) if item["answers"] else "No answers"
                print(
                    f"  - {item['label']:<14} "
                    f"{item['resolver']:<15} "
                    f"{item['status']:<8} "
                    f"{item['duration_ms']:>4} ms  "
                    f"{answers}"
                )

            print(f"\n {Y}ASSESSMENT:{RESET}")
            for finding in findings:
                print(f"  {finding}")

            print(f"\n {Y}HARDENING / OPS NOTES:{RESET}")
            if recommendations:
                for item in recommendations:
                    print(f"  - {item}")
            else:
                print("  - No additional operational guidance was generated.")

            report_lines = [
                "DNS TELEMETRY",
                "",
                f"Domain: {domain}",
                f"System DNS: {', '.join(system_resolvers) if system_resolvers else 'No data'}",
                "",
                "[Resolver Paths]",
                *(
                    f"{item['label']} | {item['resolver']} | {item['status']} | {item['duration_ms']} ms | {', '.join(item['answers']) if item['answers'] else 'No answers'}"
                    for item in results
                ),
                "",
                "[Assessment]",
                *findings,
                "",
                "[Notes]",
                *(recommendations or ["No additional operational guidance was generated."]),
            ]

            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "DNS_Telemetry")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
