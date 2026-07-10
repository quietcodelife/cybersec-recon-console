#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import subprocess

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

PUBLIC_RESOLVER = "8.8.8.8"
COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
    "smtp",
    "mandrill",
    "amazonses",
]


def query_record(name, record_type):
    result = subprocess.run(
        ["nslookup", f"-type={record_type}", name, PUBLIC_RESOLVER],
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    return output.strip()


def parse_mx_records(output):
    records = []
    patterns = [
        r"mail exchanger = ([^\s]+)",
        r"MX preference = \d+, mail exchanger = ([^\s]+)",
    ]
    for line in output.splitlines():
        cleaned = line.strip().rstrip(".")
        for pattern in patterns:
            match = re.search(pattern, cleaned, re.IGNORECASE)
            if match:
                value = match.group(1).rstrip(".")
                if value not in records:
                    records.append(value)
    return records


def parse_txt_records(output):
    records = []
    current_fragments = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        quoted_parts = re.findall(r'"([^"]*)"', line)
        if quoted_parts:
            current_fragments.extend(quoted_parts)
            if "text =" in line.lower() or line.endswith('"'):
                candidate = "".join(current_fragments).strip()
                if candidate and candidate not in records:
                    records.append(candidate)
                current_fragments = []
            continue

        if current_fragments:
            candidate = "".join(current_fragments).strip()
            if candidate and candidate not in records:
                records.append(candidate)
            current_fragments = []

        if "text =" in line.lower():
            rhs = line.split("=", 1)[1].strip().strip('"')
            if rhs and rhs not in records:
                records.append(rhs)

    if current_fragments:
        candidate = "".join(current_fragments).strip()
        if candidate and candidate not in records:
            records.append(candidate)

    return records


def extract_spf_record(txt_records):
    return [record for record in txt_records if record.lower().startswith("v=spf1")]


def extract_dmarc_record(txt_records):
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def parse_dmarc_policy(record):
    if not record:
        return None
    for part in record.split(";"):
        chunk = part.strip()
        if chunk.lower().startswith("p="):
            return chunk.split("=", 1)[1].strip().lower()
    return None


def collect_dkim(domain, custom_selectors):
    selectors = []
    for item in COMMON_DKIM_SELECTORS + custom_selectors:
        selector = item.strip().lower()
        if selector and selector not in selectors:
            selectors.append(selector)

    discovered = []
    for selector in selectors:
        fqdn = f"{selector}._domainkey.{domain}"
        output = query_record(fqdn, "TXT")
        txt_records = parse_txt_records(output)
        for record in txt_records:
            if "v=dkim1" in record.lower():
                discovered.append(
                    {
                        "selector": selector,
                        "host": fqdn,
                        "record": record,
                    }
                )
                break
    return discovered, selectors


def score_assessment(mx_records, spf_records, dmarc_record, dkim_records):
    score = 0
    findings = []

    if mx_records:
        score += 20
        findings.append(f"{G}[OK]{RESET} MX records are published.")
    else:
        findings.append(f"{R}[MISS]{RESET} No MX records were detected.")

    if len(spf_records) == 1:
        score += 30
        findings.append(f"{G}[OK]{RESET} One SPF record is present.")
    elif len(spf_records) > 1:
        score += 10
        findings.append(f"{Y}[WARN]{RESET} Multiple SPF records were detected. This often breaks validation.")
    else:
        findings.append(f"{R}[MISS]{RESET} No SPF record was detected.")

    dmarc_policy = parse_dmarc_policy(dmarc_record)
    if dmarc_record:
        if dmarc_policy == "reject":
            score += 30
            findings.append(f"{G}[OK]{RESET} DMARC policy is set to reject.")
        elif dmarc_policy == "quarantine":
            score += 24
            findings.append(f"{G}[OK]{RESET} DMARC policy is set to quarantine.")
        elif dmarc_policy == "none":
            score += 10
            findings.append(f"{Y}[WARN]{RESET} DMARC exists but policy is none.")
        else:
            score += 12
            findings.append(f"{Y}[WARN]{RESET} DMARC exists but policy could not be classified.")
    else:
        findings.append(f"{R}[MISS]{RESET} No DMARC record was detected.")

    if dkim_records:
        score += 20
        findings.append(f"{G}[OK]{RESET} DKIM selectors were discovered.")
    else:
        findings.append(f"{Y}[WARN]{RESET} No DKIM selector matched the tested list.")

    if score >= 80:
        verdict = "Strong"
    elif score >= 55:
        verdict = "Moderate"
    else:
        verdict = "Weak"

    return score, verdict, findings


def print_records(title, records, limit=12):
    print(f"\n {Y}{title}:{RESET}")
    if not records:
        print("  none")
        return
    for record in records[:limit]:
        print(f"  - {record}")
    if len(records) > limit:
        print(f"  ... {len(records) - limit} more")


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                    {Y}EMAIL SECURITY AUDIT{RESET}")
        print(f"{C}================================================================{RESET}")

        if not core_utils.command_exists("nslookup"):
            print(f"\n {R}[ERROR]{RESET} Missing required command: 'nslookup'.")
            input("\n Enter...")
            break

        raw_domain = input("\n Domain (for example example.com) [0=back]: ").strip()
        if raw_domain in ("", "0"):
            break

        try:
            domain = core_utils.validate_host(raw_domain).lower()
            selector_input = input(
                " Optional DKIM selectors (comma separated, press Enter to use common defaults): "
            ).strip()
            custom_selectors = [item.strip() for item in selector_input.split(",") if item.strip()] if selector_input else []

            mx_output = query_record(domain, "MX")
            txt_output = query_record(domain, "TXT")
            dmarc_output = query_record(f"_dmarc.{domain}", "TXT")

            mx_records = parse_mx_records(mx_output)
            txt_records = parse_txt_records(txt_output)
            spf_records = extract_spf_record(txt_records)
            dmarc_record = extract_dmarc_record(parse_txt_records(dmarc_output))
            dkim_records, tested_selectors = collect_dkim(domain, custom_selectors)

            score, verdict, findings = score_assessment(mx_records, spf_records, dmarc_record, dkim_records)

            print(f"\n {G}>>> EMAIL AUTHENTICATION SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" DOMAIN:         {domain}")
            print(f" RESOLVER:       {PUBLIC_RESOLVER}")
            print(f" SCORE:          {score}/100")
            print(f" VERDICT:        {verdict}")
            print(f" DKIM TEST SET:  {len(tested_selectors)} selectors")
            print(" ----------------------------------------------------------------")

            print(f"\n {Y}FINDINGS:{RESET}")
            for finding in findings:
                print(f"  {finding}")

            print_records("MX records", mx_records)
            print_records("SPF records", spf_records)
            print_records("Root TXT records", txt_records, limit=10)

            print(f"\n {Y}DMARC record:{RESET}")
            if dmarc_record:
                print(f"  {dmarc_record}")
                policy = parse_dmarc_policy(dmarc_record) or "unclassified"
                print(f"  Policy: {policy}")
            else:
                print("  none")

            print(f"\n {Y}DKIM selectors discovered:{RESET}")
            if dkim_records:
                for entry in dkim_records:
                    preview = entry["record"][:140] + ("..." if len(entry["record"]) > 140 else "")
                    print(f"  - {entry['selector']} -> {entry['host']}")
                    print(f"    {preview}")
            else:
                print("  none")

            report_lines = [
                f"EMAIL SECURITY AUDIT: {domain}",
                f"Resolver: {PUBLIC_RESOLVER}",
                f"Score: {score}/100",
                f"Verdict: {verdict}",
                "",
                "Findings:",
            ]
            report_lines.extend([re.sub(r"\x1b\[[0-9;]*m", "", item) for item in findings])
            report_lines.extend(
                [
                    "",
                    "[MX]",
                    *mx_records,
                    "",
                    "[SPF]",
                    *(spf_records or ["none"]),
                    "",
                    "[DMARC]",
                    dmarc_record or "none",
                    "",
                    "[DKIM]",
                ]
            )
            if dkim_records:
                for entry in dkim_records:
                    report_lines.append(f"{entry['selector']} -> {entry['host']}")
                    report_lines.append(entry["record"])
            else:
                report_lines.append("none")

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Email_Security_Audit")

        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
