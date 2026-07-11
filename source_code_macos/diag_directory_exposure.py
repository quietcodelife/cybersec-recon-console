#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

EXPOSURE_PATHS = [
    (".git/HEAD", "Git metadata exposure", "high"),
    (".env", "Environment file exposure", "high"),
    ("backup.zip", "Backup archive exposure", "high"),
    ("config.php.bak", "Configuration backup exposure", "high"),
    ("phpinfo.php", "PHP diagnostics exposure", "medium"),
    ("server-status", "Server status page exposure", "medium"),
    ("admin/", "Administrative panel discovery", "medium"),
    ("login/", "Login portal discovery", "low"),
    ("uploads/", "Public upload directory review", "low"),
    ("api/", "API surface discovery", "low"),
]


def normalize_target(raw_target):
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ValueError("No target was provided.")

    if "://" not in raw_target:
        raw_target = f"https://{raw_target}"

    parsed = urllib.parse.urlparse(raw_target)
    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    core_utils.validate_host(parsed.hostname)
    return parsed


def build_base_url(parsed_target):
    port_suffix = f":{parsed_target.port}" if parsed_target.port else ""
    return f"{parsed_target.scheme}://{parsed_target.hostname}{port_suffix}"


def extract_title(body_text):
    match = TITLE_PATTERN.search(body_text or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def classify_status(status_code, body_text):
    lowered = (body_text or "").lower()
    if status_code == 200:
        if "index of /" in lowered:
            return "Directory listing exposed"
        return "Accessible"
    if status_code in (401, 403):
        return "Access controlled"
    if status_code in (301, 302, 307, 308):
        return "Redirected"
    if status_code == 404:
        return "Not found"
    return "Unhandled response"


def classify_finding_type(status_code, classification):
    if status_code == 200:
        return "accessible"
    if status_code in (401, 403):
        return "restricted"
    if classification == "Redirected":
        return "redirected"
    return "observed"


def display_label(label, finding_type):
    if finding_type == "restricted":
        return label.replace("exposure", "restricted path").replace("discovery", "restricted path")
    return label


def fetch_path(url, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CyberSec-Recon-Console/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain,*/*",
        },
    )
    with opener.open(request, timeout=8) as response:
        body = response.read(4096).decode("utf-8", errors="replace")
        return {
            "status": response.status,
            "final_url": response.geturl(),
            "content_type": response.headers.get("Content-Type", "No information"),
            "content_length": response.headers.get("Content-Length", ""),
            "title": extract_title(body),
            "classification": classify_status(response.status, body),
            "tls_verified": verify_tls,
        }


def safe_fetch(url):
    tls_notice = None
    try:
        return fetch_path(url, verify_tls=True), tls_notice
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLCertVerificationError):
            tls_notice = f"TLS validation failed for {url}: {reason}"
            return fetch_path(url, verify_tls=False), tls_notice
        raise


def risk_label(value):
    if value == "high":
        return f"{R}HIGH{RESET}"
    if value == "medium":
        return f"{Y}MEDIUM{RESET}"
    return f"{G}LOW{RESET}"


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                 {Y}DIRECTORY EXPOSURE RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            base_url = build_base_url(parsed_target)
            findings = []
            tls_notices = []

            print(f"\n {Y}[i]{RESET} Probing common exposure paths on {base_url}")

            for path, label, severity in EXPOSURE_PATHS:
                target_url = urllib.parse.urljoin(base_url + "/", path)
                try:
                    result, tls_notice = safe_fetch(target_url)
                    if tls_notice and tls_notice not in tls_notices:
                        tls_notices.append(tls_notice)

                    if result["status"] != 404:
                        findings.append(
                            {
                                "path": path,
                                "label": label,
                                "severity": severity,
                                "url": target_url,
                                "status": result["status"],
                                "final_url": result["final_url"],
                                "content_type": result["content_type"],
                                "content_length": result["content_length"] or "No data",
                                "title": result["title"] or "No title",
                                "classification": result["classification"],
                                "finding_type": classify_finding_type(result["status"], result["classification"]),
                                "tls_verified": result["tls_verified"],
                            }
                        )
                except urllib.error.HTTPError as exc:
                    if exc.code != 404:
                        findings.append(
                            {
                                "path": path,
                                "label": label,
                                "severity": severity,
                                "url": target_url,
                                "status": exc.code,
                                "final_url": target_url,
                                "content_type": "No information",
                                "content_length": "No data",
                                "title": "No title",
                                "classification": "Access controlled" if exc.code in (401, 403) else "HTTP error",
                                "finding_type": "restricted" if exc.code in (401, 403) else "observed",
                                "tls_verified": True,
                            }
                        )
                except urllib.error.URLError:
                    continue

            accessible_findings = [item for item in findings if item["finding_type"] == "accessible"]
            restricted_findings = [item for item in findings if item["finding_type"] == "restricted"]
            other_findings = [item for item in findings if item["finding_type"] not in ("accessible", "restricted")]

            print(f"\n {G}>>> EXPOSURE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TARGET:         {base_url}")
            print(f" CHECKLIST:      {len(EXPOSURE_PATHS)} paths")
            print(f" FINDINGS:       {len(findings)}")
            print(f" ACCESSIBLE:     {len(accessible_findings)}")
            print(f" RESTRICTED:     {len(restricted_findings)}")
            print(" ----------------------------------------------------------------")

            if tls_notices:
                for notice in tls_notices:
                    print(f" {Y}[TLS NOTICE]{RESET} {notice}")
                    print(f" {Y}[TLS NOTICE]{RESET} Collection continued in unverified certificate mode.")

            if findings:
                for finding in findings:
                    heading = display_label(finding["label"], finding["finding_type"])
                    prefix = risk_label(finding["severity"]) if finding["finding_type"] == "accessible" else f"{C}INFO{RESET}"
                    print(f"\n {prefix} {heading}")
                    print(f" Path:           /{finding['path'].lstrip('/')}")
                    print(f" Status:         {finding['status']}")
                    print(f" Finding Type:   {finding['finding_type'].replace('_', ' ').title()}")
                    print(f" Classification: {finding['classification']}")
                    print(f" Content-Type:   {finding['content_type']}")
                    print(f" Content-Length: {finding['content_length']}")
                    print(f" Title:          {finding['title']}")
                    print(f" Final URL:      {finding['final_url']}")
                    print(
                        f" TLS Verify:     "
                        f"{G + 'OK' + RESET if finding['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}"
                    )
            else:
                print(f"\n {G}[OK]{RESET} No exposures were detected in the standard path checklist.")

            report_lines = [
                f"DIRECTORY EXPOSURE RECON: {base_url}",
                f"Checklist size: {len(EXPOSURE_PATHS)}",
                f"Findings: {len(findings)}",
                f"Accessible findings: {len(accessible_findings)}",
                f"Restricted findings: {len(restricted_findings)}",
            ]
            for notice in tls_notices:
                report_lines.append(f"TLS Warning: {notice}")
            for finding in findings:
                report_lines.extend(
                    [
                        "",
                        f"[{finding['finding_type'].upper()}] {display_label(finding['label'], finding['finding_type'])}",
                        f"Path: /{finding['path'].lstrip('/')}",
                        f"Status: {finding['status']}",
                        f"Finding Type: {finding['finding_type']}",
                        f"Classification: {finding['classification']}",
                        f"Content-Type: {finding['content_type']}",
                        f"Content-Length: {finding['content_length']}",
                        f"Title: {finding['title']}",
                        f"Final URL: {finding['final_url']}",
                        f"TLS Verify: {'OK' if finding['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                    ]
                )

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Directory_Exposure_Recon")

        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
