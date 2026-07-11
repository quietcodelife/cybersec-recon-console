#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
USER_AGENT = "CyberSec-Recon-Console/1.0"
DEFAULT_SAMPLES = 5


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


def fetch_once(target_url, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    request = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )

    start = time.perf_counter()
    with urllib.request.urlopen(request, timeout=8, context=ssl_ctx) as response:
        duration_ms = int((time.perf_counter() - start) * 1000)
        headers = dict(response.headers.items())
        return {
            "status": response.status,
            "final_url": response.geturl(),
            "duration_ms": duration_ms,
            "server": headers.get("Server", "No information"),
            "content_type": headers.get("Content-Type", "No information"),
            "content_length": headers.get("Content-Length", "No data"),
            "tls_verified": verify_tls,
        }


def fetch_with_tls_fallback(target_url):
    tls_note = None
    try:
        return fetch_once(target_url, verify_tls=True), tls_note
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLCertVerificationError):
            tls_note = f"TLS validation failed: {reason}"
            return fetch_once(target_url, verify_tls=False), tls_note
        raise


def evaluate_run(samples):
    findings = []
    status_codes = {sample["status"] for sample in samples}
    final_urls = {sample["final_url"] for sample in samples}
    servers = {sample["server"] for sample in samples}
    durations = [sample["duration_ms"] for sample in samples]

    if len(status_codes) == 1:
        findings.append(f"[OK] Status remained stable across samples: {next(iter(status_codes))}.")
    else:
        findings.append("[WARN] HTTP status changed across samples.")

    if len(final_urls) == 1:
        findings.append("[OK] Final URL remained stable across samples.")
    else:
        findings.append("[WARN] Final URL changed across samples.")

    if len(servers) == 1:
        findings.append("[OK] Server banner remained stable across samples.")
    else:
        findings.append("[WARN] Server banner changed across samples.")

    average_ms = int(sum(durations) / len(durations)) if durations else 0
    minimum_ms = min(durations) if durations else 0
    maximum_ms = max(durations) if durations else 0
    jitter_ms = maximum_ms - minimum_ms

    if average_ms >= 1000:
        findings.append("[WARN] Average response time exceeded 1000 ms.")
    elif average_ms >= 400:
        findings.append("[INFO] Average response time was moderate.")
    else:
        findings.append("[OK] Average response time stayed low.")

    if jitter_ms >= 700:
        findings.append("[WARN] Response time jitter was high across the sample set.")
    elif jitter_ms >= 250:
        findings.append("[INFO] Response time jitter was noticeable.")
    else:
        findings.append("[OK] Response time remained consistent across samples.")

    return findings, {
        "average_ms": average_ms,
        "minimum_ms": minimum_ms,
        "maximum_ms": maximum_ms,
        "jitter_ms": jitter_ms,
    }


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}HTTP REACHABILITY MONITOR{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()
        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            sample_input = input(" Sample count (default 5): ").strip()
            sample_count = int(sample_input) if sample_input.isdigit() and int(sample_input) > 0 else DEFAULT_SAMPLES

            results = []
            tls_notes = []
            print(f"\n [i] Running {sample_count} HTTP reachability sample(s) against {parsed_target.netloc}...")
            for index in range(sample_count):
                result, tls_note = fetch_with_tls_fallback(parsed_target.geturl())
                results.append(result)
                if tls_note and tls_note not in tls_notes:
                    tls_notes.append(tls_note)
                if index + 1 < sample_count:
                    time.sleep(1)

            findings, metrics = evaluate_run(results)
            latest = results[-1]
            average_ms = metrics["average_ms"]
            minimum_ms = metrics["minimum_ms"]
            maximum_ms = metrics["maximum_ms"]
            jitter_ms = metrics["jitter_ms"]

            print(f"\n {G}>>> HTTP MONITOR SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {latest['final_url']}")
            print(f" LAST STATUS:    {latest['status']}")
            print(f" AVG RTT:        {average_ms} ms")
            print(f" MIN / MAX RTT:  {minimum_ms} ms / {maximum_ms} ms")
            print(f" JITTER:         {jitter_ms} ms")
            print(f" SAMPLE COUNT:   {len(results)}")
            print(f" SERVER:         {latest['server']}")
            print(f" CONTENT-TYPE:   {latest['content_type']}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if latest['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")

            for note in tls_notes:
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} Monitoring continued in unverified certificate mode.")

            print(f"\n {Y}SAMPLE LOG:{RESET}")
            for index, sample in enumerate(results, 1):
                sample_note = ""
                if average_ms and sample["duration_ms"] >= max(average_ms * 1.75, average_ms + 250):
                    sample_note = f"  {Y}[SPIKE]{RESET}"
                print(
                    f"  - #{index}  status={sample['status']}  rtt={sample['duration_ms']} ms  "
                    f"server={sample['server']}  final={sample['final_url']}{sample_note}"
                )

            print(f"\n {Y}ASSESSMENT:{RESET}")
            for finding in findings:
                print(f"  {finding}")

            report_lines = [
                "HTTP REACHABILITY MONITOR",
                "",
                f"Initial URL: {parsed_target.geturl()}",
                f"Average RTT: {average_ms} ms",
                f"Sample Count: {len(results)}",
                "",
                "[Sample Log]",
                *(
                    f"#{index} | status={sample['status']} | rtt={sample['duration_ms']} ms | server={sample['server']} | final={sample['final_url']}"
                    for index, sample in enumerate(results, 1)
                ),
                "",
                "[Assessment]",
                *findings,
            ]

            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "HTTP_Reachability_Monitor")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
