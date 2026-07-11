#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
CT_TIMEOUT_SECONDS = 30


def normalize_domain(raw_value):
    raw_value = (raw_value or "").strip()
    if not raw_value:
        raise ValueError("No domain was provided.")

    if "://" in raw_value:
        parsed = urllib.parse.urlparse(raw_value)
        raw_value = parsed.hostname or ""

    domain = core_utils.validate_host(raw_value).lower()
    return domain.lstrip("*.") if domain.startswith("*.") else domain


def fetch_ct_entries(query_value, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    query = urllib.parse.quote(query_value)
    request = urllib.request.Request(
        f"https://crt.sh/?q={query}&output=json",
        headers={"User-Agent": "CyberSec-Recon-Console/1.0"},
    )
    with opener.open(request, timeout=CT_TIMEOUT_SECONDS) as response:
        payload = response.read().decode("utf-8", errors="replace")
        source_url = response.geturl()
    if not payload.strip():
        return {"entries": [], "tls_verified": verify_tls, "source_url": source_url}
    return {"entries": json.loads(payload), "tls_verified": verify_tls, "source_url": source_url}


def safe_fetch_ct_entries(domain):
    tls_note = None
    attempts = [f"%.{domain}", domain]
    if not domain.startswith("www."):
        attempts.append(f"www.{domain}")

    aggregated_entries = []
    source_urls = []
    tls_verified = True
    partial_results = False
    last_error = None

    for query_value in attempts:
        try:
            result = fetch_ct_entries(query_value, verify_tls=True)
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ssl.SSLCertVerificationError):
                if not tls_note:
                    tls_note = f"TLS validation failed for CT source: {reason}"
                result = fetch_ct_entries(query_value, verify_tls=False)
                tls_verified = False
            else:
                last_error = exc
                continue
        except (TimeoutError, socket.timeout) as exc:
            last_error = exc
            continue

        partial_results = True
        aggregated_entries.extend(result["entries"])
        source_urls.append(result["source_url"])
        tls_verified = tls_verified and result["tls_verified"]

        if query_value.startswith("%.") and result["entries"]:
            break

    if partial_results:
        return {
            "entries": aggregated_entries,
            "tls_verified": tls_verified,
            "source_url": " | ".join(dict.fromkeys(source_urls)),
            "partial_fallback": len(source_urls) > 1 or not source_urls[0].endswith(f"q=%25.{domain}&output=json"),
        }, tls_note

    if last_error:
        raise last_error
    raise TimeoutError("Certificate transparency queries did not return before timeout.")


def extract_names(entries, domain):
    names = set()
    for entry in entries:
        raw_names = entry.get("name_value", "")
        for item in raw_names.splitlines():
            cleaned = item.strip().lower().lstrip("*.")
            if cleaned and cleaned.endswith(domain):
                names.add(cleaned)
    return sorted(names)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                {Y}CERTIFICATE TRANSPARENCY RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n Domain or URL [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            domain = normalize_domain(target)
            print(f"\n [i] Querying certificate transparency logs for {domain}...")

            result, tls_note = safe_fetch_ct_entries(domain)
            entries = result["entries"]
            names = extract_names(entries, domain)

            print(f"\n {G}>>> CT RECON SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" DOMAIN:         {domain}")
            print(f" CT ENTRIES:     {len(entries)}")
            print(f" UNIQUE NAMES:   {len(names)}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")
                print(f" {Y}[TLS NOTICE]{RESET} CT collection continued in unverified certificate mode.")
            if result.get("partial_fallback"):
                print(f" {Y}[SOURCE NOTICE]{RESET} Fallback CT queries were used after the primary wildcard lookup stalled.")

            print(f"\n {Y}DISCOVERED HOSTNAMES:{RESET}")
            if names:
                for name in names[:40]:
                    print(f"  {G}- {name}{RESET}")
                if len(names) > 40:
                    print(f"  {Y}... plus {len(names) - 40} more entries{RESET}")
            else:
                print(f"  {R}- No CT hostnames discovered{RESET}")

            report_lines = [
                f"CERTIFICATE TRANSPARENCY RECON: {domain}",
                f"CT Entries: {len(entries)}",
                f"Unique Names: {len(names)}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                f"CT Source URL: {result['source_url']}",
                "",
                "[Discovered Hostnames]",
                *(names or ["No CT hostnames discovered"]),
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])
            if result.get("partial_fallback"):
                report_lines.extend(["", "Source Notice: Fallback CT queries were used after the primary wildcard lookup stalled."])

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "CT_Recon")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc}")
        except (TimeoutError, socket.timeout):
            print(f"\n {R}[TIMEOUT]{RESET} The certificate transparency source did not respond in time.")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
