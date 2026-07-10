#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


class CaptureRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops.append((code, req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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


def fetch_http_profile(parsed_target, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    redirect_handler = CaptureRedirectHandler()
    opener = urllib.request.build_opener(redirect_handler, urllib.request.HTTPSHandler(context=ssl_ctx))

    req = urllib.request.Request(
        parsed_target.geturl(),
        headers={
            "User-Agent": "CyberSec-Recon-Console/1.0",
            "Accept": "*/*",
        },
    )
    with opener.open(req, timeout=8) as response:
        body = response.read(2048)
        headers = dict(response.headers.items())
        final_url = response.geturl()
        status = response.status

    return {
        "status": status,
        "headers": headers,
        "final_url": final_url,
        "redirects": redirect_handler.hops,
        "body_preview": body.decode("utf-8", errors="replace"),
        "tls_verified": verify_tls,
    }


def classify_security_headers(headers):
    lowered = {k.lower(): v for k, v in headers.items()}
    present = []
    missing = []
    for header_name in SECURITY_HEADERS:
        if header_name in lowered:
            present.append((header_name, lowered[header_name]))
        else:
            missing.append(header_name)
    return present, missing


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                    {Y}HTTP SURFACE RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            tls_note = None
            try:
                result = fetch_http_profile(parsed_target, verify_tls=True)
            except urllib.error.URLError as e:
                reason = getattr(e, "reason", "")
                if isinstance(reason, ssl.SSLCertVerificationError):
                    tls_note = f"TLS validation failed: {reason}"
                    result = fetch_http_profile(parsed_target, verify_tls=False)
                else:
                    raise

            headers = result["headers"]
            present, missing = classify_security_headers(headers)

            server = headers.get("Server", "No information")
            ctype = headers.get("Content-Type", "No information")
            powered_by = headers.get("X-Powered-By", "No information")

            print(f"\n {G}>>> HTTP SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" HOST:           {parsed_target.hostname}")
            if parsed_target.path:
                print(f" PATH:           {parsed_target.path}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(f" SERVER:         {server}")
            print(f" CONTENT-TYPE:   {ctype}")
            print(f" X-POWERED-BY:   {powered_by}")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")
                print(f" {Y}[TLS NOTICE]{RESET} HTTP profile was still collected using unverified certificate mode.")

            if result["redirects"]:
                print(f" {Y}REDIRECT CHAIN:{RESET}")
                for code, source, destination in result["redirects"]:
                    print(f"  [{code}] {source} -> {destination}")
            else:
                print(f" {Y}REDIRECT CHAIN:{RESET} none")

            print(f"\n {Y}SECURITY HEADERS:{RESET}")
            if present:
                for key, value in present:
                    preview = value[:80] + ("..." if len(value) > 80 else "")
                    print(f"  {G}[OK]{RESET} {key}: {preview}")
            else:
                print(f"  {R}[NONE]{RESET} No standard security headers were detected.")

            if missing:
                print(f"\n {R}MISSING HEADERS:{RESET} {', '.join(missing)}")

            print(f"\n {Y}PREVIEW ODPOWIEDZI:{RESET}")
            preview = result["body_preview"].strip()
            if preview:
                print(preview[:400])
            else:
                print(" No text body was returned or the response is binary.")

            report_lines = [
                f"HTTP SURFACE RECON: {parsed_target.geturl()}",
                f"Host: {parsed_target.hostname}",
                f"Path: {parsed_target.path or '/'}",
                f"Final URL: {result['final_url']}",
                f"Status: {result['status']}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                f"Server: {server}",
                f"Content-Type: {ctype}",
                f"X-Powered-By: {powered_by}",
                f"Redirects: {len(result['redirects'])}",
                "",
                "Security headers:",
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Warning: {tls_note}"])
            for key, value in present:
                report_lines.append(f"[OK] {key}: {value}")
            for key in missing:
                report_lines.append(f"[MISSING] {key}")

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "HTTP_Recon")

        except urllib.error.HTTPError as e:
            print(f"\n {R}[HTTP ERROR]{RESET} {e.code} {e.reason}")
        except urllib.error.URLError as e:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {e.reason}")
        except Exception as e:
            print(f"\n {R}[ERROR]{RESET} {e}")

        input("\n Enter...")
