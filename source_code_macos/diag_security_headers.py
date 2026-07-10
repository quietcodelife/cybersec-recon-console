#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

HEADER_SPECS = [
    {
        "name": "strict-transport-security",
        "label": "HSTS",
        "weight": 20,
        "evaluate": lambda value: "max-age=" in value and "0" not in value.split("max-age=", 1)[1][:2],
        "good": "HSTS policy is present.",
        "bad": "HSTS is missing or weak. Enforce HTTPS with a long max-age policy.",
    },
    {
        "name": "content-security-policy",
        "label": "Content-Security-Policy",
        "weight": 25,
        "evaluate": lambda value: "default-src" in value and "unsafe-inline" not in value,
        "good": "CSP is present and avoids unsafe-inline in the visible policy.",
        "bad": "CSP is missing or permissive. Define default-src and reduce inline script/style allowances.",
    },
    {
        "name": "x-frame-options",
        "label": "X-Frame-Options",
        "weight": 10,
        "evaluate": lambda value: value in ("deny", "sameorigin"),
        "good": "Clickjacking protection header is set.",
        "bad": "Add X-Frame-Options: DENY or SAMEORIGIN.",
    },
    {
        "name": "x-content-type-options",
        "label": "X-Content-Type-Options",
        "weight": 10,
        "evaluate": lambda value: value == "nosniff",
        "good": "Content sniffing protection is enabled.",
        "bad": "Add X-Content-Type-Options: nosniff.",
    },
    {
        "name": "referrer-policy",
        "label": "Referrer-Policy",
        "weight": 10,
        "evaluate": lambda value: value in ("strict-origin-when-cross-origin", "no-referrer", "same-origin"),
        "good": "Referrer handling is restrictive.",
        "bad": "Use a stricter Referrer-Policy such as strict-origin-when-cross-origin.",
    },
    {
        "name": "permissions-policy",
        "label": "Permissions-Policy",
        "weight": 10,
        "evaluate": lambda value: bool(value.strip()),
        "good": "Permissions-Policy is present.",
        "bad": "Declare Permissions-Policy to restrict powerful browser features.",
    },
    {
        "name": "cross-origin-opener-policy",
        "label": "Cross-Origin-Opener-Policy",
        "weight": 5,
        "evaluate": lambda value: value in ("same-origin", "same-origin-allow-popups"),
        "good": "COOP is present.",
        "bad": "Consider Cross-Origin-Opener-Policy: same-origin.",
    },
    {
        "name": "cross-origin-resource-policy",
        "label": "Cross-Origin-Resource-Policy",
        "weight": 5,
        "evaluate": lambda value: value in ("same-origin", "same-site"),
        "good": "CORP is present.",
        "bad": "Consider Cross-Origin-Resource-Policy for sensitive resources.",
    },
    {
        "name": "cross-origin-embedder-policy",
        "label": "Cross-Origin-Embedder-Policy",
        "weight": 5,
        "evaluate": lambda value: value in ("require-corp", "credentialless"),
        "good": "COEP is present.",
        "bad": "Consider Cross-Origin-Embedder-Policy when isolation is required.",
    },
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


def fetch_headers(parsed_target, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    redirect_handler = CaptureRedirectHandler()
    opener = urllib.request.build_opener(redirect_handler, urllib.request.HTTPSHandler(context=ssl_ctx))

    request = urllib.request.Request(
        parsed_target.geturl(),
        headers={
            "User-Agent": "CyberSec-Recon-Console/1.0",
            "Accept": "*/*",
        },
    )

    with opener.open(request, timeout=8) as response:
        headers = dict(response.headers.items())
        final_url = response.geturl()
        status = response.status

    return {
        "status": status,
        "headers": headers,
        "final_url": final_url,
        "redirects": redirect_handler.hops,
        "tls_verified": verify_tls,
    }


def grade_from_score(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def audit_headers(headers):
    lowered = {key.lower(): value.strip() for key, value in headers.items()}
    findings = []
    recommendations = []
    score = 0

    for spec in HEADER_SPECS:
        value = lowered.get(spec["name"], "")
        if value and spec["evaluate"](value.lower()):
            score += spec["weight"]
            findings.append(f"[OK] {spec['label']}: {value[:110]}")
        elif value:
            findings.append(f"[WEAK] {spec['label']}: {value[:110]}")
            recommendations.append(spec["bad"])
        else:
            findings.append(f"[MISSING] {spec['label']}")
            recommendations.append(spec["bad"])

    server = lowered.get("server", "")
    powered_by = lowered.get("x-powered-by", "")
    if powered_by:
        findings.append(f"[INFO] X-Powered-By exposed: {powered_by[:110]}")
        recommendations.append("Suppress X-Powered-By to reduce stack disclosure.")
    if server:
        findings.append(f"[INFO] Server header exposed: {server[:110]}")

    if "set-cookie" in lowered:
        cookie_value = lowered["set-cookie"]
        if "secure" in cookie_value and "httponly" in cookie_value:
            score += 5
            findings.append("[OK] Cookie flags include Secure and HttpOnly.")
        else:
            findings.append("[WEAK] Cookie flags are missing Secure and/or HttpOnly.")
            recommendations.append("Harden session cookies with Secure, HttpOnly, and SameSite.")

    score = min(score, 100)
    unique_recommendations = []
    for item in recommendations:
        if item not in unique_recommendations:
            unique_recommendations.append(item)

    return {
        "score": score,
        "grade": grade_from_score(score),
        "findings": findings,
        "recommendations": unique_recommendations,
    }


def print_section(title, values, success_when_empty=False):
    print(f"\n {Y}{title}:{RESET}")
    if values:
        for value in values:
            print(f"  {G}- {value}{RESET}")
    else:
        label = "No issues detected" if success_when_empty else "No data available"
        color = G if success_when_empty else R
        print(f"  {color}- {label}{RESET}")


def print_redirect_chain(redirects):
    print(f"\n {Y}REDIRECT CHAIN:{RESET}")
    if not redirects:
        print(f"  {G}- No redirects observed{RESET}")
        return
    for code, source, destination in redirects:
        print(f"  {G}- [{code}] {source} -> {destination}{RESET}")


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}SECURITY HEADERS AUDIT{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            tls_note = None
            try:
                result = fetch_headers(parsed_target, verify_tls=True)
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", "")
                if isinstance(reason, ssl.SSLCertVerificationError):
                    tls_note = f"TLS validation failed: {reason}"
                    result = fetch_headers(parsed_target, verify_tls=False)
                else:
                    raise

            audit = audit_headers(result["headers"])
            server = result["headers"].get("Server", "No information")
            powered_by = result["headers"].get("X-Powered-By", "No information")

            print(f"\n {G}>>> SECURITY HEADER POSTURE{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            print(f" SCORE:          {audit['score']}/100")
            print(f" GRADE:          {audit['grade']}")
            print(f" SERVER:         {server}")
            print(f" X-POWERED-BY:   {powered_by}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")

            print_redirect_chain(result["redirects"])
            print_section("FINDINGS", audit["findings"])
            print_section("HARDENING RECOMMENDATIONS", audit["recommendations"], success_when_empty=True)

            report_lines = [
                f"SECURITY HEADERS AUDIT: {parsed_target.geturl()}",
                f"Final URL: {result['final_url']}",
                f"Status: {result['status']}",
                f"Score: {audit['score']}/100",
                f"Grade: {audit['grade']}",
                f"Server: {server}",
                f"X-Powered-By: {powered_by}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                "",
                "[Redirect Chain]",
                *([f"[{code}] {source} -> {destination}" for code, source, destination in result["redirects"]] or ["No redirects observed"]),
                "",
                "[Findings]",
                *(audit["findings"] or ["No data available"]),
                "",
                "[Recommendations]",
                *(audit["recommendations"] or ["No issues detected"]),
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Security_Headers_Audit")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc.reason}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
