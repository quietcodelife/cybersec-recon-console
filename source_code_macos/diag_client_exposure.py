#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import html
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
USER_AGENT = "CyberSec-Recon-Console/1.0"
MAX_JS_FETCH = 5
MAX_JS_BYTES = 16384
MAX_PAGE_BYTES = 131072

SCRIPT_SRC_PATTERN = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
ABSOLUTE_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
RELATIVE_API_PATTERN = re.compile(r"(?<![A-Za-z0-9_])/(?:api|graphql|auth|oauth|admin|internal|uploads?|storage|assets)/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*")

SERVICE_PATTERNS = [
    ("Sentry DSN", re.compile(r"https://[A-Za-z0-9._-]+@o\d+\.ingest\.sentry\.io/\d+", re.IGNORECASE)),
    ("Firebase config", re.compile(r"(firebaseapp\.com|firebasestorage\.googleapis\.com|AIza[0-9A-Za-z\-_]{20,})", re.IGNORECASE)),
    ("Supabase endpoint", re.compile(r"https://[A-Za-z0-9-]+\.supabase\.co", re.IGNORECASE)),
    ("Stripe public key", re.compile(r"pk_(?:live|test)_[0-9A-Za-z]{16,}", re.IGNORECASE)),
    ("Mapbox public token", re.compile(r"pk\.[0-9A-Za-z\._-]{20,}", re.IGNORECASE)),
    ("Intercom app id", re.compile(r"app_id[\"'\s:=]+[A-Za-z0-9]{6,}", re.IGNORECASE)),
]

STORAGE_HINTS = [
    ("AWS S3", re.compile(r"https?://[A-Za-z0-9._-]+\.s3[.-][A-Za-z0-9-]+\.amazonaws\.com[^\"]*", re.IGNORECASE)),
    ("Google Cloud Storage", re.compile(r"https?://storage\.googleapis\.com/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)),
    ("Azure Blob Storage", re.compile(r"https?://[A-Za-z0-9-]+\.blob\.core\.windows\.net/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)),
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


def fetch_text(url, verify_tls=True, max_bytes=MAX_PAGE_BYTES):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/javascript,text/javascript,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(request, timeout=10, context=ssl_ctx) as response:
        body = response.read(max_bytes).decode("utf-8", errors="replace")
        return {
            "status": response.status,
            "headers": dict(response.headers.items()),
            "body": body,
            "final_url": response.geturl(),
            "tls_verified": verify_tls,
        }


def fetch_with_tls_fallback(url, max_bytes=MAX_PAGE_BYTES):
    tls_notes = []
    try:
        return fetch_text(url, verify_tls=True, max_bytes=max_bytes), tls_notes
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLCertVerificationError):
            tls_notes.append(f"TLS validation failed for {url}: {reason}")
            return fetch_text(url, verify_tls=False, max_bytes=max_bytes), tls_notes
        raise


def unique_preserve(values):
    seen = set()
    output = []
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return output


def extract_script_urls(base_url, body):
    urls = []
    for raw_src in SCRIPT_SRC_PATTERN.findall(body or ""):
        absolute = urllib.parse.urljoin(base_url, html.unescape(raw_src.strip()))
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme in ("http", "https"):
            urls.append(absolute)
    return unique_preserve(urls)


def classify_url(url):
    lowered = url.lower()
    if any(token in lowered for token in ("/api/", "/graphql", "/auth/", "/oauth/")):
        return "API / Auth"
    if any(token in lowered for token in ("/admin", "/panel", "/dashboard", "/manage")):
        return "Admin / Panel"
    if any(token in lowered for token in ("/upload", "/uploads", "/storage", "/bucket", ".blob.", ".s3")):
        return "Storage / Upload"
    return "General URL"


def extract_urls(text, base_url):
    findings = []
    for match in ABSOLUTE_URL_PATTERN.findall(text or ""):
        findings.append((classify_url(match), match))
    for match in RELATIVE_API_PATTERN.findall(text or ""):
        absolute = urllib.parse.urljoin(base_url, match)
        findings.append((classify_url(absolute), absolute))
    unique = []
    seen = set()
    for label, value in findings:
        key = (label, value)
        if key not in seen:
            seen.add(key)
            unique.append((label, value))
    return unique


def extract_service_findings(text):
    findings = []
    for label, pattern in SERVICE_PATTERNS:
        for match in pattern.findall(text or ""):
            value = match if isinstance(match, str) else "".join(match)
            findings.append((label, value))
    return unique_preserve([f"{label}: {value}" for label, value in findings])


def extract_storage_findings(text):
    findings = []
    for label, pattern in STORAGE_HINTS:
        for match in pattern.findall(text or ""):
            findings.append(f"{label}: {match}")
    return unique_preserve(findings)


def extract_path_hints(text, base_url):
    hints = []
    for label, value in extract_urls(text, base_url):
        if label in ("API / Auth", "Admin / Panel", "Storage / Upload"):
            hints.append(f"{label}: {value}")
    return unique_preserve(hints)


def gather_javascript_findings(page_result):
    script_urls = extract_script_urls(page_result["final_url"], page_result["body"])
    same_host_scripts = []
    base_host = urllib.parse.urlparse(page_result["final_url"]).hostname
    for url in script_urls:
        if urllib.parse.urlparse(url).hostname == base_host:
            same_host_scripts.append(url)

    fetched_scripts = []
    tls_notes = []
    combined_findings = []
    for script_url in same_host_scripts[:MAX_JS_FETCH]:
        try:
            result, fetch_tls_notes = fetch_with_tls_fallback(script_url, max_bytes=MAX_JS_BYTES)
            tls_notes.extend(fetch_tls_notes)
            fetched_scripts.append(script_url)
            combined_findings.extend(extract_path_hints(result["body"], script_url))
            combined_findings.extend(extract_service_findings(result["body"]))
            combined_findings.extend(extract_storage_findings(result["body"]))
        except Exception:
            continue

    return {
        "script_urls": script_urls,
        "fetched_scripts": fetched_scripts,
        "tls_notes": unique_preserve(tls_notes),
        "js_findings": unique_preserve(combined_findings),
    }


def score_exposure(page_findings, js_findings, service_findings, storage_findings):
    findings = []
    recommendations = []
    score = 100

    if page_findings:
        findings.append(f"[INFO] Public client content exposed {len(page_findings)} high-signal path or endpoint hint(s).")
        score -= min(18, len(page_findings) * 3)
    else:
        findings.append("[OK] No high-signal path or endpoint hints were detected in the initial page content.")

    if js_findings:
        findings.append(f"[INFO] Public JavaScript exposed {len(js_findings)} additional high-signal hint(s).")
        score -= min(20, len(js_findings) * 4)
        recommendations.append("Review whether production JavaScript exposes unnecessary internal routes, admin paths, or backend endpoints.")
    else:
        findings.append("[OK] No additional high-signal findings were extracted from sampled public scripts.")

    if service_findings:
        findings.append(f"[WARN] Public service identifiers detected: {len(service_findings)}")
        score -= min(20, len(service_findings) * 5)
        recommendations.append("Review exposed third-party service identifiers and confirm they are intended to be public.")

    if storage_findings:
        findings.append(f"[WARN] Public storage or upload references detected: {len(storage_findings)}")
        score -= min(18, len(storage_findings) * 6)
        recommendations.append("Review whether public storage or upload endpoints require additional access control or signed URL restrictions.")

    score = max(0, min(score, 100))
    if score >= 85:
        grade = "A"
        verdict = "Low Exposure"
    elif score >= 70:
        grade = "B"
        verdict = "Controlled Exposure"
    elif score >= 55:
        grade = "C"
        verdict = "Moderate Exposure"
    elif score >= 35:
        grade = "D"
        verdict = "Broad Exposure"
    else:
        grade = "F"
        verdict = "High Exposure"

    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "findings": findings,
        "recommendations": unique_preserve(recommendations),
    }


def print_section(title, values, limit=10):
    print(f"\n {Y}{title}:{RESET}")
    if not values:
        print("  none")
        return
    for value in values[:limit]:
        print(f"  - {value}")
    if len(values) > limit:
        print(f"  ... {len(values) - limit} more")


def build_report(parsed_target, page_result, audit, page_hints, js_hints, service_hints, storage_hints, script_urls, fetched_scripts):
    lines = [
        "CLIENT EXPOSURE RECON",
        "",
        f"Initial URL: {parsed_target.geturl()}",
        f"Final URL: {page_result['final_url']}",
        f"Status: {page_result['status']}",
        f"TLS Verify: {'OK' if page_result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
        f"Score: {audit['score']}/100",
        f"Grade: {audit['grade']}",
        f"Verdict: {audit['verdict']}",
        "",
        "[Findings]",
        *(f"- {item}" for item in audit["findings"]),
        "",
        "[Page Hints]",
        *([f"- {item}" for item in page_hints] or ["- No high-signal page hints"]),
        "",
        "[JavaScript Hints]",
        *([f"- {item}" for item in js_hints] or ["- No high-signal JavaScript hints"]),
        "",
        "[Service Identifiers]",
        *([f"- {item}" for item in service_hints] or ["- No public service identifiers detected"]),
        "",
        "[Storage References]",
        *([f"- {item}" for item in storage_hints] or ["- No storage or upload references detected"]),
        "",
        "[Sampled Scripts]",
        *([f"- {item}" for item in fetched_scripts] or ["- No same-origin scripts sampled"]),
        "",
        "[Discovered Script URLs]",
        *([f"- {item}" for item in script_urls] or ["- No script URLs discovered"]),
    ]
    return "\n".join(lines)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}CLIENT EXPOSURE RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            page_result, tls_notes = fetch_with_tls_fallback(parsed_target.geturl(), max_bytes=MAX_PAGE_BYTES)
            page_hints = extract_path_hints(page_result["body"], page_result["final_url"])
            service_hints = extract_service_findings(page_result["body"])
            storage_hints = extract_storage_findings(page_result["body"])
            js_profile = gather_javascript_findings(page_result)
            tls_notes.extend(js_profile["tls_notes"])

            audit = score_exposure(page_hints, js_profile["js_findings"], service_hints, storage_hints)

            print(f"\n {G}>>> CLIENT EXPOSURE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {page_result['final_url']}")
            print(f" STATUS:         {page_result['status']}")
            print(f" SCORE:          {audit['score']}/100")
            print(f" GRADE:          {audit['grade']}")
            print(f" VERDICT:        {audit['verdict']}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if page_result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(f" SCRIPTS FOUND:  {len(js_profile['script_urls'])}")
            print(f" SAMPLED JS:     {len(js_profile['fetched_scripts'])}")
            print(" ----------------------------------------------------------------")
            for note in unique_preserve(tls_notes):
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} Collection continued in unverified certificate mode where necessary.")

            print_section("PAGE HINTS", page_hints)
            print_section("JAVASCRIPT HINTS", js_profile["js_findings"])
            print_section("SERVICE IDENTIFIERS", service_hints)
            print_section("STORAGE / UPLOAD REFERENCES", storage_hints)

            print(f"\n {Y}ASSESSMENT:{RESET}")
            for finding in audit["findings"]:
                print(f"  {finding}")

            print(f"\n {Y}HARDENING RECOMMENDATIONS:{RESET}")
            if audit["recommendations"]:
                for item in audit["recommendations"]:
                    print(f"  - {item}")
            else:
                print("  - No additional hardening guidance was generated.")

            report = build_report(
                parsed_target,
                page_result,
                audit,
                page_hints,
                js_profile["js_findings"],
                service_hints,
                storage_hints,
                js_profile["script_urls"],
                js_profile["fetched_scripts"],
            )
            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save(report, "Client_Exposure_Recon")
        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc.reason}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
