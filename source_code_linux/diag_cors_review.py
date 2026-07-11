#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
USER_AGENT = "CyberSec-Recon-Console/1.0"
TEST_ORIGIN = "https://evil.example"
NULL_ORIGIN = "null"
TEST_METHOD = "POST"
TEST_HEADERS = "Authorization, Content-Type, X-Requested-With"


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


def perform_request(parsed_target, method="GET", origin=TEST_ORIGIN, verify_tls=True, preflight=False):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    headers = {
        "User-Agent": USER_AGENT,
        "Origin": origin,
        "Accept": "*/*",
    }
    if preflight:
        headers["Access-Control-Request-Method"] = TEST_METHOD
        headers["Access-Control-Request-Headers"] = TEST_HEADERS

    request = urllib.request.Request(parsed_target.geturl(), method=method, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=8, context=ssl_ctx) as response:
            return {
                "status": response.status,
                "headers": dict(response.headers.items()),
                "final_url": response.geturl(),
                "tls_verified": verify_tls,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "headers": dict(exc.headers.items()),
            "final_url": exc.geturl(),
            "tls_verified": verify_tls,
            "error": None,
        }


def collect_profile(parsed_target):
    tls_notes = []
    try:
        baseline = perform_request(parsed_target, method="GET", origin=TEST_ORIGIN, verify_tls=True)
        preflight = perform_request(parsed_target, method="OPTIONS", origin=TEST_ORIGIN, verify_tls=True, preflight=True)
        null_origin = perform_request(parsed_target, method="GET", origin=NULL_ORIGIN, verify_tls=True)
        return baseline, preflight, null_origin, tls_notes
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLCertVerificationError):
            tls_notes.append(f"TLS validation failed: {reason}")
            baseline = perform_request(parsed_target, method="GET", origin=TEST_ORIGIN, verify_tls=False)
            preflight = perform_request(parsed_target, method="OPTIONS", origin=TEST_ORIGIN, verify_tls=False, preflight=True)
            null_origin = perform_request(parsed_target, method="GET", origin=NULL_ORIGIN, verify_tls=False)
            return baseline, preflight, null_origin, tls_notes
        raise


def header_value(headers, name):
    return headers.get(name, headers.get(name.title(), ""))


def split_csv(value):
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def evaluate_cors(baseline, preflight, null_origin):
    findings = []
    recommendations = []
    score = 100

    allow_origin = header_value(baseline["headers"], "Access-Control-Allow-Origin")
    allow_credentials = header_value(baseline["headers"], "Access-Control-Allow-Credentials").lower()
    vary = header_value(baseline["headers"], "Vary")
    null_allow_origin = header_value(null_origin["headers"], "Access-Control-Allow-Origin")

    preflight_origin = header_value(preflight["headers"], "Access-Control-Allow-Origin")
    preflight_methods = split_csv(header_value(preflight["headers"], "Access-Control-Allow-Methods"))
    preflight_headers = split_csv(header_value(preflight["headers"], "Access-Control-Allow-Headers"))
    preflight_max_age = header_value(preflight["headers"], "Access-Control-Max-Age")
    preflight_location = header_value(preflight["headers"], "Location")
    preflight_redirect = 300 <= int(preflight["status"]) < 400

    if allow_origin:
        findings.append(f"[INFO] GET response advertises ACAO: {allow_origin}")
    else:
        findings.append("[INFO] GET response does not advertise ACAO.")
        score -= 5

    if preflight_redirect:
        findings.append(f"[WARN] Preflight returned redirect status {preflight['status']}.")
        if preflight_location:
            findings.append(f"[INFO] Preflight redirect location: {preflight_location}")
        recommendations.append("Avoid redirecting CORS preflight requests. Return the final resource policy directly to OPTIONS requests.")
        score -= 20
    elif preflight_origin:
        findings.append(f"[INFO] Preflight response advertises ACAO: {preflight_origin}")
    else:
        findings.append("[WARN] Preflight response does not advertise ACAO.")
        recommendations.append("If cross-origin access is intended, define explicit preflight policy headers.")
        score -= 10

    if allow_origin == "*" and allow_credentials == "true":
        findings.append("[WEAK] ACAO is '*' while credentials are allowed.")
        recommendations.append("Do not combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.")
        score -= 50
    elif allow_origin == TEST_ORIGIN:
        findings.append("[WARN] Arbitrary test origin was reflected in ACAO.")
        recommendations.append("Avoid reflecting arbitrary Origin values without an allowlist.")
        score -= 30
    elif allow_origin == "*":
        findings.append("[INFO] Wildcard ACAO is enabled.")
        recommendations.append("Review whether wildcard cross-origin reads are necessary for this resource.")
        score -= 15
    else:
        findings.append("[OK] GET response did not reflect the arbitrary test origin.")

    if preflight_origin == TEST_ORIGIN:
        findings.append("[WARN] Preflight response reflected the arbitrary test origin.")
        recommendations.append("Restrict preflight origin handling to a defined allowlist.")
        score -= 20
    elif preflight_origin == "*":
        findings.append("[INFO] Preflight uses wildcard ACAO.")
        score -= 10

    if null_allow_origin == "null":
        findings.append("[WEAK] The server explicitly allows Origin: null.")
        recommendations.append("Avoid allowing Origin: null unless there is a specific, reviewed use case.")
        score -= 20

    if allow_credentials == "true":
        findings.append("[INFO] Credentials are allowed cross-origin.")
        recommendations.append("Allow credentials only for trusted origins and sensitive workflows that require them.")
        score -= 10

    if "origin" not in vary.lower() and (allow_origin == TEST_ORIGIN or preflight_origin == TEST_ORIGIN):
        findings.append("[WARN] Vary: Origin is missing while origin-specific behavior is present.")
        recommendations.append("Add Vary: Origin when responses change based on the Origin header.")
        score -= 15
    elif vary:
        findings.append(f"[OK] Vary header present: {vary}")

    if preflight_methods:
        findings.append(f"[INFO] Preflight methods: {', '.join(preflight_methods)}")
        if "*" in preflight_methods:
            recommendations.append("Avoid wildcard method policies where narrower method allowlists are possible.")
            score -= 10
    elif preflight_redirect:
        findings.append("[INFO] Preflight method policy could not be evaluated because the server redirected the OPTIONS request.")
    else:
        findings.append("[WARN] No preflight method policy was returned.")
        score -= 10

    if preflight_headers:
        findings.append(f"[INFO] Preflight headers: {', '.join(preflight_headers)}")
        if "*" in preflight_headers:
            recommendations.append("Avoid wildcard request-header policies where narrower allowlists are possible.")
            score -= 10
    elif preflight_redirect:
        findings.append("[INFO] Preflight header policy could not be evaluated because the server redirected the OPTIONS request.")
    else:
        findings.append("[WARN] No preflight header policy was returned.")
        score -= 8

    if preflight_max_age:
        findings.append(f"[INFO] Preflight cache duration: {preflight_max_age}")

    score = max(0, min(score, 100))
    if score >= 85:
        grade = "A"
        verdict = "Strong"
    elif score >= 70:
        grade = "B"
        verdict = "Good"
    elif score >= 55:
        grade = "C"
        verdict = "Moderate"
    elif score >= 35:
        grade = "D"
        verdict = "Weak"
    else:
        grade = "F"
        verdict = "High Risk"

    unique_recommendations = []
    for item in recommendations:
        if item not in unique_recommendations:
            unique_recommendations.append(item)

    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "findings": findings,
        "recommendations": unique_recommendations,
        "allow_origin": allow_origin or "No data",
        "allow_credentials": allow_credentials or "No data",
        "preflight_origin": preflight_origin or "No data",
        "preflight_methods": ", ".join(preflight_methods) if preflight_methods else "No data",
        "preflight_headers": ", ".join(preflight_headers) if preflight_headers else "No data",
        "preflight_location": preflight_location or "No data",
        "vary": vary or "No data",
    }


def build_report(parsed_target, baseline, preflight, null_origin, audit):
    lines = [
        "CORS MISCONFIGURATION REVIEW",
        "",
        f"Initial target: {parsed_target.geturl()}",
        f"GET status: {baseline['status']}",
        f"OPTIONS status: {preflight['status']}",
        f"NULL origin status: {null_origin['status']}",
        f"Score: {audit['score']}/100",
        f"Grade: {audit['grade']}",
        f"Verdict: {audit['verdict']}",
        "",
        "[Policy Summary]",
        f"- ACAO (GET): {audit['allow_origin']}",
        f"- ACAC (GET): {audit['allow_credentials']}",
        f"- ACAO (OPTIONS): {audit['preflight_origin']}",
        f"- ACAM: {audit['preflight_methods']}",
        f"- ACAH: {audit['preflight_headers']}",
        f"- Redirect Location: {audit['preflight_location']}",
        f"- Vary: {audit['vary']}",
        "",
        "[Findings]",
        *(f"- {item}" for item in audit["findings"]),
        "",
        "[Recommendations]",
        *([f"- {item}" for item in audit["recommendations"]] or ["- No hardening recommendations generated."]),
    ]
    return "\n".join(lines)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}CORS MISCONFIGURATION REVIEW{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            baseline, preflight, null_origin, tls_notes = collect_profile(parsed_target)
            audit = evaluate_cors(baseline, preflight, null_origin)

            print(f"\n {G}>>> CORS POSTURE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {baseline['final_url']}")
            print(f" GET STATUS:     {baseline['status']}")
            print(f" OPTIONS STATUS: {preflight['status']}")
            print(f" SCORE:          {audit['score']}/100")
            print(f" GRADE:          {audit['grade']}")
            print(f" VERDICT:        {audit['verdict']}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if baseline['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")
            for note in tls_notes:
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} CORS review continued in unverified certificate mode.")

            print(f"\n {Y}POLICY SNAPSHOT:{RESET}")
            print(f"  Test Origin:           {TEST_ORIGIN}")
            print(f"  Null Origin:           {NULL_ORIGIN}")
            print(f"  ACAO (GET):            {audit['allow_origin']}")
            print(f"  ACAC (GET):            {audit['allow_credentials']}")
            print(f"  ACAO (OPTIONS):        {audit['preflight_origin']}")
            print(f"  ACAM:                  {audit['preflight_methods']}")
            print(f"  ACAH:                  {audit['preflight_headers']}")
            print(f"  Redirect Location:     {audit['preflight_location']}")
            print(f"  Vary:                  {audit['vary']}")

            print(f"\n {Y}FINDINGS:{RESET}")
            for finding in audit["findings"]:
                print(f"  {finding}")

            print(f"\n {Y}HARDENING RECOMMENDATIONS:{RESET}")
            if audit["recommendations"]:
                for item in audit["recommendations"]:
                    print(f"  - {item}")
            else:
                print("  - No additional hardening guidance was generated.")

            report = build_report(parsed_target, baseline, preflight, null_origin, audit)
            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save(report, "CORS_Misconfiguration_Review")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc.reason}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
