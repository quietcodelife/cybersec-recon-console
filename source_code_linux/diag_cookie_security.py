#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

TRACKING_KEYWORDS = [
    "ga",
    "gid",
    "gcl",
    "utm",
    "visit",
    "stat",
    "track",
    "analytics",
    "pixel",
    "consent",
    "ab",
    "tab",
    "sgv",
]

SESSION_KEYWORDS = [
    "sess",
    "session",
    "auth",
    "token",
    "jwt",
    "login",
    "csrf",
    "sid",
    "phpsessid",
    "jsessionid",
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


def fetch_cookie_profile(parsed_target, verify_tls=True):
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
        headers = response.headers
        final_url = response.geturl()
        status = response.status
        set_cookie_values = headers.get_all("Set-Cookie") or []

    return {
        "status": status,
        "headers": dict(headers.items()),
        "set_cookies": set_cookie_values,
        "final_url": final_url,
        "redirects": redirect_handler.hops,
        "tls_verified": verify_tls,
    }


def parse_set_cookie(raw_cookie):
    parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return None

    name, value = parts[0].split("=", 1)
    attributes = {}
    flags = set()

    for part in parts[1:]:
        if "=" in part:
            key, attr_value = part.split("=", 1)
            attributes[key.strip().lower()] = attr_value.strip()
        else:
            flags.add(part.strip().lower())

    return {
        "name": name.strip(),
        "value_preview": value[:24] + ("..." if len(value) > 24 else ""),
        "attributes": attributes,
        "flags": flags,
        "raw": raw_cookie,
    }


def classify_cookie_purpose(cookie):
    name = cookie["name"].lower()
    combined = " ".join([name, cookie["raw"].lower()])

    if any(keyword in combined for keyword in SESSION_KEYWORDS):
        return "Session / Authentication"
    if any(keyword in combined for keyword in TRACKING_KEYWORDS):
        return "Analytics / Tracking"
    return "General"


def evaluate_cookie(cookie, parsed_target):
    attributes = cookie["attributes"]
    flags = cookie["flags"]
    issues = []
    score = 20

    secure = "secure" in flags
    httponly = "httponly" in flags
    samesite = attributes.get("samesite", "")
    domain_attr = attributes.get("domain", "")
    path_attr = attributes.get("path", "")
    expires_attr = attributes.get("expires", "")
    max_age_attr = attributes.get("max-age", "")
    purpose = classify_cookie_purpose(cookie)
    is_tracking_cookie = purpose == "Analytics / Tracking"
    is_session_cookie = purpose == "Session / Authentication"

    if secure:
        score += 20
    else:
        issues.append("Missing Secure flag")

    if httponly:
        score += 20 if is_session_cookie else 10
    else:
        if is_session_cookie:
            issues.append("Missing HttpOnly flag on a session-oriented cookie")
        elif not is_tracking_cookie:
            issues.append("Missing HttpOnly flag")

    if samesite:
        normalized_samesite = samesite.lower()
        if normalized_samesite == "strict":
            score += 25
        elif normalized_samesite == "lax":
            score += 20
        elif normalized_samesite == "none":
            score += 15 if secure else 5
            if not secure:
                issues.append("SameSite=None without Secure flag")
        else:
            issues.append(f"Unrecognized SameSite value: {samesite}")
    else:
        issues.append("Missing SameSite attribute")

    if domain_attr:
        clean_domain = domain_attr.lstrip(".").lower()
        host = (parsed_target.hostname or "").lower()
        if clean_domain == host:
            score += 10
        else:
            score += 7
            issues.append(f"Review Domain scope: {domain_attr}")
    else:
        score += 10

    if path_attr == "/":
        score += 5
    elif path_attr:
        score += 3

    persistence = "Session"
    if max_age_attr:
        persistence = f"Persistent (Max-Age={max_age_attr})"
    elif expires_attr:
        persistence = f"Persistent (Expires={expires_attr})"

    if expires_attr:
        try:
            expires_dt = parsedate_to_datetime(expires_attr)
            if expires_dt.year >= 2035:
                issues.append("Long-lived cookie expiration")
        except Exception:
            issues.append("Unparsed Expires attribute")

    score = min(score, 100)
    if score >= 85:
        posture = "Strong"
    elif score >= 60:
        posture = "Moderate"
    else:
        posture = "Weak"

    return {
        "name": cookie["name"],
        "value_preview": cookie["value_preview"],
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite or "Missing",
        "domain": domain_attr or "Host-only",
        "path": path_attr or "No explicit path",
        "persistence": persistence,
        "purpose": purpose,
        "score": score,
        "posture": posture,
        "issues": issues,
        "raw": cookie["raw"],
    }


def summarize_profiles(profiles):
    findings = []
    recommendations = []
    weak_count = sum(1 for profile in profiles if profile["posture"] == "Weak")
    strong_count = sum(1 for profile in profiles if profile["posture"] == "Strong")

    if not profiles:
        findings.append("No Set-Cookie headers were returned by the target.")
        recommendations.append("No cookie hardening review was possible because no cookies were observed.")
        return {
            "average_score": None,
            "grade": "N/A",
            "findings": findings,
            "recommendations": recommendations,
        }

    average_score = int(sum(profile["score"] for profile in profiles) / len(profiles))
    if average_score >= 85:
        grade = "A"
    elif average_score >= 70:
        grade = "B"
    elif average_score >= 55:
        grade = "C"
    elif average_score >= 40:
        grade = "D"
    else:
        grade = "F"

    findings.append(f"Observed cookies: {len(profiles)}")
    findings.append(f"Strong posture cookies: {strong_count}")
    findings.append(f"Weak posture cookies: {weak_count}")

    if any(not profile["secure"] for profile in profiles):
        recommendations.append("Set the Secure flag on all session and authentication cookies.")
    if any(not profile["httponly"] for profile in profiles):
        recommendations.append("Set HttpOnly on cookies that are not required in client-side JavaScript.")
    if any(profile["samesite"] == "Missing" for profile in profiles):
        recommendations.append("Define SameSite explicitly to reduce CSRF exposure.")
    if any("Review Domain scope" in issue for profile in profiles for issue in profile["issues"]):
        recommendations.append("Reduce cookie Domain scope where subdomain sharing is not required.")
    if any("Long-lived cookie expiration" in issue for profile in profiles for issue in profile["issues"]):
        recommendations.append("Shorten persistent cookie lifetime for sensitive sessions.")

    if not recommendations:
        recommendations.append("Cookie posture looks solid in the visible response set.")

    unique_recommendations = []
    for item in recommendations:
        if item not in unique_recommendations:
            unique_recommendations.append(item)

    return {
        "average_score": average_score,
        "grade": grade,
        "findings": findings,
        "recommendations": unique_recommendations,
    }


def print_redirect_chain(redirects):
    print(f"\n {Y}REDIRECT CHAIN:{RESET}")
    if not redirects:
        print("  - No redirects observed")
        return
    for code, source, destination in redirects:
        print(f"  - [{code}] {source} -> {destination}")


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}COOKIE SECURITY AUDIT{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            tls_note = None
            try:
                result = fetch_cookie_profile(parsed_target, verify_tls=True)
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", "")
                if isinstance(reason, ssl.SSLCertVerificationError):
                    tls_note = f"TLS validation failed: {reason}"
                    result = fetch_cookie_profile(parsed_target, verify_tls=False)
                else:
                    raise

            parsed_cookies = [parse_set_cookie(item) for item in result["set_cookies"]]
            parsed_cookies = [item for item in parsed_cookies if item]
            profiles = [evaluate_cookie(item, parsed_target) for item in parsed_cookies]
            summary = summarize_profiles(profiles)

            print(f"\n {G}>>> COOKIE POSTURE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            score_label = f"{summary['average_score']}/100" if summary["average_score"] is not None else "Not applicable"
            print(f" SCORE:          {score_label}")
            print(f" GRADE:          {summary['grade']}")
            print(f" COOKIES:        {len(profiles)}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")
                print(f" {Y}[TLS NOTICE]{RESET} Cookie collection continued in unverified certificate mode.")

            print_redirect_chain(result["redirects"])

            print(f"\n {Y}SUMMARY FINDINGS:{RESET}")
            for item in summary["findings"]:
                print(f"  - {item}")

            print(f"\n {Y}COOKIE DETAILS:{RESET}")
            if profiles:
                for profile in profiles:
                    print(f"\n  {profile['name']}  [{profile['posture']}]")
                    print(f"   Score:        {profile['score']}/100")
                    print(f"   Purpose:      {profile['purpose']}")
                    print(f"   Value:        {profile['value_preview']}")
                    print(f"   Secure:       {'Yes' if profile['secure'] else 'No'}")
                    print(f"   HttpOnly:     {'Yes' if profile['httponly'] else 'No'}")
                    print(f"   SameSite:     {profile['samesite']}")
                    print(f"   Domain:       {profile['domain']}")
                    print(f"   Path:         {profile['path']}")
                    print(f"   Persistence:  {profile['persistence']}")
                    if profile["issues"]:
                        print("   Issues:")
                        for issue in profile["issues"]:
                            print(f"    - {issue}")
            else:
                print("  No cookies were observed.")

            print(f"\n {Y}HARDENING RECOMMENDATIONS:{RESET}")
            for item in summary["recommendations"]:
                print(f"  - {item}")

            report_lines = [
                f"COOKIE SECURITY AUDIT: {parsed_target.geturl()}",
                f"Final URL: {result['final_url']}",
                f"Status: {result['status']}",
                f"Score: {score_label}",
                f"Grade: {summary['grade']}",
                f"Cookies Observed: {len(profiles)}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                "",
                "[Redirect Chain]",
                *([f"[{code}] {source} -> {destination}" for code, source, destination in result["redirects"]] or ["No redirects observed"]),
                "",
                "[Summary Findings]",
                *(summary["findings"] or ["No data available"]),
                "",
                "[Recommendations]",
                *(summary["recommendations"] or ["No data available"]),
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])
            for profile in profiles:
                report_lines.extend(
                    [
                        "",
                        f"[Cookie] {profile['name']}",
                        f"Score: {profile['score']}/100",
                        f"Posture: {profile['posture']}",
                        f"Purpose: {profile['purpose']}",
                        f"Secure: {'Yes' if profile['secure'] else 'No'}",
                        f"HttpOnly: {'Yes' if profile['httponly'] else 'No'}",
                        f"SameSite: {profile['samesite']}",
                        f"Domain: {profile['domain']}",
                        f"Path: {profile['path']}",
                        f"Persistence: {profile['persistence']}",
                        f"Value Preview: {profile['value_preview']}",
                    ]
                )
                for issue in profile["issues"]:
                    report_lines.append(f"Issue: {issue}")

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Cookie_Security_Audit")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc.reason}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
