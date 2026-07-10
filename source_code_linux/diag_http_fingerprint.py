#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


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


def fetch_profile(parsed_target, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    redirect_handler = CaptureRedirectHandler()
    opener = urllib.request.build_opener(redirect_handler, urllib.request.HTTPSHandler(context=ssl_ctx))

    request = urllib.request.Request(
        parsed_target.geturl(),
        headers={
            "User-Agent": "CyberSec-Recon-Console/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    with opener.open(request, timeout=8) as response:
        body = response.read(8192)
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


def find_cookie_markers(headers):
    markers = []
    raw_cookie_header = headers.get("Set-Cookie", "")
    lowered = raw_cookie_header.lower()
    if "phpsessid" in lowered:
        markers.append("PHP session cookie")
    if "laravel_session" in lowered:
        markers.append("Laravel session cookie")
    if "jsessionid" in lowered:
        markers.append("Java session cookie")
    if "asp.net_sessionid" in lowered or ".aspnetcore" in lowered:
        markers.append("ASP.NET session cookie")
    if "_shopify" in lowered or "cart_sig" in lowered:
        markers.append("Shopify cookie")
    if "wordpress_" in lowered or "wp-" in lowered:
        markers.append("WordPress cookie")
    return markers


def find_security_headers(headers):
    lowered_headers = {key.lower(): value for key, value in headers.items()}
    checks = [
        ("strict-transport-security", "HSTS"),
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ]
    present = [label for header, label in checks if header in lowered_headers]
    missing = [label for header, label in checks if header not in lowered_headers]
    return present, missing


def fingerprint(headers, body_preview):
    lowered_headers = {key.lower(): value for key, value in headers.items()}
    server = lowered_headers.get("server", "").lower()
    powered_by = lowered_headers.get("x-powered-by", "").lower()
    generator = lowered_headers.get("x-generator", "").lower()
    via = lowered_headers.get("via", "").lower()
    body = body_preview.lower()

    web_stack = []
    frameworks = []
    infrastructure = []
    observations = []
    confidence_points = 0

    def add_unique(collection, value):
        if value and value not in collection:
            collection.append(value)

    if "nginx" in server:
        add_unique(web_stack, "nginx")
        confidence_points += 3
    if "apache" in server:
        add_unique(web_stack, "Apache HTTP Server")
        confidence_points += 3
    if "openresty" in server:
        add_unique(web_stack, "OpenResty")
        confidence_points += 3
    if "litespeed" in server:
        add_unique(web_stack, "LiteSpeed")
        confidence_points += 3
    if "caddy" in server:
        add_unique(web_stack, "Caddy")
        confidence_points += 3
    if "iis" in server:
        add_unique(web_stack, "Microsoft IIS")
        confidence_points += 3
    if "envoy" in server:
        add_unique(web_stack, "Envoy")
        confidence_points += 2

    if "express" in powered_by:
        add_unique(frameworks, "Express")
        confidence_points += 3
    if "php" in powered_by:
        add_unique(web_stack, "PHP")
        confidence_points += 2
    if "asp.net" in powered_by:
        add_unique(frameworks, "ASP.NET")
        confidence_points += 3

    if "wp-content" in body or "wp-includes" in body or "/wp-json/" in body or "wordpress" in generator:
        add_unique(frameworks, "WordPress")
        confidence_points += 3
    if "woocommerce" in body:
        add_unique(frameworks, "WooCommerce")
        confidence_points += 2
    if "__next_data__" in body or "/_next/static/" in body or "x-powered-by: next.js" in body:
        add_unique(frameworks, "Next.js")
        confidence_points += 3
    if "__nuxt__" in body or "/_nuxt/" in body:
        add_unique(frameworks, "Nuxt.js")
        confidence_points += 3
    if "drupal-settings-json" in body or "drupalsettings" in body or "/sites/default/files/" in body:
        add_unique(frameworks, "Drupal")
        confidence_points += 3
    if "joomla!" in body or "com_content" in body:
        add_unique(frameworks, "Joomla")
        confidence_points += 3
    if "shopify" in body or "cdn.shopify.com" in body:
        add_unique(frameworks, "Shopify")
        confidence_points += 3
    if "react" in body and "__next_data__" not in body:
        add_unique(frameworks, "React (possible)")
        confidence_points += 1
    if "vue" in body and "__nuxt__" not in body:
        add_unique(frameworks, "Vue.js (possible)")
        confidence_points += 1
    if "ng-version" in body or "angular" in body:
        add_unique(frameworks, "Angular (possible)")
        confidence_points += 1
    if "bootstrap" in body:
        add_unique(frameworks, "Bootstrap assets")
        confidence_points += 1

    if "cloudflare" in server or "cf-ray" in lowered_headers:
        add_unique(infrastructure, "Cloudflare")
        confidence_points += 3
    if "x-vercel-id" in lowered_headers:
        add_unique(infrastructure, "Vercel")
        confidence_points += 3
    if "x-nf-request-id" in lowered_headers or "netlify" in server:
        add_unique(infrastructure, "Netlify")
        confidence_points += 3
    if "fastly" in via or "x-served-by" in lowered_headers:
        add_unique(infrastructure, "Fastly")
        confidence_points += 2
    if "akamai" in via or "akamai" in lowered_headers.get("x-cache", "").lower():
        add_unique(infrastructure, "Akamai")
        confidence_points += 2
    if "server-timing" in lowered_headers and "cdn-cache" in lowered_headers["server-timing"].lower():
        add_unique(infrastructure, "CDN cache layer")
        confidence_points += 1

    if "alt-svc" in lowered_headers:
        add_unique(observations, f"Alt-Svc advertised: {lowered_headers['alt-svc'][:80]}")
    if "strict-transport-security" in lowered_headers:
        add_unique(observations, "HSTS enabled")
    if headers.get("Set-Cookie"):
        add_unique(observations, "Set-Cookie header present")

    security_present, security_missing = find_security_headers(headers)

    if confidence_points >= 10:
        confidence = "High"
    elif confidence_points >= 5:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "web_stack": web_stack,
        "frameworks": frameworks,
        "infrastructure": infrastructure,
        "cookie_markers": find_cookie_markers(headers),
        "security_present": security_present,
        "security_missing": security_missing,
        "observations": observations,
        "confidence": confidence,
        "confidence_points": confidence_points,
    }


def print_section(title, values):
    print(f"\n {Y}{title}:{RESET}")
    if values:
        for value in values:
            print(f"  {G}- {value}{RESET}")
    else:
        print(f"  {R}- No clear indicators{RESET}")


def print_redirect_chain(redirects):
    print(f"\n {Y}REDIRECT CHAIN:{RESET}")
    if not redirects:
        print(f"  {G}- No redirects observed{RESET}")
        return

    for code, source_url, target_url in redirects:
        print(f"  {G}- [{code}] {source_url} -> {target_url}{RESET}")


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}HTTP TECH FINGERPRINT{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            tls_note = None
            try:
                result = fetch_profile(parsed_target, verify_tls=True)
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", "")
                if isinstance(reason, ssl.SSLCertVerificationError):
                    tls_note = f"TLS validation failed: {reason}"
                    result = fetch_profile(parsed_target, verify_tls=False)
                else:
                    raise

            findings = fingerprint(result["headers"], result["body_preview"])
            server = result["headers"].get("Server", "No information")
            powered_by = result["headers"].get("X-Powered-By", "No information")
            redirect_lines = [f"[{code}] {source_url} -> {target_url}" for code, source_url, target_url in result["redirects"]]

            print(f"\n {G}>>> FINGERPRINT SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            print(f" SERVER:         {server}")
            print(f" X-POWERED-BY:   {powered_by}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(f" CONFIDENCE:     {findings['confidence']} ({findings['confidence_points']} pts)")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")

            print_redirect_chain(result["redirects"])
            print_section("WEB STACK", findings["web_stack"])
            print_section("FRAMEWORK / CMS", findings["frameworks"])
            print_section("INFRASTRUCTURE", findings["infrastructure"])
            print_section("COOKIE MARKERS", findings["cookie_markers"])
            print_section("SECURITY HEADERS PRESENT", findings["security_present"])
            print_section("SECURITY HEADERS MISSING", findings["security_missing"])
            print_section("OBSERVATIONS", findings["observations"])

            report_lines = [
                f"HTTP TECH FINGERPRINT: {parsed_target.geturl()}",
                f"Final URL: {result['final_url']}",
                f"Status: {result['status']}",
                f"Server: {server}",
                f"X-Powered-By: {powered_by}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                f"Confidence: {findings['confidence']} ({findings['confidence_points']} pts)",
                "",
                "[Redirect Chain]",
                *(redirect_lines or ["No redirects observed"]),
                "",
                "[Web Stack]",
                *(findings["web_stack"] or ["No clear indicators"]),
                "",
                "[Framework / CMS]",
                *(findings["frameworks"] or ["No clear indicators"]),
                "",
                "[Infrastructure]",
                *(findings["infrastructure"] or ["No clear indicators"]),
                "",
                "[Cookie Markers]",
                *(findings["cookie_markers"] or ["No clear indicators"]),
                "",
                "[Security Headers Present]",
                *(findings["security_present"] or ["No clear indicators"]),
                "",
                "[Security Headers Missing]",
                *(findings["security_missing"] or ["No clear indicators"]),
                "",
                "[Observations]",
                *(findings["observations"] or ["No clear indicators"]),
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "HTTP_Tech_Fingerprint")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc.reason}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
