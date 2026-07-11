#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


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
    port_suffix = ""
    if parsed_target.port:
        port_suffix = f":{parsed_target.port}"
    return f"{parsed_target.scheme}://{parsed_target.hostname}{port_suffix}"


def fetch_url(url, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CyberSec-Recon-Console/1.0",
            "Accept": "text/plain,application/xml,text/xml,*/*",
        },
    )

    with opener.open(request, timeout=8) as response:
        content = response.read(1024 * 1024)
        return {
            "status": response.status,
            "final_url": response.geturl(),
            "headers": dict(response.headers.items()),
            "content": content.decode("utf-8", errors="replace"),
            "tls_verified": verify_tls,
        }


def safe_fetch(url):
    tls_notice = None
    try:
        return fetch_url(url, verify_tls=True), tls_notice
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLCertVerificationError):
            tls_notice = f"TLS validation failed for {url}: {reason}"
            return fetch_url(url, verify_tls=False), tls_notice
        raise


def parse_robots(content):
    user_agents = []
    allows = []
    disallows = []
    sitemaps = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            user_agents.append(value)
        elif key == "allow":
            allows.append(value)
        elif key == "disallow":
            disallows.append(value)
        elif key == "sitemap":
            sitemaps.append(value)

    return {
        "user_agents": user_agents,
        "allows": allows,
        "disallows": disallows,
        "sitemaps": sitemaps,
    }


def parse_sitemap(content):
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return {
            "type": "unparsed",
            "entries": [],
            "count": 0,
        }

    entries = []
    root_tag = root.tag.lower()

    if root_tag.endswith("urlset"):
        entry_type = "urlset"
        for element in root.iter():
            if element.tag.lower().endswith("loc") and (element.text or "").strip():
                entries.append(element.text.strip())
    elif root_tag.endswith("sitemapindex"):
        entry_type = "sitemapindex"
        for element in root.iter():
            if element.tag.lower().endswith("loc") and (element.text or "").strip():
                entries.append(element.text.strip())
    else:
        entry_type = "xml"

    return {
        "type": entry_type,
        "entries": entries,
        "count": len(entries),
    }


def print_list_block(title, values, limit=10):
    print(f"\n {Y}{title}:{RESET}")
    if not values:
        print("  none")
        return

    for value in values[:limit]:
        print(f"  - {value}")

    if len(values) > limit:
        print(f"  ... {len(values) - limit} more")


def collect_sitemap_candidates(base_url, robots_data):
    candidates = []
    if robots_data:
        for item in robots_data.get("sitemaps", []):
            value = item.strip()
            if value and value not in candidates:
                candidates.append(value)

    default_sitemap = urllib.parse.urljoin(base_url + "/", "sitemap.xml")
    if default_sitemap not in candidates:
        candidates.append(default_sitemap)
    return candidates


def fetch_first_available_sitemap(candidates, tls_notices):
    attempts = []
    for sitemap_url in candidates:
        try:
            result, tls_notice = safe_fetch(sitemap_url)
            if tls_notice and tls_notice not in tls_notices:
                tls_notices.append(tls_notice)
            return result, None, sitemap_url, attempts
        except urllib.error.HTTPError as exc:
            attempts.append((sitemap_url, f"{exc.code} {exc.reason}"))
        except urllib.error.URLError as exc:
            attempts.append((sitemap_url, str(exc.reason)))

    if attempts:
        last_url, last_error = attempts[-1]
        return None, last_error, last_url, attempts
    return None, "No sitemap candidate was available", "", attempts


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}ROBOTS / SITEMAP RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            base_url = build_base_url(parsed_target)
            robots_url = urllib.parse.urljoin(base_url + "/", "robots.txt")
            tls_notices = []
            robots_result = None
            sitemap_result = None
            robots_error = None
            sitemap_error = None
            sitemap_source_url = ""
            sitemap_attempts = []

            try:
                robots_result, tls_notice = safe_fetch(robots_url)
                if tls_notice:
                    tls_notices.append(tls_notice)
            except urllib.error.HTTPError as exc:
                robots_error = f"{exc.code} {exc.reason}"
            except urllib.error.URLError as exc:
                robots_error = str(exc.reason)

            robots_data = parse_robots(robots_result["content"]) if robots_result else None
            sitemap_candidates = collect_sitemap_candidates(base_url, robots_data)
            sitemap_result, sitemap_error, sitemap_source_url, sitemap_attempts = fetch_first_available_sitemap(
                sitemap_candidates, tls_notices
            )
            sitemap_data = parse_sitemap(sitemap_result["content"]) if sitemap_result else None

            print(f"\n {G}>>> RESOURCE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TARGET:         {base_url}")
            print(f" ROBOTS.TXT:     {G + str(robots_result['status']) + RESET if robots_result else R + 'UNAVAILABLE' + RESET}")
            print(f" SITEMAP:        {G + str(sitemap_result['status']) + RESET if sitemap_result else R + 'UNAVAILABLE' + RESET}")
            print(" ----------------------------------------------------------------")

            if tls_notices:
                for notice in tls_notices:
                    print(f" {Y}[TLS NOTICE]{RESET} {notice}")
                    print(f" {Y}[TLS NOTICE]{RESET} Collection continued in unverified certificate mode.")

            if robots_result:
                print(f"\n {Y}ROBOTS.TXT DETAILS:{RESET}")
                print(f" Final URL:      {robots_result['final_url']}")
                print(f" TLS Verify:     {G + 'OK' + RESET if robots_result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
                print_list_block("User-Agent rules", robots_data["user_agents"], limit=8)
                print_list_block("Allow paths", robots_data["allows"], limit=8)
                print_list_block("Disallow paths", robots_data["disallows"], limit=12)
                print_list_block("Sitemap references", robots_data["sitemaps"], limit=8)
            else:
                print(f"\n {R}[ROBOTS.TXT]{RESET} {robots_error or 'Not available'}")

            if sitemap_result:
                print(f"\n {Y}SITEMAP DETAILS:{RESET}")
                print(f" Source URL:     {sitemap_source_url}")
                print(f" Final URL:      {sitemap_result['final_url']}")
                print(f" TLS Verify:     {G + 'OK' + RESET if sitemap_result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
                print(f" XML Type:       {sitemap_data['type']}")
                print(f" Entry Count:    {sitemap_data['count']}")
                print_list_block("Sample entries", sitemap_data["entries"], limit=12)
            else:
                print(f"\n {R}[SITEMAP]{RESET} {sitemap_error or 'Not available'}")
                if sitemap_attempts:
                    print_list_block(
                        "Sitemap attempts",
                        [f"{url} -> {error}" for url, error in sitemap_attempts],
                        limit=8,
                    )

            report_lines = [
                f"ROBOTS / SITEMAP RECON: {base_url}",
                f"robots.txt: {robots_result['status'] if robots_result else 'UNAVAILABLE'}",
                f"sitemap: {sitemap_result['status'] if sitemap_result else 'UNAVAILABLE'}",
            ]

            for notice in tls_notices:
                report_lines.append(f"TLS Warning: {notice}")

            if robots_result:
                report_lines.extend(
                    [
                        "",
                        "[robots.txt]",
                        f"Final URL: {robots_result['final_url']}",
                        f"TLS Verify: {'OK' if robots_result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                        f"User-Agent rules: {len(robots_data['user_agents'])}",
                        f"Allow paths: {len(robots_data['allows'])}",
                        f"Disallow paths: {len(robots_data['disallows'])}",
                        f"Sitemap references: {len(robots_data['sitemaps'])}",
                    ]
                )
                for item in robots_data["disallows"][:20]:
                    report_lines.append(f"DISALLOW {item}")
            else:
                report_lines.extend(["", f"[robots.txt] {robots_error or 'Not available'}"])

            if sitemap_result:
                report_lines.extend(
                    [
                        "",
                        "[sitemap]",
                        f"Source URL: {sitemap_source_url}",
                        f"Final URL: {sitemap_result['final_url']}",
                        f"TLS Verify: {'OK' if sitemap_result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                        f"XML Type: {sitemap_data['type']}",
                        f"Entry Count: {sitemap_data['count']}",
                    ]
                )
                for item in sitemap_data["entries"][:20]:
                    report_lines.append(f"ENTRY {item}")
            else:
                report_lines.extend(["", f"[sitemap] {sitemap_error or 'Not available'}"])
                for url, error in sitemap_attempts:
                    report_lines.append(f"ATTEMPT {url} -> {error}")

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Robots_Sitemap_Recon")

        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
