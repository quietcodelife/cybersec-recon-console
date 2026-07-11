#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import html
import os
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import core_config
import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


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


def fetch_page(parsed_target, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    request = urllib.request.Request(
        parsed_target.geturl(),
        headers={
            "User-Agent": "CyberSec-Recon-Console/1.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        },
    )
    with opener.open(request, timeout=10) as response:
        body = response.read(8192).decode("utf-8", errors="replace")
        final_url = response.geturl()
        status = response.status
        content_type = response.headers.get("Content-Type", "No information")
    return {
        "body": body,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "tls_verified": verify_tls,
    }


def extract_title(html_text):
    match = TITLE_PATTERN.search(html_text or "")
    if not match:
        return "No HTML title found"
    title = html.unescape(re.sub(r"\s+", " ", match.group(1)).strip())
    return title or "No HTML title found"


def safe_stem(hostname):
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", hostname)


def capture_screenshot(url, hostname):
    os.makedirs(core_config.REPORTS_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    stem = safe_stem(hostname)

    if core_utils.command_exists("wkhtmltoimage"):
        output_path = os.path.join(core_config.REPORTS_DIR, f"HTTP_Capture_{stem}_{stamp}.png")
        subprocess.run(
            ["wkhtmltoimage", "--quiet", url, output_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return output_path, "wkhtmltoimage"

    if core_utils.command_exists("cutycapt"):
        output_path = os.path.join(core_config.REPORTS_DIR, f"HTTP_Capture_{stem}_{stamp}.png")
        subprocess.run(
            ["cutycapt", f"--url={url}", f"--out={output_path}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return output_path, "cutycapt"

    return None, None


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"              {Y}HTTP SCREENSHOT / TITLE GRABBER{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            tls_note = None
            try:
                result = fetch_page(parsed_target, verify_tls=True)
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", "")
                if isinstance(reason, ssl.SSLCertVerificationError):
                    tls_note = f"TLS validation failed: {reason}"
                    result = fetch_page(parsed_target, verify_tls=False)
                else:
                    raise
            title = extract_title(result["body"])
            screenshot_path, screenshot_engine = capture_screenshot(result["final_url"], parsed_target.hostname)

            print(f"\n {G}>>> HTTP CAPTURE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            print(f" CONTENT-TYPE:   {result['content_type']}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(f" TITLE:          {title}")
            print(
                f" SCREENSHOT:     "
                f"{screenshot_path if screenshot_path else 'No renderer available (wkhtmltoimage / cutycapt not found)'}"
            )
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")
                print(f" {Y}[TLS NOTICE]{RESET} Page capture continued in unverified certificate mode.")

            report_lines = [
                f"HTTP SCREENSHOT / TITLE GRABBER: {parsed_target.geturl()}",
                f"Final URL: {result['final_url']}",
                f"Status: {result['status']}",
                f"Content-Type: {result['content_type']}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                f"Title: {title}",
                f"Screenshot Engine: {screenshot_engine or 'Unavailable'}",
                f"Screenshot Path: {screenshot_path or 'Not captured'}",
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])

            if input("\n [?] Save text report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "HTTP_Capture")

        except subprocess.CalledProcessError:
            print(f"\n {R}[ERROR]{RESET} Screenshot renderer failed while capturing the page.")
        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc.reason}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
