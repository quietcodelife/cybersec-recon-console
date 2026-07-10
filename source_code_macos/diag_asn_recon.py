#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress
import socket

import core_report
import core_utils

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

BGPVIEW_URL = "https://api.bgpview.io/ip/{ip}"
RDAP_URL = "https://rdap.org/ip/{ip}"
REQUEST_HEADERS = {
    "User-Agent": "CyberSec-Recon-Console/1.0",
    "Accept": "application/json",
}


def resolve_target(raw_target):
    target = core_utils.validate_host(raw_target).lower()
    try:
        ipaddress.ip_address(target)
        return target, [target], "ip"
    except ValueError:
        pass

    results = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    ips = []
    for entry in results:
        ip_value = entry[4][0]
        if ip_value not in ips:
            ips.append(ip_value)

    if not ips:
        raise ValueError("No IP addresses were resolved.")
    return target, ips, "domain"


def fetch_json(url):
    if requests is None:
        return None
    response = requests.get(url, headers=REQUEST_HEADERS, timeout=8)
    if response.status_code != 200:
        return None
    return response.json()


def fetch_bgpview(ip_value):
    payload = fetch_json(BGPVIEW_URL.format(ip=ip_value))
    if not payload:
        return {}

    data = payload.get("data", {})
    prefixes = data.get("prefixes") or []
    prefix_entry = prefixes[0] if prefixes else {}
    rir_name = ""
    if isinstance(prefix_entry.get("rir_allocation"), dict):
        rir_name = prefix_entry["rir_allocation"].get("rir_name", "")

    return {
        "asn": str(data.get("asn", "")) or "",
        "asn_name": data.get("name", "") or "",
        "description": data.get("description_short", "") or data.get("description", "") or "",
        "prefix": prefix_entry.get("prefix", "") or "",
        "prefix_name": prefix_entry.get("name", "") or "",
        "country": data.get("country_code", "") or "",
        "rir": rir_name,
    }


def extract_country_from_entities(entities):
    for entity in entities or []:
        for vcard in entity.get("vcardArray", [None, []])[1]:
            if isinstance(vcard, list) and len(vcard) >= 4 and vcard[0] == "adr":
                label = vcard[3]
                if isinstance(label, list) and label:
                    possible = str(label[-1]).strip()
                    if possible:
                        return possible
    return ""


def fetch_rdap(ip_value):
    payload = fetch_json(RDAP_URL.format(ip=ip_value))
    if not payload:
        return {}

    start = payload.get("startAddress", "") or ""
    end = payload.get("endAddress", "") or ""
    network_type = payload.get("type", "") or ""
    name = payload.get("name", "") or ""
    handle = payload.get("handle", "") or ""
    country = payload.get("country", "") or extract_country_from_entities(payload.get("entities"))

    remarks = []
    for item in payload.get("remarks", []) or []:
        for line in item.get("description", []) or []:
            cleaned = str(line).strip()
            if cleaned and cleaned not in remarks:
                remarks.append(cleaned)

    return {
        "network_name": name,
        "handle": handle,
        "start": start,
        "end": end,
        "network_type": network_type,
        "country": country,
        "remarks": remarks[:4],
    }


def classify_provider(profile_text):
    value = profile_text.lower()
    markers = [
        ("Cloudflare", ["cloudflare"]),
        ("Amazon Web Services", ["amazon", "aws", "amazonses", "ec2"]),
        ("Google Cloud", ["google", "gcp"]),
        ("Microsoft Azure", ["microsoft", "azure"]),
        ("Fastly", ["fastly"]),
        ("Akamai", ["akamai"]),
        ("OVHcloud", ["ovh"]),
        ("Hetzner", ["hetzner"]),
        ("DigitalOcean", ["digitalocean"]),
        ("Netlify", ["netlify"]),
        ("Vercel", ["vercel"]),
    ]
    for label, tokens in markers:
        if any(token in value for token in tokens):
            return label
    return "Unclassified"


def merge_profile(ip_value):
    bgp_profile = fetch_bgpview(ip_value)
    rdap_profile = fetch_rdap(ip_value)

    profile_text = " ".join(
        filter(
            None,
            [
                bgp_profile.get("asn_name", ""),
                bgp_profile.get("description", ""),
                bgp_profile.get("prefix_name", ""),
                rdap_profile.get("network_name", ""),
                " ".join(rdap_profile.get("remarks", [])),
            ],
        )
    )

    return {
        "ip": ip_value,
        "asn": bgp_profile.get("asn", ""),
        "asn_name": bgp_profile.get("asn_name", ""),
        "description": bgp_profile.get("description", ""),
        "prefix": bgp_profile.get("prefix", ""),
        "prefix_name": bgp_profile.get("prefix_name", ""),
        "rir": bgp_profile.get("rir", ""),
        "country": bgp_profile.get("country", "") or rdap_profile.get("country", ""),
        "network_name": rdap_profile.get("network_name", ""),
        "network_type": rdap_profile.get("network_type", ""),
        "handle": rdap_profile.get("handle", ""),
        "start": rdap_profile.get("start", ""),
        "end": rdap_profile.get("end", ""),
        "remarks": rdap_profile.get("remarks", []),
        "provider_guess": classify_provider(profile_text),
    }


def format_value(value, fallback="No data"):
    return value if value else fallback


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                      {Y}ASN / BGP RECON{RESET}")
        print(f"{C}================================================================{RESET}")

        if requests is None:
            print(f"\n {R}[ERROR]{RESET} Missing required Python module: 'requests'.")
            input("\n Enter...")
            break

        raw_target = input("\n Domain or IP (for example example.com or 8.8.8.8) [0=back]: ").strip()
        if raw_target in ("", "0"):
            break

        try:
            target, ips, target_type = resolve_target(raw_target)
            profiles = [merge_profile(ip_value) for ip_value in ips]
            unique_asns = sorted({item["asn"] for item in profiles if item["asn"]})
            unique_providers = sorted({item["provider_guess"] for item in profiles if item["provider_guess"]})

            print(f"\n {G}>>> ROUTING SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TARGET:         {target}")
            print(f" TARGET TYPE:    {target_type}")
            print(f" RESOLVED IPs:   {len(ips)}")
            print(f" UNIQUE ASNs:    {len(unique_asns)}")
            print(f" PROVIDERS:      {', '.join(unique_providers) if unique_providers else 'No data'}")
            print(" ----------------------------------------------------------------")

            for index, profile in enumerate(profiles, 1):
                print(f"\n {Y}IP PROFILE #{index}:{RESET}")
                print(f" IP:             {profile['ip']}")
                print(f" ASN:            {format_value(profile['asn'], 'Unavailable')}")
                print(f" ASN NAME:       {format_value(profile['asn_name'])}")
                print(f" DESCRIPTION:    {format_value(profile['description'])}")
                print(f" PREFIX:         {format_value(profile['prefix'])}")
                print(f" NETBLOCK:       {format_value(profile['start'])} - {format_value(profile['end'])}")
                print(f" NETWORK NAME:   {format_value(profile['network_name'])}")
                print(f" NETWORK TYPE:   {format_value(profile['network_type'])}")
                print(f" COUNTRY:        {format_value(profile['country'])}")
                print(f" RIR:            {format_value(profile['rir'])}")
                print(f" PROVIDER GUESS: {format_value(profile['provider_guess'])}")
                if profile["remarks"]:
                    print(" REMARKS:")
                    for remark in profile["remarks"]:
                        print(f"  - {remark}")

            report_lines = [
                f"ASN / BGP RECON: {target}",
                f"Target type: {target_type}",
                f"Resolved IP count: {len(ips)}",
                f"Unique ASNs: {', '.join(unique_asns) if unique_asns else 'none'}",
                f"Providers: {', '.join(unique_providers) if unique_providers else 'none'}",
            ]
            for profile in profiles:
                report_lines.extend(
                    [
                        "",
                        f"[{profile['ip']}]",
                        f"ASN: {profile['asn'] or 'Unavailable'}",
                        f"ASN Name: {profile['asn_name'] or 'No data'}",
                        f"Description: {profile['description'] or 'No data'}",
                        f"Prefix: {profile['prefix'] or 'No data'}",
                        f"Netblock: {profile['start'] or 'No data'} - {profile['end'] or 'No data'}",
                        f"Network Name: {profile['network_name'] or 'No data'}",
                        f"Network Type: {profile['network_type'] or 'No data'}",
                        f"Country: {profile['country'] or 'No data'}",
                        f"RIR: {profile['rir'] or 'No data'}",
                        f"Provider Guess: {profile['provider_guess'] or 'No data'}",
                    ]
                )
                for remark in profile["remarks"]:
                    report_lines.append(f"Remark: {remark}")

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "ASN_BGP_Recon")

        except socket.gaierror:
            print(f"\n {R}[ERROR]{RESET} Failed to resolve target.")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
