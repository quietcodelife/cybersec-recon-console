#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import core_config
import core_report

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                       {Y}GEOIP FOOTPRINT{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Retrieving public IP geolocation...\n")

    try:
        import requests
        response = requests.get("http://ip-api.com/json/", timeout=5).json()
        if response["status"] == "success":
            ip_address = response.get("query", "No data")
            country = response.get("country", "No data")
            country_code = response.get("countryCode", "--")
            city = response.get("city", "No data")
            region = response.get("regionName", "No data")
            provider = response.get("isp", "No data")
            timezone = response.get("timezone", "No data")
            org = response.get("org", "No data")

            print(f" {G}>>> GEOIP SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" IP ADDRESS:     {ip_address}")
            print(f" COUNTRY:        {country} ({country_code})")
            print(f" REGION:         {region}")
            print(f" CITY:           {city}")
            print(f" TIMEZONE:       {timezone}")
            print(f" PROVIDER:       {provider}")
            print(f" ORGANIZATION:   {org}")
            print(" ----------------------------------------------------------------")

            data = "\n".join([
                "GEOIP FOOTPRINT",
                f"IP Address: {ip_address}",
                f"Country: {country} ({country_code})",
                f"Region: {region}",
                f"City: {city}",
                f"Timezone: {timezone}",
                f"Provider: {provider}",
                f"Organization: {org}",
            ])

            if input(" [?] Save report? (y/n): ").lower() == 'y':
                core_report.save(data, "GeoIP_Report")
        else:
            print(f" {R}[API ERROR]{RESET} The geolocation source did not return a successful result.")
    except Exception as e:
        print(f" {R}[CONNECTION ERROR]{RESET} {e}")

    input("\n Enter...")
