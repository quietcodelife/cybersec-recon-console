#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, core_report, core_config

def run():
    core_config.clear_screen()
    print("=== IP GEOLOCATION ===\n")
    print(" [i] Retrieving data...")
    
    try:
        import requests
        response = requests.get("http://ip-api.com/json/", timeout=5).json()
        if response['status'] == 'success':
            data = f"""
 IP ADDRESS:  {response['query']}
 COUNTRY:     {response['country']} ({response['countryCode']})
 CITY:        {response['city']}
 REGION:      {response['regionName']}
 PROVIDER:    {response['isp']}
"""
            print(data)
            print("-" * 40)
            if input(" [?] Save report? (y/n): ").lower() == 'y':
                core_report.save(data, "GeoIP_Report")
        else:
            print(" [!] API error.")
    except Exception as e:
        print(f" [!] Connection error: {e}")
        
    input("\n Enter...")
