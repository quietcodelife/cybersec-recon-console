#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ssl

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
TLS_PORTS = {443, 465, 587, 993, 995, 8443}


def parse_ports(raw_value):
    raw_value = (raw_value or "").strip()
    if not raw_value:
        return DEFAULT_PORTS
    ports = []
    for item in raw_value.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")
        ports.append(port)
    return ports


def request_payload(port):
    if port in (80, 443, 8080, 8443):
        return b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n"
    return b"\r\n"


def read_plain_banner(host, port):
    with socket.create_connection((host, port), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(request_payload(port))
        return sock.recv(512)


def read_tls_banner(host, port):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=3) as sock:
        sock.settimeout(3)
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(3)
            tls_sock.sendall(request_payload(port))
            return tls_sock.recv(512)


def grab_banner(host, port):
    if port in TLS_PORTS:
        try:
            data = read_tls_banner(host, port)
        except ssl.SSLError:
            data = read_plain_banner(host, port)
    else:
        data = read_plain_banner(host, port)
    return data.decode("utf-8", errors="replace").strip() or "No banner captured"


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}SERVICE BANNER GRABBER{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n Host or IP [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            host = core_utils.validate_host(target)
            ports = parse_ports(input(" Ports (comma-separated, Enter for defaults): ").strip())
            results = []

            print(f"\n [i] Grabbing banners from {host}...")
            for port in ports:
                try:
                    banner = grab_banner(host, port)
                    results.append((port, "OPEN", banner.splitlines()[0][:120]))
                except Exception as exc:
                    results.append((port, "NO BANNER", str(exc)[:120]))

            print(f"\n {G}>>> BANNER SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TARGET:         {host}")
            print(f" PORT COUNT:     {len(ports)}")
            print(" ----------------------------------------------------------------")

            for port, state, note in results:
                color = G if state == "OPEN" else Y
                print(f" {color}[{port:>5}]{RESET} {state:<10} {note}")

            report_lines = [
                f"SERVICE BANNER GRABBER: {host}",
                f"Ports Tested: {', '.join(str(port) for port in ports)}",
                "",
                "[Results]",
                *[f"{port} | {state} | {note}" for port, state, note in results],
            ]

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Banner_Grab")

        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
