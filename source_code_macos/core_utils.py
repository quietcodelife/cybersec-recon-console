#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib
import ipaddress
import platform
import shutil


REQUIRED_PYTHON_MODULES = [
    "requests",
]

REQUIRED_SYSTEM_COMMANDS = [
    "ifconfig",
    "arp",
    "netstat",
    "ping",
    "nslookup",
    "traceroute",
    "networksetup",
    "system_profiler",
    "pfctl",
    "dscacheutil",
    "nano",
]


def command_exists(command_name):
    return shutil.which(command_name) is not None


def missing_commands(*command_names):
    return [name for name in command_names if not command_exists(name)]


def missing_python_modules(*module_names):
    missing = []
    for module_name in module_names:
        try:
            importlib.import_module(module_name)
        except Exception:
            missing.append(module_name)
    return missing


def is_linux_platform():
    return platform.system().lower() == "linux"


def is_macos_platform():
    return platform.system().lower() == "darwin"


def validate_host(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("No address was provided.")

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if any(ch not in allowed for ch in value):
        raise ValueError("Address contains invalid characters.")

    if value.startswith(("-", ".")) or value.endswith(("-", ".")):
        raise ValueError("Address format is invalid.")

    return value


def validate_ipv4(value):
    value = (value or "").strip()
    ipaddress.IPv4Address(value)
    return value
