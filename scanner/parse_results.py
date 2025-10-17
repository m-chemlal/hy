"""Utilities for parsing Nmap results into structured records."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List

PORT_COLUMNS = ["ip", "hostname", "port", "state", "service", "product"]


def parse_xml(path: Path) -> List[Dict[str, Any]]:
    root = ET.parse(path).getroot()
    hosts = []
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.attrib.get("addr", "unknown") if address is not None else "unknown"
        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.attrib.get("name") if hostname_node is not None else ""
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port in ports_node.findall("port"):
            state_node = port.find("state")
            service_node = port.find("service")
            hosts.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "port": int(port.attrib.get("portid", 0)),
                    "state": state_node.attrib.get("state", "unknown") if state_node is not None else "unknown",
                    "service": service_node.attrib.get("name", "") if service_node is not None else "",
                    "product": service_node.attrib.get("product", "") if service_node is not None else "",
                }
            )
    return hosts


def parse_json(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [
        {**port, "ip": host.get("ip", "unknown"), "hostname": host.get("hostname", "")}
        for host in data.get("hosts", [])
        for port in host.get("ports", [])
    ]


def parse_results(path: Path) -> List[Dict[str, Any]]:
    if path.suffix == ".xml":
        return parse_xml(path)
    return parse_json(path)


def write_csv(records: Iterable[Dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=PORT_COLUMNS)
        writer.writeheader()
        for row in records:
            writer.writerow({key: row.get(key, "") for key in PORT_COLUMNS})


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Nmap scan results")
    parser.add_argument("scan_file", type=Path, help="Path to the Nmap output file")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to store the parsed CSV",
    )
    args = parser.parse_args()

    records = parse_results(args.scan_file)
    if args.output:
        write_csv(records, args.output)
    else:
        print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
