"""Utilities for parsing Nmap results into structured pandas DataFrames."""
from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd


PORT_COLUMNS = ["ip", "hostname", "port", "state", "service", "product"]


def parse_xml(path: Path) -> List[Dict[str, Any]]:
    root = ET.parse(path).getroot()
    hosts = []
    for host in root.findall("host"):
        ip = host.find("address").attrib.get("addr", "unknown")
        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.attrib.get("name") if hostname_node is not None else ""
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port in ports_node.findall("port"):
            service_node = port.find("service")
            hosts.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "port": int(port.attrib.get("portid", 0)),
                    "state": port.find("state").attrib.get("state", "unknown"),
                    "service": service_node.attrib.get("name") if service_node is not None else "",
                    "product": service_node.attrib.get("product") if service_node is not None else "",
                }
            )
    return hosts


def parse_json(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [
        {**port, "ip": host["ip"], "hostname": host.get("hostname", "")}
        for host in data.get("hosts", [])
        for port in host.get("ports", [])
    ]


def parse_results(path: Path) -> pd.DataFrame:
    if path.suffix == ".xml":
        records = parse_xml(path)
    else:
        records = parse_json(path)
    return pd.DataFrame.from_records(records, columns=PORT_COLUMNS)


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

    df = parse_results(args.scan_file)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.output, index=False)
    else:
        print(df)


if __name__ == "__main__":
    main()
