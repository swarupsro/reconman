from __future__ import annotations

import os
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from flask import current_app


class ScanExecutionError(RuntimeError):
    pass


def execute_nmap_scan(target: str, profile_args: list[str], timeout: int, stop_checker) -> dict:
    # Build the subprocess argument vector from whitelisted values only.
    xml_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    xml_file.close()
    command = [
        current_app.config["NMAP_BINARY"],
        *profile_args,
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        xml_file.name,
        target,
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    start_monotonic = time.monotonic()
    try:
        while process.poll() is None:
            # Poll the database-backed stop flag so operators can stop a running host.
            if stop_checker():
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise ScanExecutionError("Scan was stopped by an operator.")
            if time.monotonic() - start_monotonic > timeout + 30:
                process.kill()
                raise ScanExecutionError("Scan exceeded the configured timeout.")
            time.sleep(1)

        stdout, stderr = process.communicate(timeout=10)
        xml_output = Path(xml_file.name).read_text(encoding="utf-8", errors="replace") if os.path.exists(xml_file.name) else ""
    finally:
        if os.path.exists(xml_file.name):
            os.unlink(xml_file.name)

    if process.returncode not in (0, 1):
        raise ScanExecutionError(stderr.strip() or "Nmap returned an unexpected error.")

    return {
        "command": command,
        "raw_output": stdout,
        "stderr": stderr,
        "xml_output": xml_output,
        "parsed": parse_nmap_xml(xml_output),
    }


def parse_nmap_xml(xml_output: str) -> dict:
    if not xml_output.strip():
        return {"hosts": []}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise ScanExecutionError("Failed to parse Nmap XML output.") from exc

    hosts: list[dict] = []
    for host in root.findall("host"):
        addresses = [node.get("addr") for node in host.findall("address") if node.get("addr")]
        hostnames = [node.get("name") for node in host.findall("hostnames/hostname") if node.get("name")]
        status_node = host.find("status")
        host_state = status_node.get("state", "unknown") if status_node is not None else "unknown"
        ports: list[dict] = []

        for port_node in host.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            if state_node is None:
                continue
            ports.append(
                {
                    "protocol": port_node.get("protocol", ""),
                    "port": int(port_node.get("portid", "0")),
                    "state": state_node.get("state", "unknown"),
                    "service": service_node.get("name", "") if service_node is not None else "",
                    "product": service_node.get("product", "") if service_node is not None else "",
                    "version": service_node.get("version", "") if service_node is not None else "",
                    "extra_info": service_node.get("extrainfo", "") if service_node is not None else "",
                }
            )

        top_os = host.find("os/osmatch")
        hosts.append(
            {
                "addresses": addresses,
                "hostnames": hostnames,
                "state": host_state,
                "ports": ports,
                "os_guess": top_os.get("name", "") if top_os is not None else "",
            }
        )

    return {"hosts": hosts}
