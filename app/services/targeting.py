from __future__ import annotations

import ipaddress
from typing import Iterable

from flask import current_app

from app.models import AppSetting


class TargetValidationError(ValueError):
    pass


def get_allowed_networks() -> list[ipaddress._BaseNetwork]:
    configured = AppSetting.get_value("allowed_ranges", current_app.config["DEFAULT_ALLOWED_RANGES"])
    networks = []
    for item in configured.split(","):
        cleaned = item.strip()
        if cleaned:
            networks.append(ipaddress.ip_network(cleaned, strict=False))
    return networks


def parse_targets(raw_targets: str) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for line in raw_targets.replace(",", "\n").splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        normalized = normalize_target(cleaned)
        if normalized not in seen:
            seen.add(normalized)
            targets.append(normalized)

    if not targets:
        raise TargetValidationError("No valid targets were provided.")
    return targets


def normalize_target(target: str) -> str:
    try:
        network = ipaddress.ip_network(target, strict=False)
        return str(network)
    except ValueError:
        pass

    if "-" in target:
        start_ip, end_ip = [part.strip() for part in target.split("-", 1)]
        try:
            ipaddress.ip_address(start_ip)
            ipaddress.ip_address(end_ip)
        except ValueError as exc:
            raise TargetValidationError(f"Invalid IP range: {target}") from exc
        return f"{start_ip}-{end_ip}"

    try:
        return str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise TargetValidationError(f"Invalid target: {target}") from exc


def validate_targets_within_scope(targets: Iterable[str]) -> None:
    allowed_networks = get_allowed_networks()
    violations = [target for target in targets if not target_in_scope(target, allowed_networks)]
    if violations:
        raise TargetValidationError(
            "These targets are outside approved internal ranges: " + ", ".join(violations[:10])
        )


def target_in_scope(target: str, allowed_networks: list[ipaddress._BaseNetwork]) -> bool:
    if "-" in target:
        start_raw, end_raw = target.split("-", 1)
        start_ip = ipaddress.ip_address(start_raw)
        end_ip = ipaddress.ip_address(end_raw)
        return any(start_ip in network and end_ip in network for network in allowed_networks)

    candidate = ipaddress.ip_network(target, strict=False)
    return any(candidate.subnet_of(network) or candidate == network for network in allowed_networks)
