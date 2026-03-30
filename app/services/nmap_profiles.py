from __future__ import annotations

from flask import current_app

from app.constants import SCAN_PROFILES


class ProfileValidationError(ValueError):
    pass


def get_available_profiles() -> dict:
    profiles = dict(SCAN_PROFILES)
    if not current_app.config.get("ENABLE_SYN_SCAN", False):
        profiles = {key: value for key, value in profiles.items() if key != "syn"}
    return profiles


def build_profile_args(profile_key: str, custom_options: dict | None = None) -> tuple[str, list[str]]:
    profiles = get_available_profiles()
    if profile_key not in profiles:
        raise ProfileValidationError("Unsupported scan profile selected.")

    if profile_key != "custom_safe":
        return profiles[profile_key]["label"], list(profiles[profile_key]["args"])

    options = custom_options or {}
    args: list[str] = []

    timing = options.get("timing")
    if timing in {"T3", "T4"}:
        args.append(f"-{timing}")

    if options.get("tcp_connect"):
        args.append("-sT")
    if options.get("service_detection"):
        args.append("-sV")
    if options.get("os_detection"):
        args.append("-O")
    if options.get("udp_top20"):
        args.extend(["-sU", "--top-ports", "20"])

    top_ports = options.get("top_ports")
    if top_ports is not None:
        if not isinstance(top_ports, int) or not 1 <= top_ports <= 1000:
            raise ProfileValidationError("Custom top ports must be between 1 and 1000.")
        args.extend(["--top-ports", str(top_ports)])

    if not args:
        args = ["-sn"]

    return SCAN_PROFILES["custom_safe"]["label"], args
