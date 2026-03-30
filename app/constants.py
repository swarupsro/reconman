from collections import OrderedDict


BATCH_STATUS = {
    "QUEUED": "Queued",
    "RUNNING": "Running",
    "PAUSED": "Paused",
    "COMPLETED": "Completed",
    "FAILED": "Failed",
    "STOPPED": "Stopped",
}

TARGET_STATUS = {
    "QUEUED": "Queued",
    "RUNNING": "Running",
    "COMPLETED": "Completed",
    "FAILED": "Failed",
    "STOPPED": "Stopped",
    "RETRYING": "Retrying",
}

ROLES = {
    "ADMIN": "admin",
    "OPERATOR": "operator",
}

SCAN_PROFILES = OrderedDict(
    {
        "ping": {
            "label": "Ping Scan",
            "description": "Host discovery only using ICMP/TCP ping probes.",
            "args": ["-sn"],
            "requires_root": False,
        },
        "quick": {
            "label": "Quick Top Ports",
            "description": "Fast scan of common ports.",
            "args": ["-T4", "-F"],
            "requires_root": False,
        },
        "service": {
            "label": "Service Detection",
            "description": "Identify service versions on discovered ports.",
            "args": ["-sV"],
            "requires_root": False,
        },
        "os": {
            "label": "OS Detection",
            "description": "Attempt operating system fingerprinting.",
            "args": ["-O"],
            "requires_root": False,
        },
        "full_tcp": {
            "label": "Full TCP Connect Scan",
            "description": "TCP connect scan across all TCP ports.",
            "args": ["-sT", "-p-"],
            "requires_root": False,
        },
        "syn": {
            "label": "SYN Scan",
            "description": "Half-open SYN scan when supported by the environment.",
            "args": ["-sS"],
            "requires_root": True,
        },
        "udp": {
            "label": "UDP Common Ports",
            "description": "UDP scan for the top 20 ports.",
            "args": ["-sU", "--top-ports", "20"],
            "requires_root": True,
        },
        "aggressive": {
            "label": "Aggressive Scan",
            "description": "Service, OS, traceroute, and script checks.",
            "args": ["-A"],
            "requires_root": False,
        },
        "vuln": {
            "label": "Vulnerability Script Scan",
            "description": "Run the safe `vuln` NSE category.",
            "args": ["--script", "vuln"],
            "requires_root": False,
        },
        "custom_safe": {
            "label": "Custom Safe Profile Builder",
            "description": "Composable whitelist-based options without free-form commands.",
            "args": [],
            "requires_root": False,
        },
    }
)
