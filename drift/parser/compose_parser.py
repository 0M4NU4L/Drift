"""Parse docker-compose.yml files."""

import logging
import re
from typing import Any

import yaml

from drift.models import (
    Architecture,
    Asset,
    AssetType,
    Component,
    ComponentType,
    DataFlow,
    TrustBoundary,
    TrustZone,
)

logger = logging.getLogger(__name__)


def parse(filepath: str) -> Architecture:
    """Parse a docker-compose file and return an Architecture."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load compose file {filepath}: {e}")
        return Architecture()

    if not data or not isinstance(data, dict) or "services" not in data:
        return Architecture()

    arch = Architecture()
    services: dict[str, dict[str, Any]] = data.get("services", {})
    networks: dict[str, dict[str, Any]] = data.get("networks", {})

    # Create Components
    for svc_name, svc_data in services.items():
        if not isinstance(svc_data, dict):
            continue

        image = svc_data.get("image", "")
        
        # Parse ports to see if publicly exposed
        raw_ports = svc_data.get("ports", [])
        exposed_ports = []
        is_public = False
        
        for p in raw_ports:
            # Ports can be strings "80:80" or ints or dicts in compose v3.2+
            if isinstance(p, str):
                parts = p.split(":")
                if len(parts) >= 2:
                    is_public = True
                    try:
                        # Take the container port (the last one usually, or split)
                        exposed_ports.append(int(parts[-1].split("/")[0]))
                    except ValueError:
                        pass
            elif isinstance(p, int):
                exposed_ports.append(p)

        # Parse environment variables
        env = svc_data.get("environment", {})
        env_dict = {}
        if isinstance(env, list):
            for e in env:
                if "=" in e:
                    k, v = e.split("=", 1)
                    env_dict[k] = v
        elif isinstance(env, dict):
            env_dict = env

        # Properties
        properties = {}
        if svc_data.get("privileged"):
            properties["privileged"] = True
        if svc_data.get("network_mode") == "host":
            properties["host_network"] = True

        comp = Component(
            name=svc_name,
            image=image,
            environment=env_dict,
            exposed_ports=exposed_ports,
            properties=properties,
            source="docker-compose",
        )
        
        # If it has mapped ports, we hint that it might be DMZ/Public
        if is_public:
            if "gateway" in svc_name.lower() or "proxy" in svc_name.lower() or "nginx" in image.lower():
                comp.trust_zone = TrustZone.DMZ
            else:
                comp.trust_zone = TrustZone.DMZ

        arch.components.append(comp)

        # Create Flows from depends_on
        depends_on = svc_data.get("depends_on", [])
        if isinstance(depends_on, list):
            for dep in depends_on:
                arch.flows.append(DataFlow(
                    source=svc_name,
                    destination=dep,
                    description=f"Compose depends_on relationship",
                ))
        elif isinstance(depends_on, dict):
            for dep in depends_on.keys():
                arch.flows.append(DataFlow(
                    source=svc_name,
                    destination=dep,
                    description=f"Compose depends_on relationship",
                ))

    return arch
