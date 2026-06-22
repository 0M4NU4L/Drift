"""Parse Kubernetes manifests."""

import logging
from typing import Any

import yaml

from drift.models import (
    Architecture,
    Component,
    ComponentType,
    DataFlow,
    TrustBoundary,
    TrustZone,
)

logger = logging.getLogger(__name__)


def parse(filepath: str) -> Architecture:
    """Parse a Kubernetes manifest file and return an Architecture."""
    arch = Architecture()
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            documents = list(yaml.safe_load_all(f))
    except Exception as e:
        logger.error(f"Failed to load k8s file {filepath}: {e}")
        return arch

    services = []
    
    for doc in documents:
        if not doc or not isinstance(doc, dict):
            continue
            
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"):
            if kind == "Pod":
                spec = doc.get("spec", {})
            elif kind == "CronJob":
                spec = doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
            else:
                spec = doc.get("spec", {}).get("template", {}).get("spec", {})
                
            containers = spec.get("containers", [])
            
            env_dict = {}
            exposed_ports = []
            properties = {}
            image_name = ""
            
            if spec.get("hostNetwork"):
                properties["host_network"] = True
                
            pod_sec_ctx = spec.get("securityContext", {})
            if pod_sec_ctx.get("runAsUser") == 0:
                properties["run_as_root"] = True
                
            volumes = spec.get("volumes", [])
            for vol in volumes:
                if vol.get("hostPath", {}).get("path") == "/":
                    properties["host_path_root"] = True
                
            for container in containers:
                image_name = container.get("image", "")
                
                # Check privileged & root
                sec_ctx = container.get("securityContext", {})
                if sec_ctx.get("privileged"):
                    properties["privileged"] = True
                if sec_ctx.get("runAsUser") == 0:
                    properties["run_as_root"] = True
                    
                # Check limits
                res = container.get("resources")
                if not res:
                    properties["no_resource_limits"] = True
                    
                # Extract env
                env = container.get("env", [])
                for e in env:
                    k = e.get("name")
                    v = e.get("value")
                    if k and v:
                        env_dict[k] = str(v)
                        
                # Extract ports
                ports = container.get("ports", [])
                for p in ports:
                    cp = p.get("containerPort")
                    if cp:
                        exposed_ports.append(int(cp))
            
            arch.components.append(
                Component(
                    name=name,
                    image=image_name,
                    environment=env_dict,
                    exposed_ports=exposed_ports,
                    properties=properties,
                    source="kubernetes",
                )
            )
            
        elif kind == "Service":
            spec = doc.get("spec", {})
            svc_type = spec.get("type", "ClusterIP")
            selector = spec.get("selector", {})
            
            services.append({
                "name": name,
                "type": svc_type,
                "selector": selector
            })
            
        elif kind == "Ingress":
            arch.boundaries.append(
                TrustBoundary(
                    name=f"Ingress: {name}",
                    zone_from=TrustZone.PUBLIC_INTERNET,
                    zone_to=TrustZone.DMZ,
                    description=f"Kubernetes Ingress {name}"
                )
            )

    # Post-process services to link flows and update properties
    for svc in services:
        if svc["type"] in ("LoadBalancer", "NodePort"):
            for comp in arch.components:
                # Simplistic matching: if component name matches any selector value
                if any(v in comp.name for v in svc["selector"].values()):
                    if svc["type"] == "NodePort":
                        comp.properties["nodeport"] = True
                    elif svc["type"] == "LoadBalancer":
                        comp.properties["loadbalancer"] = True
                    
    return arch
