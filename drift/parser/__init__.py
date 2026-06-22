"""Parser layer — auto-discovers and parses infrastructure files."""

import logging
from pathlib import Path

from drift.models import Architecture

logger = logging.getLogger(__name__)


def parse_directory(path: str) -> Architecture:
    """Scan a directory for supported files and parse them all.
    
    Discovers: docker-compose*.yml, *.tf, *.yaml (k8s), architecture.json
    Merges all partial architectures into one.
    """
    target = Path(path).resolve()
    merged = Architecture()
    
    if not target.exists():
        logger.error(f"Path does not exist: {target}")
        return merged
        
    if target.is_file():
        files_to_scan = [target]
    else:
        # Search for files recursively
        files_to_scan = []
        files_to_scan.extend(target.rglob("docker-compose*.yml"))
        files_to_scan.extend(target.rglob("docker-compose*.yaml"))
        files_to_scan.extend(target.rglob("*.tf"))
        files_to_scan.extend(target.rglob("*.yaml"))
        files_to_scan.extend(target.rglob("*.yml"))
        files_to_scan.extend(target.rglob("architecture.json"))

    from drift.parser import (
        compose_parser,
        json_parser,
        k8s_parser,
        terraform_parser,
    )

    for file_path in files_to_scan:
        name = file_path.name.lower()
        partial = None
        
        try:
            if name.startswith("docker-compose"):
                partial = compose_parser.parse(str(file_path))
            elif name.endswith(".tf"):
                partial = terraform_parser.parse(str(file_path))
            elif name == "architecture.json":
                partial = json_parser.parse(str(file_path))
            elif name.endswith((".yaml", ".yml")) and not name.startswith("docker-compose"):
                # Could be k8s manifest
                partial = k8s_parser.parse(str(file_path))
                
            if partial and (partial.components or partial.boundaries or partial.flows):
                merged = merged.merge(partial)
                
        except Exception as e:
            logger.warning(f"Failed to parse {file_path}: {e}")

    return merged
