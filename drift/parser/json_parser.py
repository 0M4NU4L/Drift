"""Parse architecture.json manual overrides."""

import json
import logging

from drift.models import Architecture

logger = logging.getLogger(__name__)


def parse(filepath: str) -> Architecture:
    """Parse an architecture.json file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        return Architecture.model_validate(data)
    except Exception as e:
        logger.error(f"Failed to load architecture.json {filepath}: {e}")
        return Architecture()
