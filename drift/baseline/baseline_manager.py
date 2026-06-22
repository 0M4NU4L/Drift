"""Baseline management — save and load drift.lock files."""

import logging
from pathlib import Path
from typing import Optional

from drift.models import Baseline

logger = logging.getLogger(__name__)


def save_baseline(baseline: Baseline, path: str = ".drift/drift.lock") -> str:
    """Serialize and save Baseline to JSON."""
    target = Path(path).resolve()
    
    try:
        # Ensure parent directory exists
        target.parent.mkdir(parents=True, exist_ok=True)
        
        with open(target, "w", encoding="utf-8") as f:
            f.write(baseline.model_dump_json(indent=2))
            
        logger.info(f"Baseline saved to {target}")
        return str(target)
    except Exception as e:
        logger.error(f"Failed to save baseline to {target}: {e}")
        return ""


def load_baseline(path: str = ".drift/drift.lock") -> Optional[Baseline]:
    """Load Baseline from JSON."""
    target = Path(path).resolve()
    
    if not target.exists():
        logger.info(f"No baseline found at {target}")
        return None
        
    try:
        with open(target, "r", encoding="utf-8") as f:
            json_str = f.read()
            
        return Baseline.model_validate_json(json_str)
    except Exception as e:
        logger.error(f"Failed to load baseline from {target}: {e}")
        return None
