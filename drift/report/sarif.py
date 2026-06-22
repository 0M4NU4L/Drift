import json
from pathlib import Path
from typing import Any
from drift.models import AnalysisResult

def generate_sarif(result: AnalysisResult, output_path: str) -> str:
    """Generate SARIF 2.1.0 output for GitHub Advanced Security."""
    
    rules = {}
    results = []
    
    for threat in result.threats:
        rule_id = f"DRIFT-{threat.stride_category.name}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": threat.stride_category.value,
                "shortDescription": {"text": f"Drift {threat.stride_category.value} threat"},
                "fullDescription": {"text": "A security threat identified by Drift's architecture analysis."},
                "help": {"text": "Review architecture design and boundaries."},
                "properties": {
                    "tags": ["security", "architecture", "stride", threat.stride_category.value.lower()]
                }
            }
            
        # Convert drift severity to SARIF level
        level = "warning"
        if threat.severity.name in ("CRITICAL", "HIGH"):
            level = "error"
        elif threat.severity.name == "LOW":
            level = "note"
            
        components = threat.affected_components if threat.affected_components else ["architecture"]
        
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{threat.severity.name}] {threat.title}\nBoundary: {threat.boundary}\nEvidence: {'; '.join(threat.evidence)}\nMitigation: {threat.mitigation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": comp
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }
                for comp in components
            ]
        })

    sarif_data: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Drift Security",
                        "informationUri": "https://github.com/drift-security/drift",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }
    
    out_file = Path(output_path)
    if out_file.is_dir() or not out_file.name.endswith(".sarif"):
        out_file = out_file / "drift-results.sarif"
        
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
        
    return str(out_file)
