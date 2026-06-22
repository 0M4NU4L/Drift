"""Validation layer to ground and deduplicate threats."""

from collections import defaultdict
from drift.models import Architecture, Threat, Severity

def validate_threats(threats: list[Threat], arch: Architecture) -> list[Threat]:
    """Validate, deduplicate, and ground threats with evidence.
    
    This layer sits between the deterministic rule engine and the AI engine.
    It ensures that threats are deduplicated, scored for confidence,
    sanity-checked against the architecture, and their severity is normalized.
    """
    grouped_threats = defaultdict(list)
    for t in threats:
        # Group by the unique ID which is based on category, title, and boundary
        grouped_threats[t.id].append(t)
        
    validated_threats = []
    
    for _id, group in grouped_threats.items():
        base_threat = group[0].model_copy(deep=True)
        
        # 1. Merge evidence from all identical threats
        all_evidence = []
        for t in group:
            for ev in t.evidence:
                if ev not in all_evidence:
                    all_evidence.append(ev)
        
        base_threat.evidence = all_evidence
        
        # 2. Sanity Checks
        if not _is_sane(base_threat, arch):
            continue
            
        # 3. Calculate Confidence Score
        base_threat.confidence = _calculate_confidence(base_threat)
        
        # 4. Normalize Severity (Ensures AI or rules don't bypass risk calculation)
        base_threat.severity = _normalize_severity(base_threat)
        
        validated_threats.append(base_threat)
        
    return validated_threats

def _is_sane(threat: Threat, arch: Architecture) -> bool:
    """Reject impossible threats based on architecture state."""
    if not threat.evidence:
        return False

    # If a threat claims unencrypted traffic, verify the flow exists and is unencrypted
    if threat.stride_category == "Tampering" and "Unencrypted" in threat.title:
        # Find the affected flow if possible
        for src_name in threat.affected_components:
            for dst_name in threat.affected_components:
                if src_name == dst_name:
                    continue
                # Try to find a flow between them
                for flow in arch.flows:
                    if flow.source == src_name and flow.destination == dst_name:
                        # If the flow IS encrypted, reject this threat
                        if flow.is_encrypted:
                            return False
    return True

def _calculate_confidence(threat: Threat) -> float:
    """Calculate a 0.0 to 1.0 confidence score based on the quality of evidence."""
    evidence_count = len(threat.evidence)
    
    if evidence_count == 0:
        return 0.0
    if evidence_count >= 2:
        return 0.95
        
    # 1 evidence string
    base_confidence = 0.80
    
    # Scale based on quality/hardness of evidence
    hard_evidence_keywords = [
        "ALLOW_HTTP=true", 
        "wildcard (*)", 
        "privileged mode",
        "has public access enabled",
        "transmits data without encryption",
        "NO_AUTH is enabled",
        "LOGGING_DISABLED=true",
        "0.0.0.0/0",
        "public address",
        "port 6379",
        "port 5432"
    ]
    
    for ev in threat.evidence:
        if any(keyword in ev for keyword in hard_evidence_keywords):
            base_confidence = 0.90
            break
            
    return min(1.0, round(base_confidence, 2))

def _normalize_severity(threat: Threat) -> Severity:
    """Recalculate and enforce deterministic severity."""
    score = threat.likelihood * threat.impact
    if score >= 20:
        return Severity.CRITICAL
    elif score >= 10:
        return Severity.HIGH
    elif score >= 4:
        return Severity.MEDIUM
    else:
        return Severity.LOW
