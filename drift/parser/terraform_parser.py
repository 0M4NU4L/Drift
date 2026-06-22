"""Parse Terraform (*.tf) files."""

import logging
import re

from drift.models import (
    Architecture,
    Component,
    ComponentType,
    TrustZone,
)

logger = logging.getLogger(__name__)

# Very simple regex-based HCL parsing
RESOURCE_PATTERN = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s+\{')
PUBLIC_CIDR = "0.0.0.0/0"

def parse(filepath: str) -> Architecture:
    """Parse a Terraform file and return an Architecture."""
    arch = Architecture()
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Failed to read terraform file {filepath}: {e}")
        return arch

    # Find all resource blocks
    for match in RESOURCE_PATTERN.finditer(content):
        res_type = match.group(1)
        res_name = match.group(2)
        
        # Extract the block content by matching braces
        start_idx = match.end() - 1
        brace_count = 0
        end_idx = start_idx
        
        for i, char in enumerate(content[start_idx:], start=start_idx):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i
                    break
                    
        block_content = content[start_idx:end_idx+1]
        
        # Map resources to components
        comp_type = ComponentType.UNKNOWN
        trust_zone = TrustZone.INTERNAL_SERVICES
        properties = {}
        
        # DBs
        if res_type in ("aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table"):
            comp_type = ComponentType.DATABASE
            trust_zone = TrustZone.DATABASE_TIER
            if "publicly_accessible = true" in block_content.replace(" ", ""):
                trust_zone = TrustZone.PUBLIC_INTERNET
                
            if "storage_encrypted = false" in block_content.replace(" ", ""):
                properties["has_encryption_config"] = False
                properties["encrypted"] = False
            else:
                properties["has_encryption_config"] = True
                properties["encrypted"] = True
                
        # S3
        elif res_type == "aws_s3_bucket":
            comp_type = ComponentType.STORAGE
            content_no_space = block_content.replace(" ", "")
            if 'acl="public-read"' in content_no_space:
                properties["public_access"] = True
            if "block_public_policy=false" in content_no_space or "restrict_public_buckets=false" in content_no_space:
                properties["public_access"] = True
                
        elif res_type == "aws_s3_bucket_public_access_block":
            content_no_space = block_content.replace(" ", "")
            if "block_public_policy=false" in content_no_space or "restrict_public_buckets=false" in content_no_space:
                # e.g., bucket = aws_s3_bucket.logs.id -> aws_s3_bucket.logs
                match = re.search(r'bucket\s*=\s*(aws_s3_bucket\.[a-zA-Z0-9_-]+)', block_content)
                if match:
                    bucket_name = match.group(1)
                    # We retroactively apply it if the component already exists
                    for c in arch.components:
                        if c.name == bucket_name:
                            c.properties["public_access"] = True
                    # In case the block is defined before the bucket, we could store it 
                    # but simple ordering usually works if we process after. 
                    # For a robust parser, we'd do a second pass, but this suffices for simple cases.
                    properties["target_bucket"] = bucket_name
                    properties["public_access"] = True
                    comp_type = ComponentType.UNKNOWN
                
        # Compute
        elif res_type in ("aws_instance", "aws_ecs_service"):
            comp_type = ComponentType.SERVICE
            
        elif res_type == "aws_lambda_function":
            comp_type = ComponentType.SERVERLESS
            
        # LB / API Gateway
        elif res_type in ("aws_lb", "aws_alb"):
            comp_type = ComponentType.LOAD_BALANCER
            if "internal = false" in block_content.replace(" ", ""):
                trust_zone = TrustZone.DMZ
                
        elif res_type in ("aws_api_gateway_rest_api", "aws_apigatewayv2_api"):
            comp_type = ComponentType.API_GATEWAY
            trust_zone = TrustZone.DMZ
            
        elif res_type == "aws_cloudfront_distribution":
            comp_type = ComponentType.CDN
            trust_zone = TrustZone.PUBLIC_INTERNET

        # IAM
        elif res_type in ("aws_iam_role_policy", "aws_iam_policy"):
            # Very crude check for wildcards
            if '"*"' in block_content or "'*'" in block_content:
                # We attribute this property to the policy itself, ideally we'd map it to the role
                properties["overly_permissive_iam"] = True
                comp_type = ComponentType.UNKNOWN # Just a policy

        if comp_type != ComponentType.UNKNOWN or properties:
            arch.components.append(
                Component(
                    name=f"{res_type}.{res_name}",
                    type=comp_type,
                    trust_zone=trust_zone,
                    properties=properties,
                    source="terraform",
                )
            )

    # Post-process to apply properties to targets
    to_remove = []
    for comp in arch.components:
        if comp.properties.get("target_bucket"):
            to_remove.append(comp)
            target_name = comp.properties["target_bucket"]
            for target_comp in arch.components:
                if target_comp.name == target_name:
                    if comp.properties.get("public_access"):
                        target_comp.properties["public_access"] = True

    # Remove the metadata components (like public access block) from the final architecture
    arch.components = [c for c in arch.components if c not in to_remove]

    return arch
