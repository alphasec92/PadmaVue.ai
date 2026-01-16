"""
DevSecOps Agent
Generates security rules for Checkov, tfsec, and Semgrep
"""

from typing import Dict, Any, List, Optional
import json

import structlog

from app.services.llm_provider import LLMProvider
from app.generators.devsecops_rules import DevSecOpsGenerator

logger = structlog.get_logger()


class DevSecOpsAgent:
    """
    DevSecOps Agent for generating security scanning rules.
    
    Generates rules for:
    - Checkov (Infrastructure as Code)
    - tfsec (Terraform security)
    - Semgrep (Code analysis)
    """
    
    SYSTEM_PROMPT = """You are a DevSecOps Agent specialized in creating security 
scanning rules and policies.

Your expertise includes:
- Checkov custom policies for IaC scanning
- tfsec rules for Terraform security
- Semgrep patterns for code security

When generating rules:
1. Be specific and actionable
2. Minimize false positives
3. Include clear descriptions
4. Provide remediation guidance

Output format: Valid YAML/JSON configurations."""
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
        self.generator = DevSecOpsGenerator()
    
    async def run(
        self,
        threat_results: Dict[str, Any],
        compliance_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate DevSecOps rules based on threat analysis.
        
        Args:
            threat_results: Results from threat agent
            compliance_results: Results from compliance agent
        
        Returns:
            Generated rules for each tool
        """
        logger.info("Generating DevSecOps rules")
        
        threats = threat_results.get("threats", [])
        
        # Generate rules for each tool
        checkov_rules = await self._generate_checkov_rules(threats)
        tfsec_rules = await self._generate_tfsec_rules(threats)
        semgrep_rules = await self._generate_semgrep_rules(threats)
        
        logger.info("DevSecOps rules generated",
                   checkov=len(checkov_rules),
                   tfsec=len(tfsec_rules),
                   semgrep=len(semgrep_rules))
        
        return {
            "checkov": {
                "custom_policies": checkov_rules,
                "config_file": self._generate_checkov_config(checkov_rules)
            },
            "tfsec": {
                "custom_rules": tfsec_rules,
                "config_file": self._generate_tfsec_config(tfsec_rules)
            },
            "semgrep": {
                "rules": semgrep_rules,
                "config_file": self._generate_semgrep_config(semgrep_rules)
            },
            "summary": {
                "total_rules": len(checkov_rules) + len(tfsec_rules) + len(semgrep_rules),
                "by_tool": {
                    "checkov": len(checkov_rules),
                    "tfsec": len(tfsec_rules),
                    "semgrep": len(semgrep_rules)
                }
            }
        }
    
    async def _generate_checkov_rules(
        self,
        threats: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate Checkov custom policies"""
        rules = []
        
        for idx, threat in enumerate(threats[:5], 1):  # Limit to top 5
            category = threat.get("category", "").lower()
            
            rule = {
                "id": f"CKV_CUSTOM_{idx}",
                "name": f"check_{category.replace(' ', '_')}_{idx}",
                "description": threat.get("title", "Custom security check"),
                "severity": threat.get("severity", "MEDIUM").upper(),
                "category": "Security",
                "resource_types": self._get_resource_types(threat),
                "guideline": threat.get("mitigations", ["Review security configuration"])[0]
            }
            
            # Add specific check based on threat type
            if "encryption" in threat.get("title", "").lower():
                rule["check"] = "ensure_encryption_enabled"
                rule["resource_types"] = ["aws_s3_bucket", "aws_rds_instance", "aws_ebs_volume"]
            elif "authentication" in threat.get("title", "").lower():
                rule["check"] = "ensure_authentication_enabled"
                rule["resource_types"] = ["aws_api_gateway_rest_api", "aws_cognito_user_pool"]
            elif "logging" in threat.get("title", "").lower():
                rule["check"] = "ensure_logging_enabled"
                rule["resource_types"] = ["aws_s3_bucket", "aws_cloudtrail", "aws_vpc"]
            else:
                rule["check"] = f"ensure_secure_{category.replace(' ', '_')}"
            
            rules.append(rule)
        
        return rules
    
    async def _generate_tfsec_rules(
        self,
        threats: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate tfsec custom rules"""
        rules = []
        
        for idx, threat in enumerate(threats[:5], 1):
            rule = {
                "id": f"CUSTOM{idx:03d}",
                "description": threat.get("title", "Custom tfsec rule"),
                "impact": threat.get("description", "Security misconfiguration detected"),
                "resolution": threat.get("mitigations", ["Apply security best practices"])[0],
                "severity": threat.get("severity", "MEDIUM").upper(),
                "provider": "aws",
                "resource_type": "aws_security_group",
                "attribute": "ingress"
            }
            
            # Add specific checks
            category = threat.get("category", "").lower()
            if "access" in category or "elevation" in category:
                rule["check"] = {
                    "attribute": "cidr_blocks",
                    "not_contains": "0.0.0.0/0"
                }
            elif "disclosure" in category:
                rule["check"] = {
                    "attribute": "encrypted",
                    "equals": True
                }
            else:
                rule["check"] = {
                    "attribute": "description",
                    "not_empty": True
                }
            
            rules.append(rule)
        
        return rules
    
    async def _generate_semgrep_rules(
        self,
        threats: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate Semgrep rules"""
        rules = []
        
        for idx, threat in enumerate(threats[:5], 1):
            category = threat.get("category", "").lower()
            
            rule = {
                "id": f"security-custom-{idx}",
                "message": threat.get("title", "Potential security issue detected"),
                "severity": "ERROR" if threat.get("severity") in ["critical", "high"] else "WARNING",
                "languages": ["python", "javascript", "typescript"],
                "metadata": {
                    "category": "security",
                    "threat_category": threat.get("category", ""),
                    "confidence": "HIGH",
                    "cwe": self._get_cwe_for_category(category),
                    "owasp": self._get_owasp_for_category(category)
                }
            }
            
            # Add patterns based on threat type
            if "injection" in threat.get("title", "").lower() or "tampering" in category:
                rule["patterns"] = [
                    {
                        "pattern": "cursor.execute($QUERY)",
                        "pattern-not": "cursor.execute($QUERY, $PARAMS)"
                    }
                ]
                rule["fix"] = "cursor.execute($QUERY, (params,))"
            elif "authentication" in threat.get("title", "").lower() or "spoofing" in category:
                rule["patterns"] = [
                    {"pattern": "password = \"...\""},
                    {"pattern": "secret = \"...\""},
                    {"pattern": "api_key = \"...\""}
                ]
            elif "disclosure" in category:
                rule["patterns"] = [
                    {"pattern": "print($SENSITIVE)"},
                    {"pattern": "console.log($SENSITIVE)"}
                ]
            else:
                rule["patterns"] = [
                    {"pattern": "eval($X)"},
                    {"pattern": "exec($X)"}
                ]
            
            rules.append(rule)
        
        return rules
    
    def _get_resource_types(self, threat: Dict[str, Any]) -> List[str]:
        """Get relevant AWS resource types for a threat"""
        component = threat.get("affected_component", "").lower()
        
        if "database" in component:
            return ["aws_rds_instance", "aws_dynamodb_table"]
        elif "storage" in component or "s3" in component:
            return ["aws_s3_bucket", "aws_ebs_volume"]
        elif "network" in component or "vpc" in component:
            return ["aws_security_group", "aws_vpc", "aws_subnet"]
        elif "api" in component:
            return ["aws_api_gateway_rest_api", "aws_lambda_function"]
        else:
            return ["aws_instance", "aws_security_group"]
    
    def _get_cwe_for_category(self, category: str) -> str:
        """Map STRIDE category to CWE"""
        cwe_map = {
            "spoofing": "CWE-287",
            "tampering": "CWE-89",
            "repudiation": "CWE-778",
            "information disclosure": "CWE-200",
            "denial of service": "CWE-400",
            "elevation of privilege": "CWE-269"
        }
        return cwe_map.get(category, "CWE-20")
    
    def _get_owasp_for_category(self, category: str) -> str:
        """Map STRIDE category to OWASP Top 10"""
        owasp_map = {
            "spoofing": "A07:2021",
            "tampering": "A03:2021",
            "repudiation": "A09:2021",
            "information disclosure": "A01:2021",
            "denial of service": "A05:2021",
            "elevation of privilege": "A01:2021"
        }
        return owasp_map.get(category, "A03:2021")
    
    def _generate_checkov_config(self, rules: List[Dict]) -> str:
        """Generate Checkov configuration file content"""
        config = {
            "soft-fail-on": [],
            "skip-check": [],
            "custom-policies-dir": "./custom_policies",
            "external-modules-download-path": ".external_modules"
        }
        
        return json.dumps(config, indent=2)
    
    def _generate_tfsec_config(self, rules: List[Dict]) -> str:
        """Generate tfsec configuration file content"""
        config = {
            "minimum_severity": "LOW",
            "exclude": [],
            "custom_check_dir": "./tfsec_rules"
        }
        
        return json.dumps(config, indent=2)
    
    def _generate_semgrep_config(self, rules: List[Dict]) -> str:
        """Generate Semgrep configuration file content"""
        config = {
            "rules": rules
        }
        
        import yaml
        return yaml.dump(config, default_flow_style=False)


