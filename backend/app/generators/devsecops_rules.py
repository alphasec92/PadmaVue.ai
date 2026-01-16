"""
DevSecOps Rule Generator
Generates security scanning rules for Checkov, tfsec, and Semgrep
"""

from typing import Dict, Any, List, Optional
import json
import yaml
import structlog

logger = structlog.get_logger()


class DevSecOpsGenerator:
    """
    Generates security scanning rules for DevSecOps tools.
    
    Supports:
    - Checkov (IaC scanning)
    - tfsec (Terraform security)
    - Semgrep (Code analysis)
    """
    
    def __init__(self):
        pass
    
    def generate_checkov_policy(
        self,
        policy_id: str,
        name: str,
        description: str,
        resource_types: List[str],
        check_type: str,
        severity: str = "MEDIUM",
        guideline: str = ""
    ) -> Dict[str, Any]:
        """
        Generate a Checkov custom policy.
        
        Args:
            policy_id: Unique policy identifier (e.g., CKV_CUSTOM_1)
            name: Policy name
            description: Policy description
            resource_types: AWS resource types to check
            check_type: Type of check to perform
            severity: Severity level
            guideline: Remediation guideline
        
        Returns:
            Checkov policy definition
        """
        policy = {
            "metadata": {
                "id": policy_id,
                "name": name,
                "severity": severity.upper(),
                "category": "Security"
            },
            "definition": {
                "cond_type": "attribute",
                "resource_types": resource_types,
                "attribute": self._get_check_attribute(check_type),
                "operator": self._get_check_operator(check_type),
                "value": self._get_check_value(check_type)
            },
            "guideline": guideline or f"Review and fix: {description}"
        }
        
        return policy
    
    def generate_checkov_yaml(
        self,
        policies: List[Dict[str, Any]]
    ) -> str:
        """Generate Checkov policy YAML file"""
        checkov_config = {
            "metadata": {
                "name": "SecurityReview Custom Policies",
                "guidelines": "https://securityreview.ai/docs/policies"
            },
            "scope": {
                "provider": "aws"
            },
            "definition": []
        }
        
        for policy in policies:
            checkov_config["definition"].append(policy)
        
        return yaml.dump(checkov_config, default_flow_style=False, sort_keys=False)
    
    def generate_tfsec_rule(
        self,
        rule_id: str,
        description: str,
        impact: str,
        resolution: str,
        severity: str = "MEDIUM",
        provider: str = "aws",
        resource_type: str = "aws_security_group",
        check: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate a tfsec custom rule.
        
        Args:
            rule_id: Unique rule identifier
            description: Rule description
            impact: Security impact
            resolution: How to resolve
            severity: Severity level
            provider: Cloud provider
            resource_type: Resource to check
            check: Check conditions
        
        Returns:
            tfsec rule definition
        """
        rule = {
            "checks": [
                {
                    "code": rule_id,
                    "description": description,
                    "impact": impact,
                    "resolution": resolution,
                    "severity": severity.upper(),
                    "requiredTypes": ["resource"],
                    "requiredLabels": [resource_type],
                    "matchSpec": check or {
                        "action": "isPresent",
                        "name": "description"
                    }
                }
            ]
        }
        
        return rule
    
    def generate_tfsec_config(
        self,
        rules: List[Dict[str, Any]],
        minimum_severity: str = "LOW"
    ) -> str:
        """Generate tfsec configuration file"""
        config = {
            "minimum_severity": minimum_severity,
            "severity_overrides": {},
            "exclude": [],
            "include": []
        }
        
        # Combine all rules
        all_checks = []
        for rule in rules:
            all_checks.extend(rule.get("checks", []))
        
        combined = {
            "checks": all_checks
        }
        
        return json.dumps(combined, indent=2)
    
    def generate_semgrep_rule(
        self,
        rule_id: str,
        message: str,
        severity: str = "WARNING",
        languages: List[str] = None,
        patterns: List[Dict[str, str]] = None,
        pattern: str = None,
        fix: str = None,
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate a Semgrep rule.
        
        Args:
            rule_id: Unique rule identifier
            message: Warning message
            severity: ERROR, WARNING, or INFO
            languages: Programming languages
            patterns: Pattern conditions
            pattern: Simple pattern string
            fix: Auto-fix pattern
            metadata: Additional metadata
        
        Returns:
            Semgrep rule definition
        """
        rule = {
            "id": rule_id,
            "message": message,
            "severity": severity.upper(),
            "languages": languages or ["python", "javascript", "typescript"]
        }
        
        # Add pattern(s)
        if patterns:
            rule["patterns"] = patterns
        elif pattern:
            rule["pattern"] = pattern
        else:
            rule["pattern"] = "..."  # Default match-all
        
        # Add fix if provided
        if fix:
            rule["fix"] = fix
        
        # Add metadata
        if metadata:
            rule["metadata"] = metadata
        else:
            rule["metadata"] = {
                "category": "security",
                "confidence": "HIGH",
                "source": "SecurityReview.ai"
            }
        
        return rule
    
    def generate_semgrep_config(
        self,
        rules: List[Dict[str, Any]]
    ) -> str:
        """Generate Semgrep configuration YAML"""
        config = {
            "rules": rules
        }
        
        return yaml.dump(config, default_flow_style=False, sort_keys=False)
    
    def generate_rules_for_threat(
        self,
        threat: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate all rules for a specific threat.
        
        Args:
            threat: Threat definition
        
        Returns:
            Rules for each tool
        """
        category = threat.get("category", "").lower()
        title = threat.get("title", "")
        severity = threat.get("severity", "medium").upper()
        
        rules = {
            "checkov": None,
            "tfsec": None,
            "semgrep": None
        }
        
        # Generate Checkov policy
        checkov_policy = self._generate_checkov_for_category(
            category,
            title,
            severity,
            threat.get("mitigations", [])
        )
        rules["checkov"] = checkov_policy
        
        # Generate tfsec rule
        tfsec_rule = self._generate_tfsec_for_category(
            category,
            title,
            severity,
            threat.get("mitigations", [])
        )
        rules["tfsec"] = tfsec_rule
        
        # Generate Semgrep rule
        semgrep_rule = self._generate_semgrep_for_category(
            category,
            title,
            severity,
            threat.get("mitigations", [])
        )
        rules["semgrep"] = semgrep_rule
        
        return rules
    
    def _generate_checkov_for_category(
        self,
        category: str,
        title: str,
        severity: str,
        mitigations: List[str]
    ) -> Dict[str, Any]:
        """Generate Checkov policy based on threat category"""
        policy_id = f"CKV_SECREV_{category[:3].upper()}"
        
        if "spoofing" in category:
            return self.generate_checkov_policy(
                policy_id=policy_id,
                name=f"check_authentication_{title[:20].lower().replace(' ', '_')}",
                description=title,
                resource_types=["aws_cognito_user_pool", "aws_iam_policy"],
                check_type="authentication",
                severity=severity,
                guideline=mitigations[0] if mitigations else "Implement strong authentication"
            )
        elif "tampering" in category:
            return self.generate_checkov_policy(
                policy_id=policy_id,
                name=f"check_integrity_{title[:20].lower().replace(' ', '_')}",
                description=title,
                resource_types=["aws_s3_bucket", "aws_rds_instance"],
                check_type="integrity",
                severity=severity,
                guideline=mitigations[0] if mitigations else "Enable integrity protection"
            )
        elif "disclosure" in category:
            return self.generate_checkov_policy(
                policy_id=policy_id,
                name=f"check_encryption_{title[:20].lower().replace(' ', '_')}",
                description=title,
                resource_types=["aws_s3_bucket", "aws_rds_instance", "aws_ebs_volume"],
                check_type="encryption",
                severity=severity,
                guideline=mitigations[0] if mitigations else "Enable encryption"
            )
        else:
            return self.generate_checkov_policy(
                policy_id=policy_id,
                name=f"check_security_{title[:20].lower().replace(' ', '_')}",
                description=title,
                resource_types=["aws_security_group"],
                check_type="general",
                severity=severity,
                guideline=mitigations[0] if mitigations else "Review security configuration"
            )
    
    def _generate_tfsec_for_category(
        self,
        category: str,
        title: str,
        severity: str,
        mitigations: List[str]
    ) -> Dict[str, Any]:
        """Generate tfsec rule based on threat category"""
        rule_id = f"SECREV{category[:3].upper()}001"
        
        check = {"action": "isPresent", "name": "description"}
        
        if "spoofing" in category:
            check = {
                "action": "equals",
                "name": "multi_factor_authentication",
                "value": "ENABLED"
            }
        elif "disclosure" in category:
            check = {
                "action": "equals",
                "name": "encrypted",
                "value": True
            }
        elif "denial" in category:
            check = {
                "action": "isPresent",
                "name": "rate_limit"
            }
        
        return self.generate_tfsec_rule(
            rule_id=rule_id,
            description=title,
            impact=f"Security risk: {category}",
            resolution=mitigations[0] if mitigations else "Apply security best practices",
            severity=severity,
            check=check
        )
    
    def _generate_semgrep_for_category(
        self,
        category: str,
        title: str,
        severity: str,
        mitigations: List[str]
    ) -> Dict[str, Any]:
        """Generate Semgrep rule based on threat category"""
        rule_id = f"security-{category.replace(' ', '-').lower()}"
        
        patterns = None
        pattern = None
        fix = None
        
        if "tampering" in category or "injection" in title.lower():
            patterns = [
                {"pattern": "cursor.execute($QUERY)"},
                {"pattern-not": "cursor.execute($QUERY, $PARAMS)"}
            ]
            fix = "cursor.execute($QUERY, (params,))"
        elif "spoofing" in category:
            patterns = [
                {"pattern": "password = \"...\""},
                {"pattern": "secret = \"...\""},
                {"pattern": "api_key = \"...\""}
            ]
        elif "disclosure" in category:
            patterns = [
                {"pattern": "print($SENSITIVE)"},
                {"pattern": "console.log($SENSITIVE)"}
            ]
        else:
            patterns = [
                {"pattern": "eval($X)"},
                {"pattern": "exec($X)"}
            ]
        
        return self.generate_semgrep_rule(
            rule_id=rule_id,
            message=title,
            severity="ERROR" if severity in ["CRITICAL", "HIGH"] else "WARNING",
            patterns=patterns,
            fix=fix,
            metadata={
                "category": "security",
                "threat_category": category,
                "confidence": "HIGH",
                "cwe": self._get_cwe(category),
                "owasp": self._get_owasp(category)
            }
        )
    
    def _get_check_attribute(self, check_type: str) -> str:
        """Get attribute for Checkov check"""
        attributes = {
            "encryption": "server_side_encryption_configuration",
            "authentication": "mfa_configuration",
            "logging": "logging",
            "integrity": "versioning",
            "general": "tags"
        }
        return attributes.get(check_type, "description")
    
    def _get_check_operator(self, check_type: str) -> str:
        """Get operator for Checkov check"""
        operators = {
            "encryption": "exists",
            "authentication": "equals",
            "logging": "exists",
            "integrity": "equals",
            "general": "exists"
        }
        return operators.get(check_type, "exists")
    
    def _get_check_value(self, check_type: str) -> Any:
        """Get value for Checkov check"""
        values = {
            "encryption": True,
            "authentication": "ON",
            "logging": True,
            "integrity": "Enabled",
            "general": True
        }
        return values.get(check_type, True)
    
    def _get_cwe(self, category: str) -> str:
        """Get CWE ID for category"""
        cwe_map = {
            "spoofing": "CWE-287",
            "tampering": "CWE-89",
            "repudiation": "CWE-778",
            "information disclosure": "CWE-200",
            "denial of service": "CWE-400",
            "elevation of privilege": "CWE-269"
        }
        return cwe_map.get(category, "CWE-20")
    
    def _get_owasp(self, category: str) -> str:
        """Get OWASP Top 10 ID for category"""
        owasp_map = {
            "spoofing": "A07:2021",
            "tampering": "A03:2021",
            "repudiation": "A09:2021",
            "information disclosure": "A01:2021",
            "denial of service": "A05:2021",
            "elevation of privilege": "A01:2021"
        }
        return owasp_map.get(category, "A03:2021")


