"""
Threat model API and DREAD scoring tests.

Tests:
1. DREAD engine calculation and scoring explanation
2. Threat API endpoints (CRUD)
3. Structured mitigation handling
4. Migration/backfill logic
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime
import json

from app.main import app
from app.engines.dread import DREADEngine
from app.models.threat import (
    ThreatEnhanced, StructuredMitigation, MitigationType, MitigationStatus,
    ConfidenceLevel, migrate_legacy_threat, infer_mitigation_type,
    generate_scoring_explanation
)


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
def dread_engine():
    """Create a DREAD engine instance."""
    return DREADEngine()


@pytest.fixture
def sample_dread_score():
    """Sample DREAD scores for testing."""
    return {
        "damage": 8,
        "reproducibility": 7,
        "exploitability": 6,
        "affected_users": 9,
        "discoverability": 5
    }


@pytest.fixture
def sample_threat_data():
    """Sample threat data for API tests."""
    return {
        "analysis_id": "test-analysis-123",
        "title": "SQL Injection in Login Form",
        "description": "The login form is vulnerable to SQL injection attacks",
        "category": "Injection",
        "severity": "high",
        "stride_category": "T",
        "dread_score": {
            "damage": 8,
            "reproducibility": 7,
            "exploitability": 6,
            "affected_users": 9,
            "discoverability": 5
        },
        "mitigations": ["Use parameterized queries", "Input validation"],
        "affected_component_ids": ["comp-login-form", "comp-db"],
        "impacted_flow_ids": ["flow-user-auth"],
        "preconditions": ["User has access to login page", "Application uses dynamic SQL"],
        "attack_scenario_steps": [
            "Attacker enters malicious SQL in username field",
            "Application concatenates input directly into SQL query",
            "Database executes malicious SQL",
            "Attacker gains unauthorized access"
        ],
        "impact_narrative": "Attacker could bypass authentication, extract sensitive data, or modify database contents."
    }


class TestDREADEngine:
    """Test DREAD risk scoring engine."""
    
    def test_calculate_returns_valid_score(self, dread_engine, sample_dread_score):
        """DREAD calculate should return a valid risk score between 1-10."""
        result = dread_engine.calculate(**sample_dread_score)
        
        assert "score" in result
        assert 1 <= result["score"] <= 10
        assert result["score"] == 7.0  # (8+7+6+9+5) / 5 = 7.0
    
    def test_calculate_returns_risk_level(self, dread_engine, sample_dread_score):
        """DREAD calculate should return a risk level classification."""
        result = dread_engine.calculate(**sample_dread_score)
        
        assert "level" in result
        assert result["level"] in ["critical", "high", "medium", "low"]
        assert result["level"] == "high"  # 7.0 is high risk
    
    def test_calculate_returns_scoring_model(self, dread_engine, sample_dread_score):
        """DREAD calculate should return the scoring model identifier."""
        result = dread_engine.calculate(**sample_dread_score)
        
        assert "scoring_model" in result
        assert result["scoring_model"] == "DREAD_AVG_V1"
    
    def test_calculate_returns_scoring_explanation(self, dread_engine, sample_dread_score):
        """DREAD calculate should return a human-readable explanation."""
        result = dread_engine.calculate(**sample_dread_score)
        
        assert "scoring_explanation" in result
        assert isinstance(result["scoring_explanation"], str)
        assert len(result["scoring_explanation"]) > 0
        # Should mention the factors
        assert "Damage" in result["scoring_explanation"] or "damage" in result["scoring_explanation"].lower()
    
    def test_calculate_critical_risk(self, dread_engine):
        """Scores 9+ should be classified as critical."""
        result = dread_engine.calculate(
            damage=10, reproducibility=9, exploitability=9,
            affected_users=10, discoverability=9
        )
        
        assert result["level"] == "critical"
        assert result["score"] >= 9
    
    def test_calculate_low_risk(self, dread_engine):
        """Scores under 4 should be classified as low."""
        result = dread_engine.calculate(
            damage=2, reproducibility=3, exploitability=2,
            affected_users=3, discoverability=2
        )
        
        assert result["level"] == "low"
        assert result["score"] < 4
    
    def test_calculate_from_dict(self, dread_engine, sample_dread_score):
        """calculate_from_dict should accept a dictionary of scores."""
        result = dread_engine.calculate_from_dict(sample_dread_score)
        
        assert result["score"] == 7.0
        assert result["level"] == "high"
        assert "scoring_explanation" in result
    
    def test_calculate_handles_missing_factors(self, dread_engine):
        """Should handle missing factors with defaults."""
        result = dread_engine.calculate_from_dict({"damage": 8})
        
        assert "score" in result
        # Should use default value (5) for missing factors
        expected = (8 + 5 + 5 + 5 + 5) / 5  # 5.6
        assert result["score"] == expected


class TestThreatModels:
    """Test Pydantic threat models and utilities."""
    
    def test_threat_enhanced_creation(self, sample_threat_data):
        """ThreatEnhanced should accept all new fields."""
        threat = ThreatEnhanced(
            id="threat-001",
            analysis_id=sample_threat_data["analysis_id"],
            title=sample_threat_data["title"],
            description=sample_threat_data["description"],
            category=sample_threat_data["category"],
            severity=sample_threat_data["severity"],
            dread_score=sample_threat_data["dread_score"],
            overall_risk=7.0,
            risk_level="high",
            scoring_model="DREAD_AVG_V1",
            scoring_explanation="Test explanation",
            mitigations=sample_threat_data["mitigations"],
            affected_component_ids=sample_threat_data["affected_component_ids"],
            impacted_flow_ids=sample_threat_data["impacted_flow_ids"],
            preconditions=sample_threat_data["preconditions"],
            attack_scenario_steps=sample_threat_data["attack_scenario_steps"],
            impact_narrative=sample_threat_data["impact_narrative"]
        )
        
        assert threat.id == "threat-001"
        assert threat.affected_component_ids == ["comp-login-form", "comp-db"]
        assert len(threat.attack_scenario_steps) == 4
        assert threat.scoring_model == "DREAD_AVG_V1"
    
    def test_structured_mitigation_creation(self):
        """StructuredMitigation should accept all fields."""
        mitigation = StructuredMitigation(
            id="mit-001",
            title="Implement parameterized queries",
            description="Replace string concatenation with parameterized SQL",
            mitigation_type=MitigationType.PREVENT,
            status=MitigationStatus.IMPLEMENTED,
            owner="Backend Team",
            verification="Code review + SAST scan"
        )
        
        assert mitigation.mitigation_type == MitigationType.PREVENT
        assert mitigation.status == MitigationStatus.IMPLEMENTED
        assert mitigation.owner == "Backend Team"
    
    def test_infer_mitigation_type_prevent(self):
        """Should infer PREVENT for preventive controls."""
        assert infer_mitigation_type("Enable encryption at rest") == MitigationType.PREVENT
        assert infer_mitigation_type("Implement input validation") == MitigationType.PREVENT
        assert infer_mitigation_type("Use secure authentication") == MitigationType.PREVENT
    
    def test_infer_mitigation_type_detect(self):
        """Should infer DETECT for detective controls."""
        assert infer_mitigation_type("Monitor for suspicious activity") == MitigationType.DETECT
        assert infer_mitigation_type("Set up logging and alerting") == MitigationType.DETECT
        assert infer_mitigation_type("Audit user access") == MitigationType.DETECT
    
    def test_infer_mitigation_type_respond(self):
        """Should infer RESPOND for response controls."""
        assert infer_mitigation_type("Create incident response plan") == MitigationType.RESPOND
        assert infer_mitigation_type("Have a backup and recovery procedure") == MitigationType.RESPOND
        assert infer_mitigation_type("Notify users of breach") == MitigationType.RESPOND
    
    def test_migrate_legacy_threat(self):
        """Should migrate legacy threat to enhanced format."""
        legacy = {
            "id": "threat-old",
            "title": "Old Threat",
            "description": "An old threat",
            "category": "Injection",
            "severity": "high",
            "dread_score": {"damage": 7, "reproducibility": 6, "exploitability": 5, "affected_users": 8, "discoverability": 4},
            "mitigations": ["Fix it", "Monitor logs"],
            "status": "identified"
        }
        
        enhanced = migrate_legacy_threat(legacy)
        
        assert enhanced["scoring_model"] == "DREAD_AVG_V1"
        assert "scoring_explanation" in enhanced
        assert enhanced["affected_component_ids"] == []
        assert enhanced["impacted_flow_ids"] == []
        assert enhanced["preconditions"] == []
        assert enhanced["attack_scenario_steps"] == []
        # Should have converted mitigations to structured format
        assert "structured_mitigations" in enhanced
        assert len(enhanced["structured_mitigations"]) == 2


class TestThreatAPIEndpoints:
    """Test threat API endpoints."""
    
    @patch('app.api.threats.threat_repo')
    @patch('app.api.threats.analysis_repo')
    def test_list_threats_returns_enhanced_format(self, mock_analysis_repo, mock_threat_repo, client):
        """GET /api/threats should return threats in enhanced format."""
        # Mock analysis exists
        mock_analysis_repo.get = AsyncMock(return_value={"analysis_id": "test-123"})
        
        # Mock threats
        mock_threat_repo.list = AsyncMock(return_value=[
            {
                "id": "threat-001",
                "title": "Test Threat",
                "description": "Test description",
                "category": "Injection",
                "severity": "high",
                "dread_score": {"damage": 7, "reproducibility": 6, "exploitability": 5, "affected_users": 8, "discoverability": 4},
                "overall_risk": 6.0,
                "risk_level": "medium",
                "scoring_model": "DREAD_AVG_V1",
                "scoring_explanation": "Test explanation",
                "mitigations": ["Test mitigation"],
                "affected_component_ids": ["comp-1"],
                "impacted_flow_ids": ["flow-1"],
                "preconditions": [],
                "attack_scenario_steps": [],
                "status": "identified"
            }
        ])
        
        response = client.get("/api/threats?analysis_id=test-123")
        assert response.status_code == 200
        
        data = response.json()
        assert "threats" in data
        threats = data["threats"]
        assert len(threats) == 1
        
        threat = threats[0]
        assert "scoring_model" in threat
        assert "scoring_explanation" in threat
        assert "affected_component_ids" in threat
    
    @patch('app.api.threats.threat_repo')
    @patch('app.api.threats.analysis_repo')
    def test_create_threat_with_enhanced_fields(self, mock_analysis_repo, mock_threat_repo, client, sample_threat_data):
        """POST /api/threats should accept enhanced fields."""
        # Mock analysis exists
        mock_analysis_repo.get = AsyncMock(return_value={
            "analysis_id": "test-analysis-123",
            "threats": []
        })
        mock_analysis_repo.save = AsyncMock()
        mock_threat_repo.save = AsyncMock()
        
        response = client.post("/api/threats", json=sample_threat_data)
        assert response.status_code in [200, 201]
        
        data = response.json()
        assert "id" in data
        assert "threat" in data
        
        created_threat = data["threat"]
        assert created_threat["affected_component_ids"] == sample_threat_data["affected_component_ids"]
        assert created_threat["impacted_flow_ids"] == sample_threat_data["impacted_flow_ids"]
        assert "scoring_explanation" in created_threat
    
    @patch('app.api.threats.threat_repo')
    def test_get_threat_details(self, mock_threat_repo, client):
        """GET /api/threats/{id} should return enhanced threat details."""
        mock_threat_repo.get = AsyncMock(return_value={
            "id": "threat-001",
            "title": "Test Threat",
            "description": "Test description",
            "category": "Injection",
            "severity": "high",
            "dread_score": {"damage": 7, "reproducibility": 6, "exploitability": 5, "affected_users": 8, "discoverability": 4},
            "overall_risk": 6.0,
            "risk_level": "medium",
            "scoring_model": "DREAD_AVG_V1",
            "scoring_explanation": "Test explanation",
            "mitigations": [],
            "structured_mitigations": [
                {
                    "id": "mit-001",
                    "title": "Input validation",
                    "mitigation_type": "PREVENT",
                    "status": "IMPLEMENTED",
                    "owner": "Dev Team"
                }
            ],
            "affected_component_ids": ["comp-1"],
            "impacted_flow_ids": ["flow-1"],
            "preconditions": ["User access"],
            "attack_scenario_steps": ["Step 1", "Step 2"],
            "impact_narrative": "Data breach possible",
            "status": "identified"
        })
        
        response = client.get("/api/threats/threat-001")
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == "threat-001"
        assert len(data["structured_mitigations"]) == 1
        assert data["structured_mitigations"][0]["mitigation_type"] == "PREVENT"
    
    @patch('app.api.threats.threat_repo')
    def test_update_threat_structured_mitigations(self, mock_threat_repo, client):
        """PATCH /api/threats/{id} should update structured mitigations."""
        existing_threat = {
            "id": "threat-001",
            "title": "Test Threat",
            "description": "Test",
            "category": "Injection",
            "severity": "high",
            "dread_score": {"damage": 7, "reproducibility": 6, "exploitability": 5, "affected_users": 8, "discoverability": 4},
            "overall_risk": 6.0,
            "mitigations": [],
            "structured_mitigations": [],
            "status": "identified"
        }
        mock_threat_repo.get = AsyncMock(return_value=existing_threat)
        mock_threat_repo.save = AsyncMock()
        
        update_data = {
            "structured_mitigations": [
                {
                    "id": "mit-new",
                    "title": "New mitigation",
                    "mitigation_type": "DETECT",
                    "status": "PROPOSED"
                }
            ]
        }
        
        response = client.patch("/api/threats/threat-001", json=update_data)
        assert response.status_code == 200
        
        # Verify save was called
        mock_threat_repo.save.assert_called_once()


class TestRiskScoringExplanation:
    """Test risk scoring explanation generation."""
    
    def test_generate_scoring_explanation(self):
        """Should generate human-readable explanation."""
        dread_score = {
            "damage": 8,
            "reproducibility": 7,
            "exploitability": 6,
            "affected_users": 9,
            "discoverability": 5
        }
        
        explanation = generate_scoring_explanation(dread_score, 7.0)
        
        assert isinstance(explanation, str)
        assert "7.0" in explanation or "7" in explanation
    
    def test_explanation_mentions_high_factors(self):
        """Explanation should mention particularly high risk factors."""
        dread_score = {
            "damage": 10,  # Very high
            "reproducibility": 5,
            "exploitability": 5,
            "affected_users": 10,  # Very high
            "discoverability": 5
        }
        
        explanation = generate_scoring_explanation(dread_score, 7.0)
        
        # Should mention the high-risk factors
        assert "damage" in explanation.lower() or "Damage" in explanation
        assert "affected" in explanation.lower() or "users" in explanation.lower()


class TestMigrationBackfill:
    """Test migration/backfill for existing threats."""
    
    def test_migrate_threat_without_new_fields(self):
        """Should add missing fields with sensible defaults."""
        old_threat = {
            "id": "old-threat",
            "title": "Legacy Threat",
            "description": "Old format threat",
            "category": "XSS",
            "severity": "medium",
            "dread_score": {"damage": 5, "reproducibility": 5, "exploitability": 5, "affected_users": 5, "discoverability": 5},
            "overall_risk": 5.0,
            "mitigations": ["Escape output"],
            "status": "identified"
        }
        
        migrated = migrate_legacy_threat(old_threat)
        
        # Should have new fields
        assert "affected_component_ids" in migrated
        assert "impacted_flow_ids" in migrated
        assert "preconditions" in migrated
        assert "attack_scenario_steps" in migrated
        assert "impact_narrative" in migrated
        assert "scoring_model" in migrated
        assert "scoring_explanation" in migrated
        assert "structured_mitigations" in migrated
        
        # Should preserve existing fields
        assert migrated["id"] == "old-threat"
        assert migrated["title"] == "Legacy Threat"
        assert migrated["mitigations"] == ["Escape output"]
    
    def test_migrate_converts_string_mitigations(self):
        """Should convert string mitigations to structured format."""
        old_threat = {
            "id": "old-threat",
            "title": "Legacy Threat",
            "description": "Old format",
            "category": "Auth",
            "severity": "high",
            "dread_score": {"damage": 7, "reproducibility": 7, "exploitability": 7, "affected_users": 7, "discoverability": 7},
            "mitigations": [
                "Implement MFA",  # Should be PREVENT
                "Monitor login attempts",  # Should be DETECT
                "Have incident response plan"  # Should be RESPOND
            ],
            "status": "identified"
        }
        
        migrated = migrate_legacy_threat(old_threat)
        
        structured = migrated["structured_mitigations"]
        assert len(structured) == 3
        
        # Check types were inferred correctly
        types = [m["mitigation_type"] for m in structured]
        assert "PREVENT" in types
        assert "DETECT" in types
        assert "RESPOND" in types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
