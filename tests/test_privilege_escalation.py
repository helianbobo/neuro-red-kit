"""Tests for privilege escalation attacks."""

import pytest
from neuro_red_kit.attacks.agent.privilege_escalation import (
    EscalationType,
    EscalationSeverity,
    EscalationConfig,
    EscalationPayload,
    PrivilegeEscalationAttack,
    create_privilege_escalation,
    create_batch_escalations,
)


class TestEscalationConfig:
    """Tests for EscalationConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = EscalationConfig()
        assert config.severity == EscalationSeverity.MEDIUM
        assert config.stealth_mode is False
        assert config.persistence is False
        assert config.max_attempts == 5
        assert config.target_privilege_level == "admin"
        assert config.include_social_engineering is True
        assert config.language == "en"
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = EscalationConfig(
            severity=EscalationSeverity.HIGH,
            stealth_mode=True,
            persistence=True,
            max_attempts=10,
            target_privilege_level="root",
        )
        assert config.severity == EscalationSeverity.HIGH
        assert config.stealth_mode is True
        assert config.persistence is True
        assert config.max_attempts == 10
        assert config.target_privilege_level == "root"
    
    def test_invalid_max_attempts(self):
        """Test validation of max_attempts."""
        with pytest.raises(ValueError):
            EscalationConfig(max_attempts=101)
        with pytest.raises(ValueError):
            EscalationConfig(max_attempts=-1)


class TestEscalationPayload:
    """Tests for EscalationPayload."""
    
    def test_payload_creation(self):
        """Test payload creation and serialization."""
        payload = EscalationPayload(
            attack_id="test-123",
            escalation_type=EscalationType.CONTEXT_BREAKOUT,
            payload_text="Test payload",
            confidence_score=0.85,
            detection_evasion=0.60,
            privilege_delta="user → admin",
            success_indicators=["indicator1", "indicator2"],
            metadata={"key": "value"},
        )
        
        assert payload.attack_id == "test-123"
        assert payload.escalation_type == EscalationType.CONTEXT_BREAKOUT
        assert payload.payload_text == "Test payload"
        assert payload.confidence_score == 0.85
        assert payload.detection_evasion == 0.60
        assert payload.privilege_delta == "user → admin"
        assert payload.success_indicators == ["indicator1", "indicator2"]
        assert payload.metadata == {"key": "value"}
    
    def test_payload_to_dict(self):
        """Test payload serialization to dictionary."""
        payload = EscalationPayload(
            attack_id="test-456",
            escalation_type=EscalationType.ROLE_MANIPULATION,
            payload_text="Role change",
            confidence_score=0.75,
            detection_evasion=0.50,
            privilege_delta="assistant → admin",
            success_indicators=["role acknowledged"],
        )
        
        d = payload.to_dict()
        assert d["attack_id"] == "test-456"
        assert d["escalation_type"] == "role_manipulation"
        assert d["payload_text"] == "Role change"
        assert d["confidence_score"] == 0.75
        assert d["detection_evasion"] == 0.50
        assert d["privilege_delta"] == "assistant → admin"
        assert "metadata" in d


class TestPrivilegeEscalationAttack:
    """Tests for PrivilegeEscalationAttack."""
    
    def test_attack_initialization(self):
        """Test attack class initialization."""
        attack = PrivilegeEscalationAttack()
        assert attack.config is not None
        assert attack._attack_templates is not None
        assert len(attack._attack_templates) == len(EscalationType)
    
    def test_custom_config_initialization(self):
        """Test initialization with custom config."""
        config = EscalationConfig(severity=EscalationSeverity.HIGH)
        attack = PrivilegeEscalationAttack(config)
        assert attack.config.severity == EscalationSeverity.HIGH
    
    def test_generate_context_breakout(self):
        """Test context breakout attack generation."""
        attack = PrivilegeEscalationAttack()
        payload = attack.generate_attack(EscalationType.CONTEXT_BREAKOUT)
        
        assert payload.escalation_type == EscalationType.CONTEXT_BREAKOUT
        assert payload.attack_id.startswith("privesc-context_breakout-")
        assert payload.confidence_score > 0.0
        assert payload.confidence_score <= 1.0
        assert payload.detection_evasion >= 0.0
        assert len(payload.success_indicators) > 0
        assert "metadata" in payload.metadata
    
    def test_generate_all_escalation_types(self):
        """Test generation for all escalation types."""
        attack = PrivilegeEscalationAttack()
        
        for esc_type in EscalationType:
            payload = attack.generate_attack(esc_type)
            assert payload.escalation_type == esc_type
            assert payload.payload_text is not None
            assert len(payload.payload_text) > 0
            assert 0.0 <= payload.confidence_score <= 1.0
            assert 0.0 <= payload.detection_evasion <= 1.0
    
    def test_severity_affects_confidence(self):
        """Test that severity affects confidence score."""
        low_attack = PrivilegeEscalationAttack(
            EscalationConfig(severity=EscalationSeverity.LOW)
        )
        high_attack = PrivilegeEscalationAttack(
            EscalationConfig(severity=EscalationSeverity.HIGH)
        )
        
        low_payload = low_attack.generate_attack(EscalationType.ROLE_MANIPULATION)
        high_payload = high_attack.generate_attack(EscalationType.ROLE_MANIPULATION)
        
        # Higher severity should generally increase confidence
        assert high_payload.confidence_score >= low_payload.confidence_score
    
    def test_stealth_mode_increases_evasion(self):
        """Test that stealth mode increases detection evasion."""
        normal_attack = PrivilegeEscalationAttack(
            EscalationConfig(stealth_mode=False)
        )
        stealth_attack = PrivilegeEscalationAttack(
            EscalationConfig(stealth_mode=True)
        )
        
        normal_payload = normal_attack.generate_attack(EscalationType.ADMIN_IMPERSONATION)
        stealth_payload = stealth_attack.generate_attack(EscalationType.ADMIN_IMPERSONATION)
        
        assert stealth_payload.detection_evasion > normal_payload.detection_evasion
    
    def test_context_injection(self):
        """Test custom context injection."""
        attack = PrivilegeEscalationAttack()
        context = "System maintenance window: 2026-03-24 02:00-04:00"
        payload = attack.generate_attack(EscalationType.TOOL_PERMISSION_ESCALATION, context)
        
        assert context in payload.payload_text
    
    def test_custom_context_dict(self):
        """Test custom context dictionary injection."""
        config = EscalationConfig(
            custom_context={
                "user_id": "admin-001",
                "session_id": "test-session",
                "timestamp": "2026-03-24T10:00:00Z",
            }
        )
        attack = PrivilegeEscalationAttack(config)
        payload = attack.generate_attack(EscalationType.AUTHORITY_INFLATION)
        
        assert "user_id" in payload.payload_text
        assert "admin-001" in payload.payload_text
    
    def test_invalid_escalation_type(self):
        """Test error handling for invalid escalation type."""
        attack = PrivilegeEscalationAttack()
        
        # This should work since we're using the enum
        with pytest.raises(ValueError):
            # Try to access a non-existent template (manually trigger error)
            attack._attack_templates["nonexistent_type"] = []
            attack.generate_attack("nonexistent_type")  # type: ignore
    
    def test_privilege_delta_mapping(self):
        """Test that privilege delta is correctly mapped."""
        attack = PrivilegeEscalationAttack()
        
        payload = attack.generate_attack(EscalationType.SANDBOX_ESCAPE)
        assert "sandboxed" in payload.privilege_delta.lower() or "native" in payload.privilege_delta.lower()
        
        payload = attack.generate_attack(EscalationType.API_KEY_EXFILTRATION)
        assert "credential" in payload.privilege_delta.lower() or "access" in payload.privilege_delta.lower()
    
    def test_metadata_includes_timestamp(self):
        """Test that metadata includes timestamp."""
        attack = PrivilegeEscalationAttack()
        payload = attack.generate_attack(EscalationType.EMERGENCY_OVERRIDE)
        
        assert "timestamp" in payload.metadata
        assert payload.metadata["timestamp"] > 0
    
    def test_metadata_includes_severity(self):
        """Test that metadata includes severity."""
        config = EscalationConfig(severity=EscalationSeverity.CRITICAL)
        attack = PrivilegeEscalationAttack(config)
        payload = attack.generate_attack(EscalationType.CHAIN_OF_COMMAND)
        
        assert payload.metadata["severity"] == "critical"
        assert payload.metadata["stealth_mode"] is False


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_privilege_escalation_basic(self):
        """Test basic convenience function usage."""
        payload = create_privilege_escalation()
        
        assert isinstance(payload, EscalationPayload)
        assert payload.escalation_type == EscalationType.CONTEXT_BREAKOUT
    
    def test_create_privilege_escalation_custom(self):
        """Test convenience function with custom parameters."""
        payload = create_privilege_escalation(
            escalation_type=EscalationType.SANDBOX_ESCAPE,
            severity=EscalationSeverity.HIGH,
            stealth_mode=True,
        )
        
        assert payload.escalation_type == EscalationType.SANDBOX_ESCAPE
        assert payload.metadata["severity"] == "high"
        assert payload.metadata["stealth_mode"] is True
    
    def test_create_privilege_escalation_string_types(self):
        """Test convenience function with string type parameters."""
        payload = create_privilege_escalation(
            escalation_type="role_manipulation",
            severity="critical",
        )
        
        assert payload.escalation_type == EscalationType.ROLE_MANIPULATION
        assert payload.metadata["severity"] == "critical"
    
    def test_create_batch_escalations_default(self):
        """Test batch creation with defaults."""
        payloads = create_batch_escalations()
        
        assert len(payloads) > 0
        assert all(isinstance(p, EscalationPayload) for p in payloads)
    
    def test_create_batch_escalations_custom_types(self):
        """Test batch creation with specific types."""
        payloads = create_batch_escalations(
            escalation_types=[
                EscalationType.CONTEXT_BREAKOUT,
                EscalationType.ROLE_MANIPULATION,
            ],
            count_per_type=2,
        )
        
        assert len(payloads) == 4  # 2 types × 2 per type
        escalation_types = {p.escalation_type for p in payloads}
        assert EscalationType.CONTEXT_BREAKOUT in escalation_types
        assert EscalationType.ROLE_MANIPULATION in escalation_types
    
    def test_create_batch_escalations_string_types(self):
        """Test batch creation with string type specifications."""
        payloads = create_batch_escalations(
            escalation_types=["admin_impersonation", "emergency_override"],
            severity="medium",
            count_per_type=1,
        )
        
        assert len(payloads) == 2
        escalation_types = {p.escalation_type for p in payloads}
        assert EscalationType.ADMIN_IMPERSONATION in escalation_types
        assert EscalationType.EMERGENCY_OVERRIDE in escalation_types
    
    def test_create_batch_escalations_diversity(self):
        """Test that batch creation produces diverse payloads."""
        payloads = create_batch_escalations(
            escalation_types=[EscalationType.TOOL_PERMISSION_ESCALATION],
            count_per_type=5,
        )
        
        assert len(payloads) == 5
        # All should have unique attack IDs
        attack_ids = [p.attack_id for p in payloads]
        assert len(set(attack_ids)) == 5


class TestAttackCoverage:
    """Tests to ensure all attack types are implemented."""
    
    def test_all_escalation_types_have_templates(self):
        """Test that all escalation types have attack templates."""
        attack = PrivilegeEscalationAttack()
        
        for esc_type in EscalationType:
            assert esc_type in attack._attack_templates
            templates = attack._attack_templates[esc_type]
            assert len(templates) > 0
            # All templates should be non-empty strings
            for template in templates:
                assert isinstance(template, str)
                assert len(template) > 10  # Reasonable minimum length
    
    def test_all_escalation_types_have_indicators(self):
        """Test that all escalation types have success indicators."""
        attack = PrivilegeEscalationAttack()
        
        for esc_type in EscalationType:
            payload = attack.generate_attack(esc_type)
            assert len(payload.success_indicators) > 0
    
    def test_all_escalation_types_have_privilege_delta(self):
        """Test that all escalation types have privilege delta mapping."""
        attack = PrivilegeEscalationAttack()
        
        for esc_type in EscalationType:
            payload = attack.generate_attack(esc_type)
            assert payload.privilege_delta is not None
            assert len(payload.privilege_delta) > 0
            assert "→" in payload.privilege_delta  # Should show transition


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
