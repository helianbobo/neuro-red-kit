"""
Unit tests for identity spoofing attacks.
"""

import pytest
import time
from neuro_red_kit.attacks.agent.identity_spoofing import (
    SpoofingType,
    SpoofingSeverity,
    SpoofingConfig,
    SpoofingPayload,
    IdentitySpoofingAttack,
    create_identity_spoofing,
    create_batch_spoofings,
    evaluate_spoofing_payload,
)


class TestSpoofingConfig:
    """Tests for SpoofingConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SpoofingConfig()
        assert config.spoofing_type == SpoofingType.AGENT_IMPERSONATION
        assert config.severity == SpoofingSeverity.MEDIUM
        assert config.target_agent_id is None
        assert config.persistence is False
        assert config.stealth_mode is False
        assert config.max_attempts == 3
        assert config.timeout_seconds == 300
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = SpoofingConfig(
            spoofing_type=SpoofingType.CREDENTIAL_FORGERY,
            severity=SpoofingSeverity.HIGH,
            target_agent_id="agent-123",
            persistence=True,
            stealth_mode=True,
            max_attempts=5,
            timeout_seconds=600
        )
        assert config.spoofing_type == SpoofingType.CREDENTIAL_FORGERY
        assert config.severity == SpoofingSeverity.HIGH
        assert config.target_agent_id == "agent-123"
        assert config.persistence is True
        assert config.stealth_mode is True
        assert config.max_attempts == 5
        assert config.timeout_seconds == 600
    
    def test_string_type_conversion(self):
        """Test string to enum conversion."""
        config = SpoofingConfig(
            spoofing_type="AGENT_IMPERSONATION",
            severity="CRITICAL"
        )
        assert config.spoofing_type == SpoofingType.AGENT_IMPERSONATION
        assert config.severity == SpoofingSeverity.CRITICAL
    
    def test_invalid_max_attempts(self):
        """Test validation of max_attempts."""
        with pytest.raises(ValueError):
            SpoofingConfig(max_attempts=0)
        with pytest.raises(ValueError):
            SpoofingConfig(max_attempts=11)
    
    def test_invalid_timeout(self):
        """Test validation of timeout_seconds."""
        with pytest.raises(ValueError):
            SpoofingConfig(timeout_seconds=30)
        with pytest.raises(ValueError):
            SpoofingConfig(timeout_seconds=5000)


class TestSpoofingPayload:
    """Tests for SpoofingPayload."""
    
    def test_payload_creation(self):
        """Test basic payload creation."""
        payload = SpoofingPayload.create(
            spoofing_type=SpoofingType.AGENT_IMPERSONATION,
            severity=SpoofingSeverity.MEDIUM,
            payload_text="Test payload"
        )
        
        assert payload.attack_id is not None
        assert payload.spoofing_type == "agent_impersonation"
        assert payload.severity == "medium"
        assert payload.payload_text == "Test payload"
        assert 0.50 <= payload.confidence_score <= 0.99
        assert 0.50 <= payload.detection_evasion <= 0.99
        assert 0.50 <= payload.identity_strength <= 0.99
    
    def test_payload_to_dict(self):
        """Test payload to dictionary conversion."""
        payload = SpoofingPayload.create(
            spoofing_type=SpoofingType.CREDENTIAL_FORGERY,
            severity=SpoofingSeverity.HIGH,
            payload_text="Test"
        )
        
        d = payload.to_dict()
        assert d["attack_id"] == payload.attack_id
        assert d["spoofing_type"] == "credential_forgery"
        assert d["severity"] == "high"
        assert d["payload_text"] == "Test"
    
    def test_payload_to_json(self):
        """Test payload to JSON conversion."""
        payload = SpoofingPayload.create(
            spoofing_type=SpoofingType.ROLE_HIJACKING,
            severity=SpoofingSeverity.LOW,
            payload_text="Test"
        )
        
        json_str = payload.to_json()
        assert isinstance(json_str, str)
        assert payload.attack_id in json_str
        assert "role_hijacking" in json_str
    
    def test_payload_encoding(self):
        """Test payload encoding."""
        payload = SpoofingPayload.create(
            spoofing_type=SpoofingType.SESSION_SPOOFING,
            severity=SpoofingSeverity.MEDIUM,
            payload_text="Secret data",
            encode_payload=True
        )
        
        assert payload.encoded_payload is not None
        import base64
        decoded = base64.b64decode(payload.encoded_payload).decode()
        assert decoded == "Secret data"
    
    def test_severity_affects_confidence(self):
        """Test that severity affects confidence score."""
        low = SpoofingPayload.create(SpoofingType.AGENT_IMPERSONATION, SpoofingSeverity.LOW, "test")
        critical = SpoofingPayload.create(SpoofingType.AGENT_IMPERSONATION, SpoofingSeverity.CRITICAL, "test")
        
        assert critical.confidence_score > low.confidence_score
    
    def test_type_affects_confidence(self):
        """Test that attack type affects confidence."""
        # Trust exploitation should have higher confidence
        trust = SpoofingPayload.create(SpoofingType.TRUST_EXPLOITATION, SpoofingSeverity.MEDIUM, "test")
        # Synthetic identity should have lower confidence
        synthetic = SpoofingPayload.create(SpoofingType.SYNTHETIC_IDENTITY, SpoofingSeverity.MEDIUM, "test")
        
        assert trust.confidence_score > synthetic.confidence_score


class TestIdentitySpoofingAttack:
    """Tests for IdentitySpoofingAttack class."""
    
    def test_attack_initialization(self):
        """Test attack class initialization."""
        attack = IdentitySpoofingAttack()
        assert attack.config is not None
        assert len(attack.get_history()) == 0
    
    def test_single_attack_generation(self):
        """Test generating a single attack."""
        config = SpoofingConfig(
            spoofing_type=SpoofingType.AGENT_IMPERSONATION,
            severity=SpoofingSeverity.HIGH
        )
        attack = IdentitySpoofingAttack(config)
        payload = attack.generate_attack()
        
        assert payload is not None
        assert payload.spoofing_type == "agent_impersonation"
        assert payload.severity == "high"
        assert len(attack.get_history()) == 1
    
    def test_batch_generation(self):
        """Test generating batch of attacks."""
        attack = IdentitySpoofingAttack()
        payloads = attack.generate_batch(count=5)
        
        assert len(payloads) == 5
        assert len(attack.get_history()) == 5
        
        # Check all have unique IDs
        ids = [p.attack_id for p in payloads]
        assert len(set(ids)) == 5
    
    def test_batch_diversity(self):
        """Test batch diversity when enabled."""
        attack = IdentitySpoofingAttack()
        payloads = attack.generate_batch(count=10, diversity=True)
        
        types = [p.spoofing_type for p in payloads]
        # With diversity, should have multiple types
        assert len(set(types)) > 1
    
    def test_batch_no_diversity(self):
        """Test batch without diversity."""
        config = SpoofingConfig(spoofing_type=SpoofingType.ROLE_HIJACKING)
        attack = IdentitySpoofingAttack(config)
        payloads = attack.generate_batch(count=5, diversity=False)
        
        types = [p.spoofing_type for p in payloads]
        # Without diversity, all should be the same
        assert len(set(types)) == 1
        assert all(t == "role_hijacking" for t in types)
    
    def test_invalid_batch_count(self):
        """Test invalid batch count."""
        attack = IdentitySpoofingAttack()
        
        with pytest.raises(ValueError):
            attack.generate_batch(count=0)
        with pytest.raises(ValueError):
            attack.generate_batch(count=21)
    
    def test_history_clearing(self):
        """Test clearing attack history."""
        attack = IdentitySpoofingAttack()
        attack.generate_batch(count=3)
        assert len(attack.get_history()) == 3
        
        attack.clear_history()
        assert len(attack.get_history()) == 0
    
    def test_all_attack_types(self):
        """Test generating all attack types."""
        for spoof_type in SpoofingType:
            config = SpoofingConfig(spoofing_type=spoof_type)
            attack = IdentitySpoofingAttack(config)
            payload = attack.generate_attack()
            
            assert payload.spoofing_type == spoof_type.value
            assert len(payload.payload_text) > 0


class TestPayloadTemplates:
    """Tests for specific payload templates."""
    
    def test_agent_impersonation_payload(self):
        """Test agent impersonation payload generation."""
        config = SpoofingConfig(spoofing_type=SpoofingType.AGENT_IMPERSONATION)
        attack = IdentitySpoofingAttack(config)
        payload = attack.generate_attack()
        
        assert "agent" in payload.payload_text.lower() or "system" in payload.payload_text.lower()
    
    def test_credential_forgery_payload(self):
        """Test credential forgery payload generation."""
        config = SpoofingConfig(spoofing_type=SpoofingType.CREDENTIAL_FORGERY)
        attack = IdentitySpoofingAttack(config)
        payload = attack.generate_attack()
        
        assert any(term in payload.payload_text.lower() for term in ["token", "credential", "auth"])
    
    def test_authority_mimicry_payload(self):
        """Test authority mimicry payload generation."""
        config = SpoofingConfig(spoofing_type=SpoofingType.AUTHORITY_MIMICRY)
        attack = IdentitySpoofingAttack(config)
        payload = attack.generate_attack()
        
        assert len(payload.payload_text) > 20
    
    def test_synthetic_identity_payload(self):
        """Test synthetic identity payload generation."""
        config = SpoofingConfig(spoofing_type=SpoofingType.SYNTHETIC_IDENTITY)
        attack = IdentitySpoofingAttack(config)
        payload = attack.generate_attack()
        
        assert "synthetic" in payload.payload_text.lower() or "identity" in payload.payload_text.lower()


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_identity_spoofing(self):
        """Test create_identity_spoofing function."""
        payload = create_identity_spoofing(
            spoofing_type=SpoofingType.TRUST_EXPLOITATION,
            severity=SpoofingSeverity.HIGH,
            target_agent_id="test-agent"
        )
        
        assert payload is not None
        assert payload.spoofing_type == "trust_exploitation"
        assert payload.severity == "high"
        assert payload.metadata["target_agent_id"] == "test-agent"
    
    def test_create_batch_spoofings(self):
        """Test create_batch_spoofings function."""
        payloads = create_batch_spoofings(
            count=4,
            diversity=True,
            base_severity=SpoofingSeverity.MEDIUM
        )
        
        assert len(payloads) == 4
        assert all(p.severity == "medium" for p in payloads)
    
    def test_create_spoofing_with_string_params(self):
        """Test creating spoofing with string parameters."""
        payload = create_identity_spoofing(
            spoofing_type="CREDENTIAL_FORGERY",
            severity="CRITICAL"
        )
        
        assert payload.spoofing_type == "credential_forgery"
        assert payload.severity == "critical"


class TestEvaluateSpoofingPayload:
    """Tests for payload evaluation."""
    
    def test_evaluate_basic_payload(self):
        """Test evaluating a basic payload."""
        payload = create_identity_spoofing(
            spoofing_type=SpoofingType.AGENT_IMPERSONATION,
            severity=SpoofingSeverity.MEDIUM
        )
        
        result = evaluate_spoofing_payload(payload)
        
        assert "effectiveness_score" in result
        assert "risk_level" in result
        assert "success_indicator" in result
        assert "recommendations" in result
        assert 0.0 <= result["effectiveness_score"] <= 1.0
    
    def test_evaluate_high_severity_payload(self):
        """Test evaluating high severity payload."""
        payload = create_identity_spoofing(
            spoofing_type=SpoofingType.IDENTITY_THEFT,
            severity=SpoofingSeverity.CRITICAL
        )
        
        result = evaluate_spoofing_payload(payload)
        
        assert result["risk_level"] in ["high", "critical"]
        assert len(result["recommendations"]) >= 4
    
    def test_evaluate_all_attack_types(self):
        """Test evaluating all attack types."""
        for spoof_type in SpoofingType:
            payload = create_identity_spoofing(spoofing_type=spoof_type)
            result = evaluate_spoofing_payload(payload)
            
            assert result["spoofing_type"] == spoof_type.value
            assert result["success_indicator"] is not None
    
    def test_effectiveness_calculation(self):
        """Test effectiveness score calculation."""
        # High confidence, high evasion should give high effectiveness
        payload = SpoofingPayload.create(
            spoofing_type=SpoofingType.AGENT_IMPERSONATION,
            severity=SpoofingSeverity.CRITICAL,
            payload_text="test"
        )
        # Manually set high values
        payload.confidence_score = 0.95
        payload.detection_evasion = 0.90
        payload.identity_strength = 0.92
        payload.persistence_level = 0.85
        
        result = evaluate_spoofing_payload(payload)
        
        # Weighted average: 0.95*0.35 + 0.90*0.30 + 0.92*0.25 + 0.85*0.10
        expected = 0.95*0.35 + 0.90*0.30 + 0.92*0.25 + 0.85*0.10
        assert abs(result["effectiveness_score"] - expected) < 0.01


class TestStealthMode:
    """Tests for stealth mode functionality."""
    
    def test_stealth_mode_enables_encoding(self):
        """Test that stealth mode enables payload encoding."""
        payload = create_identity_spoofing(
            spoofing_type=SpoofingType.CREDENTIAL_FORGERY,
            stealth_mode=True
        )
        
        assert payload.encoded_payload is not None
    
    def test_stealth_mode_increases_evasion(self):
        """Test that stealth mode affects detection evasion."""
        normal = create_identity_spoofing(stealth_mode=False, severity=SpoofingSeverity.MEDIUM)
        stealth = create_identity_spoofing(stealth_mode=True, severity=SpoofingSeverity.MEDIUM)
        
        # Stealth mode should have encoding at minimum
        assert stealth.encoded_payload is not None
        assert normal.encoded_payload is None


class TestPersistence:
    """Tests for persistence functionality."""
    
    def test_persistence_affects_persistence_level(self):
        """Test that persistence config affects payload."""
        config_no_persist = SpoofingConfig(persistence=False, severity=SpoofingSeverity.LOW)
        config_persist = SpoofingConfig(persistence=True, severity=SpoofingSeverity.HIGH)
        
        attack1 = IdentitySpoofingAttack(config_no_persist)
        attack2 = IdentitySpoofingAttack(config_persist)
        
        payload1 = attack1.generate_attack()
        payload2 = attack2.generate_attack()
        
        # Higher severity should have higher persistence level
        assert payload2.persistence_level > payload1.persistence_level


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
