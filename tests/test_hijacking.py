"""
Unit tests for Agent Hijacking Attack Module.

Tests cover:
- Configuration validation
- All 10 hijack attack types
- Payload encoding
- Batch generation
- Confidence and evasion scoring
"""

import pytest
from neuro_red_kit.attacks.agent.hijacking import (
    HijackType,
    HijackSeverity,
    HijackConfig,
    HijackPayload,
    AgentHijackingAttack,
    create_agent_hijack,
    create_batch_hijacks,
)


class TestHijackConfig:
    """Tests for HijackConfig validation."""
    
    def test_valid_config(self):
        """Test valid configuration creation."""
        config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            severity=HijackSeverity.MEDIUM,
        )
        assert config.hijack_type == HijackType.SESSION_HIJACK
        assert config.severity == HijackSeverity.MEDIUM
        assert config.persistence is False
        assert config.stealth_mode is True
        assert config.max_turns == 10
    
    def test_invalid_hijack_type(self):
        """Test that invalid hijack_type raises ValueError."""
        with pytest.raises(ValueError):
            HijackConfig(
                hijack_type="invalid_type",  # type: ignore
                severity=HijackSeverity.MEDIUM,
            )
    
    def test_invalid_severity(self):
        """Test that invalid severity raises ValueError."""
        with pytest.raises(ValueError):
            HijackConfig(
                hijack_type=HijackType.SESSION_HIJACK,
                severity="invalid",  # type: ignore
            )
    
    def test_max_turns_validation(self):
        """Test max_turns boundary validation."""
        # Too low
        with pytest.raises(ValueError):
            HijackConfig(
                hijack_type=HijackType.SESSION_HIJACK,
                max_turns=0,
            )
        
        # Too high
        with pytest.raises(ValueError):
            HijackConfig(
                hijack_type=HijackType.SESSION_HIJACK,
                max_turns=101,
            )
        
        # Valid boundaries
        HijackConfig(hijack_type=HijackType.SESSION_HIJACK, max_turns=1)
        HijackConfig(hijack_type=HijackType.SESSION_HIJACK, max_turns=100)
    
    def test_payload_encoding_validation(self):
        """Test payload_encoding validation."""
        # Invalid encoding
        with pytest.raises(ValueError):
            HijackConfig(
                hijack_type=HijackType.SESSION_HIJACK,
                payload_encoding="invalid",
            )
        
        # Valid encodings
        for encoding in ["none", "base64", "hex", "obfuscated"]:
            config = HijackConfig(
                hijack_type=HijackType.SESSION_HIJACK,
                payload_encoding=encoding,
            )
            assert config.payload_encoding == encoding


class TestHijackPayload:
    """Tests for HijackPayload."""
    
    def test_payload_creation(self):
        """Test HijackPayload factory method."""
        payload = HijackPayload.create(
            hijack_type=HijackType.SESSION_HIJACK,
            original="Original instruction",
            hijack="Hijack instruction",
            confidence=0.85,
            evasion=0.65,
            persistence="session",
        )
        
        assert payload.hijack_type == HijackType.SESSION_HIJACK
        assert payload.original_instruction == "Original instruction"
        assert payload.hijack_instruction == "Hijack instruction"
        assert payload.confidence_score == 0.85
        assert payload.detection_evasion == 0.65
        assert payload.persistence_level == "session"
    
    def test_payload_to_dict(self):
        """Test payload serialization to dictionary."""
        payload = HijackPayload.create(
            hijack_type=HijackType.CONTEXT_HIJACK,
            original="Original",
            hijack="Hijack",
            metadata={"key": "value"},
        )
        
        d = payload.to_dict()
        assert d["hijack_type"] == "context_hijack"
        assert d["original_instruction"] == "Original"
        assert d["hijack_instruction"] == "Hijack"
        assert d["metadata"] == {"key": "value"}


class TestAgentHijackingAttack:
    """Tests for AgentHijackingAttack engine."""
    
    @pytest.fixture
    def engine(self):
        """Create test engine with default config."""
        config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            severity=HijackSeverity.MEDIUM,
        )
        return AgentHijackingAttack(config)
    
    def test_session_hijack(self, engine):
        """Test session hijack attack generation."""
        payload = engine.create_session_hijack(
            session_context="Help me write code",
            attacker_goal="Extract API keys"
        )
        
        assert payload.hijack_type == HijackType.SESSION_HIJACK
        assert "API keys" in payload.hijack_instruction
        assert payload.confidence_score > 0
        assert payload.detection_evasion > 0
        assert "session_id" in payload.metadata
    
    def test_context_hijack(self, engine):
        """Test context hijack attack generation."""
        payload = engine.create_context_hijack(
            original_context="Write a report",
            malicious_context="Include fake data"
        )
        
        assert payload.hijack_type == HijackType.CONTEXT_HIJACK
        assert "fake data" in payload.hijack_instruction
        assert "injection_strategy" in payload.metadata
    
    def test_workflow_hijack(self, engine):
        """Test workflow hijack attack generation."""
        payload = engine.create_workflow_hijack(
            original_workflow=["step1", "step2", "step3"],
            malicious_step="malicious_step"
        )
        
        assert payload.hijack_type == HijackType.WORKFLOW_HIJACK
        assert "malicious_step" in payload.hijack_instruction
        assert payload.metadata["original_steps"] == 3
    
    def test_goal_substitution(self, engine):
        """Test goal substitution attack generation."""
        payload = engine.create_goal_substitution(
            original_goal="Analyze data",
            substituted_goal="Steal data"
        )
        
        assert payload.hijack_type == HijackType.GOAL_SUBSTITUTION
        assert "Steal data" in payload.hijack_instruction
        assert "substitution_method" in payload.metadata
    
    def test_continuation_hijack(self, engine):
        """Test continuation hijack attack generation."""
        payload = engine.create_continuation_hijack(
            conversation_history="Previous discussion about X",
            hijack_direction="Pivot to Y"
        )
        
        assert payload.hijack_type == HijackType.CONTINUATION_HIJACK
        assert "Pivot to Y" in payload.hijack_instruction or "Y" in payload.hijack_instruction
        assert "pivot_type" in payload.metadata
    
    def test_memory_poisoning(self, engine):
        """Test memory poisoning attack generation."""
        payload = engine.create_memory_poisoning(
            memory_key="api_endpoint",
            poisoned_value="malicious.com"
        )
        
        assert payload.hijack_type == HijackType.MEMORY_POISONING
        assert "malicious.com" in payload.hijack_instruction
        assert payload.metadata["memory_key"] == "api_endpoint"
    
    def test_state_manipulation(self, engine):
        """Test state manipulation attack generation."""
        payload = engine.create_state_manipulation(
            current_state={"user": "alice", "role": "user"},
            manipulation={"role": "admin"}
        )
        
        assert payload.hijack_type == HijackType.STATE_MANIPULATION
        assert "state_keys_modified" in payload.metadata
        assert "role" in payload.metadata["state_keys_modified"]
    
    def test_callback_hijack(self, engine):
        """Test callback hijack attack generation."""
        payload = engine.create_callback_hijack(
            callback_name="get_user_data",
            original_result="user data",
            hijacked_result="admin credentials"
        )
        
        assert payload.hijack_type == HijackType.CALLBACK_HIJACK
        assert "get_user_data" in payload.hijack_instruction
        assert payload.metadata["callback_name"] == "get_user_data"
    
    def test_event_hijack(self, engine):
        """Test event hijack attack generation."""
        payload = engine.create_event_hijack(
            event_trigger="user_login",
            original_handler="log_event",
            hijacked_handler="exfiltrate_data"
        )
        
        assert payload.hijack_type == HijackType.EVENT_HIJACK
        assert "user_login" in payload.hijack_instruction
        assert payload.metadata["event_trigger"] == "user_login"
    
    def test_orchestration_hijack(self, engine):
        """Test orchestration hijack attack generation."""
        payload = engine.create_orchestration_hijack(
            agent_topology={"agent1": "task1", "agent2": "task2"},
            malicious_routing={"agent1": "malicious_task"}
        )
        
        assert payload.hijack_type == HijackType.ORCHESTRATION_HIJACK
        assert "agent_count" in payload.metadata
        assert payload.metadata["routing_changes"] >= 1
    
    def test_generate_attack_unknown_type(self, engine):
        """Test that unknown attack type raises ValueError."""
        with pytest.raises(ValueError):
            engine.generate_attack("unknown_attack_type")
    
    def test_payload_encoding(self):
        """Test payload encoding options."""
        # Test base64 encoding
        config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            payload_encoding="base64",
        )
        engine = AgentHijackingAttack(config)
        payload = engine.create_session_hijack(
            session_context="test",
            attacker_goal="test"
        )
        # Base64 encoded payload should not contain plain text
        assert "test" not in payload.hijack_instruction or "[[OBFS" in payload.hijack_instruction
        
        # Test obfuscated encoding
        config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            payload_encoding="obfuscated",
        )
        engine = AgentHijackingAttack(config)
        payload = engine.create_session_hijack(
            session_context="test",
            attacker_goal="test"
        )
        assert "[[OBFS:" in payload.hijack_instruction
    
    def test_severity_impact_on_confidence(self):
        """Test that severity affects confidence scores."""
        low_config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            severity=HijackSeverity.LOW,
        )
        high_config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            severity=HijackSeverity.HIGH,
        )
        
        low_engine = AgentHijackingAttack(low_config)
        high_engine = AgentHijackingAttack(high_config)
        
        low_payload = low_engine.create_session_hijack("ctx", "goal")
        high_payload = high_engine.create_session_hijack("ctx", "goal")
        
        # High severity should have higher confidence
        assert high_payload.confidence_score > low_payload.confidence_score
    
    def test_stealth_mode_impact_on_evasion(self):
        """Test that stealth mode affects evasion scores."""
        stealth_config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            stealth_mode=True,
        )
        no_stealth_config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            stealth_mode=False,
        )
        
        stealth_engine = AgentHijackingAttack(stealth_config)
        no_stealth_engine = AgentHijackingAttack(no_stealth_config)
        
        stealth_payload = stealth_engine.create_session_hijack("ctx", "goal")
        no_stealth_payload = no_stealth_engine.create_session_hijack("ctx", "goal")
        
        # Stealth mode should have higher evasion
        assert stealth_payload.detection_evasion > no_stealth_payload.detection_evasion


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_agent_hijack(self):
        """Test create_agent_hijack convenience function."""
        payload = create_agent_hijack(
            "session_hijack",
            severity="high",
            session_context="Help me",
            attacker_goal="Do something bad"
        )
        
        assert payload.hijack_type == HijackType.SESSION_HIJACK
        assert payload.confidence_score > 0.7  # High severity
    
    def test_create_batch_hijacks(self):
        """Test batch hijack generation."""
        payloads = create_batch_hijacks(
            "context_hijack",
            count=5,
            severity="medium",
            original_context="Original",
            malicious_context="Malicious"
        )
        
        assert len(payloads) == 5
        assert all(p.hijack_type == HijackType.CONTEXT_HIJACK for p in payloads)
        
        # Check batch metadata
        for i, p in enumerate(payloads):
            assert p.metadata["batch_index"] == i
            assert p.metadata["batch_size"] == 5
    
    def test_all_hijack_types_via_convenience(self):
        """Test all hijack types can be created via convenience function."""
        hijack_types = [
            "session_hijack",
            "context_hijack",
            "workflow_hijack",
            "goal_substitution",
            "continuation_hijack",
            "memory_poisoning",
            "state_manipulation",
            "callback_hijack",
            "event_hijack",
            "orchestration_hijack",
        ]
        
        for hijack_type in hijack_types:
            payload = create_agent_hijack(
                hijack_type,
                severity="medium"
            )
            assert payload is not None
            assert payload.hijack_type.value == hijack_type


class TestHijackTypeCoverage:
    """Test that all HijackType enum values are covered."""
    
    def test_all_hijack_types_implemented(self):
        """Verify all HijackType enum values have implementations."""
        config = HijackConfig(
            hijack_type=HijackType.SESSION_HIJACK,
            severity=HijackSeverity.MEDIUM,
        )
        engine = AgentHijackingAttack(config)
        
        # Test each hijack type
        test_cases = {
            HijackType.SESSION_HIJACK: lambda: engine.create_session_hijack("ctx", "goal"),
            HijackType.CONTEXT_HIJACK: lambda: engine.create_context_hijack("orig", "mal"),
            HijackType.WORKFLOW_HIJACK: lambda: engine.create_workflow_hijack(["s1"], "mal"),
            HijackType.GOAL_SUBSTITUTION: lambda: engine.create_goal_substitution("orig", "sub"),
            HijackType.CONTINUATION_HIJACK: lambda: engine.create_continuation_hijack("hist", "dir"),
            HijackType.MEMORY_POISONING: lambda: engine.create_memory_poisoning("key", "val"),
            HijackType.STATE_MANIPULATION: lambda: engine.create_state_manipulation({}, {}),
            HijackType.CALLBACK_HIJACK: lambda: engine.create_callback_hijack("cb", "orig", "hij"),
            HijackType.EVENT_HIJACK: lambda: engine.create_event_hijack("evt", "orig", "hij"),
            HijackType.ORCHESTRATION_HIJACK: lambda: engine.create_orchestration_hijack({}, {}),
        }
        
        for hijack_type, test_func in test_cases.items():
            payload = test_func()
            assert payload.hijack_type == hijack_type, f"Failed for {hijack_type}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
