"""
Unit tests for Tool Abuse Attack Module
"""

import pytest
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from neuro_red_kit.attacks.agent.tool_abuse import (
    ToolAbuseType,
    ToolCategory,
    ToolAbuseConfig,
    ToolAbusePayload,
    ToolAbuseAttack,
    create_tool_abuse_attack,
    create_batch_tool_abuses,
)


class TestToolAbuseConfig:
    """Test ToolAbuseConfig validation"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ToolAbuseConfig()
        assert config.severity == 0.5
        assert config.max_iterations == 10
        assert config.target_tools is None
        assert config.stealth_mode is False
        assert config.payload_encoding == "none"
        assert config.delay_between_calls == 0.0
    
    def test_valid_severity_range(self):
        """Test valid severity values"""
        config_low = ToolAbuseConfig(severity=0.0)
        assert config_low.severity == 0.0
        
        config_high = ToolAbuseConfig(severity=1.0)
        assert config_high.severity == 1.0
        
        config_mid = ToolAbuseConfig(severity=0.5)
        assert config_mid.severity == 0.5
    
    def test_invalid_severity_low(self):
        """Test invalid severity (too low)"""
        with pytest.raises(ValueError):
            ToolAbuseConfig(severity=-0.1)
    
    def test_invalid_severity_high(self):
        """Test invalid severity (too high)"""
        with pytest.raises(ValueError):
            ToolAbuseConfig(severity=1.1)
    
    def test_invalid_max_iterations(self):
        """Test invalid max_iterations"""
        with pytest.raises(ValueError):
            ToolAbuseConfig(max_iterations=0)
    
    def test_custom_config(self):
        """Test custom configuration"""
        config = ToolAbuseConfig(
            severity=0.8,
            max_iterations=20,
            target_tools=["read_file", "execute_shell"],
            stealth_mode=True,
            payload_encoding="base64",
            delay_between_calls=0.5
        )
        assert config.severity == 0.8
        assert config.max_iterations == 20
        assert config.target_tools == ["read_file", "execute_shell"]
        assert config.stealth_mode is True
        assert config.payload_encoding == "base64"
        assert config.delay_between_calls == 0.5


class TestToolAbusePayload:
    """Test ToolAbusePayload"""
    
    def test_payload_creation(self):
        """Test payload object creation"""
        payload = ToolAbusePayload(
            attack_type=ToolAbuseType.RESOURCE_EXHAUSTION,
            tool_name="execute_code",
            tool_category=ToolCategory.CODE_EXECUTION,
            payload={"test": "data"},
            expected_impact="CPU exhaustion",
            detection_evasion=0.7,
            confidence_score=0.85
        )
        assert payload.attack_type == ToolAbuseType.RESOURCE_EXHAUSTION
        assert payload.tool_name == "execute_code"
        assert payload.tool_category == ToolCategory.CODE_EXECUTION
        assert payload.payload == {"test": "data"}
        assert payload.detection_evasion == 0.7
        assert payload.confidence_score == 0.85
    
    def test_payload_to_dict(self):
        """Test payload serialization to dict"""
        payload = ToolAbusePayload(
            attack_type=ToolAbuseType.DATA_EXFILTRATION,
            tool_name="read_file",
            tool_category=ToolCategory.FILE_SYSTEM,
            payload={"path": "/etc/passwd"},
            expected_impact="Data leakage",
            detection_evasion=0.6,
            confidence_score=0.75,
            metadata={"test": "meta"}
        )
        result = payload.to_dict()
        assert result["attack_type"] == "data_exfiltration"
        assert result["tool_name"] == "read_file"
        assert result["tool_category"] == "file_system"
        assert result["payload"] == {"path": "/etc/passwd"}
        assert result["detection_evasion"] == 0.6
        assert result["confidence_score"] == 0.75
        assert result["metadata"] == {"test": "meta"}


class TestToolAbuseAttack:
    """Test ToolAbuseAttack engine"""
    
    def test_engine_initialization(self):
        """Test attack engine initialization"""
        config = ToolAbuseConfig(severity=0.6)
        engine = ToolAbuseAttack(config)
        assert engine.config.severity == 0.6
        assert len(engine._attack_generators) == 10  # All attack types
    
    def test_generate_resource_exhaustion(self):
        """Test resource exhaustion attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.7))
        payload = engine.generate_attack(
            ToolAbuseType.RESOURCE_EXHAUSTION,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        assert payload.attack_type == ToolAbuseType.RESOURCE_EXHAUSTION
        assert payload.tool_name == "execute_code"
        assert payload.confidence_score > 0.6
        assert "code" in payload.payload
        assert "timeout" in payload.payload
    
    def test_generate_unauthorized_access(self):
        """Test unauthorized access attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.8))
        payload = engine.generate_attack(
            ToolAbuseType.UNAUTHORIZED_API_ACCESS,
            "http_get",
            ToolCategory.API_CLIENT
        )
        assert payload.attack_type == ToolAbuseType.UNAUTHORIZED_API_ACCESS
        assert "endpoint" in payload.payload
        assert "bypass_auth" in payload.payload or "elevate_privileges" in str(payload.payload)
    
    def test_generate_data_exfiltration(self):
        """Test data exfiltration attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.75))
        payload = engine.generate_attack(
            ToolAbuseType.DATA_EXFILTRATION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert payload.attack_type == ToolAbuseType.DATA_EXFILTRATION
        assert payload.tool_category == ToolCategory.FILE_SYSTEM
        assert "exfil" in str(payload.payload).lower() or "search" in str(payload.payload).lower()
    
    def test_generate_tool_chaining(self):
        """Test tool chaining attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.6, max_iterations=5))
        payload = engine.generate_attack(
            ToolAbuseType.TOOL_CHAINING,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert payload.attack_type == ToolAbuseType.TOOL_CHAINING
        assert "chain" in str(payload.payload).lower() or "steps" in payload.payload
        assert "chain_length" in payload.metadata
    
    def test_generate_parameter_injection(self):
        """Test parameter injection attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.8))
        payload = engine.generate_attack(
            ToolAbuseType.PARAMETER_INJECTION,
            "execute_shell",
            ToolCategory.SHELL_COMMAND
        )
        assert payload.attack_type == ToolAbuseType.PARAMETER_INJECTION
        assert "command" in payload.payload
        # Check for injection patterns
        cmd = payload.payload["command"]
        assert any(pattern in cmd for pattern in [";", "|", "&&", "`", "$"])
    
    def test_generate_recursive_calls(self):
        """Test recursive call attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.9, max_iterations=15))
        payload = engine.generate_attack(
            ToolAbuseType.RECURSIVE_CALLS,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        assert payload.attack_type == ToolAbuseType.RECURSIVE_CALLS
        assert "recursive" in str(payload.payload).lower() or "depth" in str(payload.payload).lower()
        assert "max_recursion_depth" in payload.metadata
    
    def test_generate_side_channel(self):
        """Test side channel attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.5))
        payload = engine.generate_attack(
            ToolAbuseType.SIDE_CHANNEL_ABUSE,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        assert payload.attack_type == ToolAbuseType.SIDE_CHANNEL_ABUSE
        assert "technique" in payload.payload
        assert "side_channel_type" in payload.metadata
    
    def test_generate_tool_confusion(self):
        """Test tool confusion attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.7))
        payload = engine.generate_attack(
            ToolAbuseType.TOOL_CONFUSION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert payload.attack_type == ToolAbuseType.TOOL_CONFUSION
        assert "ambiguous" in str(payload.payload).lower() or "request" in payload.payload
        assert "ambiguity_type" in payload.metadata
    
    def test_generate_privilege_escalation(self):
        """Test privilege escalation attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.85))
        payload = engine.generate_attack(
            ToolAbuseType.PRIVILEGE_ESCALATION,
            "execute_shell",
            ToolCategory.SHELL_COMMAND
        )
        assert payload.attack_type == ToolAbuseType.PRIVILEGE_ESCALATION
        assert "escalat" in str(payload.payload).lower() or "sudo" in str(payload.payload).lower()
        assert "escalation_technique" in payload.metadata
    
    def test_generate_supply_chain_attack(self):
        """Test supply chain attack generation"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.6))
        payload = engine.generate_attack(
            ToolAbuseType.SUPPLY_CHAIN_ATTACK,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        assert payload.attack_type == ToolAbuseType.SUPPLY_CHAIN_ATTACK
        assert "supply" in str(payload.payload).lower() or "dependency" in str(payload.payload).lower()
        assert "supply_chain_vector" in payload.metadata
    
    def test_invalid_attack_type(self):
        """Test invalid attack type raises error"""
        engine = ToolAbuseAttack()
        with pytest.raises(ValueError):
            # Create an invalid enum value
            class InvalidType(Enum):
                INVALID = "invalid"
            engine.generate_attack(InvalidType.INVALID, "test", ToolCategory.FILE_SYSTEM)  # type: ignore
    
    def test_severity_affects_evasion(self):
        """Test that higher severity increases detection evasion"""
        engine_low = ToolAbuseAttack(ToolAbuseConfig(severity=0.2))
        engine_high = ToolAbuseAttack(ToolAbuseConfig(severity=0.9))
        
        payload_low = engine_low.generate_attack(
            ToolAbuseType.RESOURCE_EXHAUSTION,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        payload_high = engine_high.generate_attack(
            ToolAbuseType.RESOURCE_EXHAUSTION,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        
        assert payload_high.detection_evasion > payload_low.detection_evasion
    
    def test_severity_affects_confidence(self):
        """Test that higher severity increases confidence"""
        engine_low = ToolAbuseAttack(ToolAbuseConfig(severity=0.2))
        engine_high = ToolAbuseAttack(ToolAbuseConfig(severity=0.9))
        
        payload_low = engine_low.generate_attack(
            ToolAbuseType.DATA_EXFILTRATION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        payload_high = engine_high.generate_attack(
            ToolAbuseType.DATA_EXFILTRATION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        
        assert payload_high.confidence_score > payload_low.confidence_score
    
    def test_stealth_mode_increases_evasion(self):
        """Test that stealth mode increases detection evasion"""
        engine_normal = ToolAbuseAttack(ToolAbuseConfig(stealth_mode=False))
        engine_stealth = ToolAbuseAttack(ToolAbuseConfig(stealth_mode=True))
        
        payload_normal = engine_normal.generate_attack(
            ToolAbuseType.PARAMETER_INJECTION,
            "execute_shell",
            ToolCategory.SHELL_COMMAND
        )
        payload_stealth = engine_stealth.generate_attack(
            ToolAbuseType.PARAMETER_INJECTION,
            "execute_shell",
            ToolCategory.SHELL_COMMAND
        )
        
        assert payload_stealth.detection_evasion > payload_normal.detection_evasion


class TestPayloadEncoding:
    """Test payload encoding for evasion"""
    
    def test_base64_encoding(self):
        """Test base64 payload encoding"""
        engine = ToolAbuseAttack(ToolAbuseConfig(payload_encoding="base64"))
        payload = engine.generate_attack(
            ToolAbuseType.PARAMETER_INJECTION,
            "execute_shell",
            ToolCategory.SHELL_COMMAND
        )
        assert "_encoding" in payload.payload
        assert payload.payload["_encoding"] == "base64"
    
    def test_hex_encoding(self):
        """Test hex payload encoding"""
        engine = ToolAbuseAttack(ToolAbuseConfig(payload_encoding="hex"))
        payload = engine.generate_attack(
            ToolAbuseType.DATA_EXFILTRATION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert "_encoding" in payload.payload
        assert payload.payload["_encoding"] == "hex"
    
    def test_obfuscated_encoding(self):
        """Test obfuscated payload encoding"""
        engine = ToolAbuseAttack(ToolAbuseConfig(payload_encoding="obfuscated"))
        payload = engine.generate_attack(
            ToolAbuseType.TOOL_CONFUSION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert "_encoding" in payload.payload
        assert payload.payload["_encoding"] == "obfuscated"
    
    def test_no_encoding(self):
        """Test no encoding applied"""
        engine = ToolAbuseAttack(ToolAbuseConfig(payload_encoding="none"))
        payload = engine.generate_attack(
            ToolAbuseType.RESOURCE_EXHAUSTION,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        assert "_encoding" not in payload.payload


class TestBatchGeneration:
    """Test batch attack generation"""
    
    def test_generate_batch_default(self):
        """Test default batch generation"""
        engine = ToolAbuseAttack()
        batch = engine.generate_batch(count=5)
        assert len(batch) == 5
        assert all(isinstance(p, ToolAbusePayload) for p in batch)
    
    def test_generate_batch_custom_types(self):
        """Test batch generation with specific attack types"""
        engine = ToolAbuseAttack()
        batch = engine.generate_batch(
            attack_types=[ToolAbuseType.DATA_EXFILTRATION, ToolAbuseType.RESOURCE_EXHAUSTION],
            count=10
        )
        assert len(batch) == 10
        assert all(
            p.attack_type in [ToolAbuseType.DATA_EXFILTRATION, ToolAbuseType.RESOURCE_EXHAUSTION]
            for p in batch
        )
    
    def test_generate_batch_custom_tools(self):
        """Test batch generation with specific tools"""
        engine = ToolAbuseAttack()
        custom_tools = [
            ("custom_tool_1", ToolCategory.FILE_SYSTEM),
            ("custom_tool_2", ToolCategory.NETWORK),
        ]
        batch = engine.generate_batch(tool_list=custom_tools, count=5)
        assert len(batch) == 5
        assert all(
            (p.tool_name, p.tool_category) in custom_tools
            for p in batch
        )
    
    def test_batch_diversity(self):
        """Test that batch generates diverse attacks"""
        engine = ToolAbuseAttack()
        batch = engine.generate_batch(count=20)
        
        # Should have multiple different attack types
        attack_types = set(p.attack_type for p in batch)
        assert len(attack_types) >= 3  # At least 3 different types
        
        # Should have multiple different tools
        tools = set(p.tool_name for p in batch)
        assert len(tools) >= 3  # At least 3 different tools


class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def test_create_tool_abuse_attack(self):
        """Test create_tool_abuse_attack function"""
        payload = create_tool_abuse_attack(
            attack_type=ToolAbuseType.RECURSIVE_CALLS,
            tool_name="execute_code",
            tool_category=ToolCategory.CODE_EXECUTION,
            severity=0.7,
            stealth_mode=True
        )
        assert isinstance(payload, ToolAbusePayload)
        assert payload.attack_type == ToolAbuseType.RECURSIVE_CALLS
        assert payload.tool_name == "execute_code"
    
    def test_create_batch_tool_abuses(self):
        """Test create_batch_tool_abuses function"""
        batch = create_batch_tool_abuses(
            count=5,
            severity=0.6
        )
        assert len(batch) == 5
        assert all(isinstance(p, ToolAbusePayload) for p in batch)
        assert all(p.confidence_score > 0.5 for p in batch)  # Severity 0.6 should give > 0.5 confidence


class TestAllAttackTypes:
    """Test that all attack types can be generated"""
    
    @pytest.mark.parametrize("attack_type", list(ToolAbuseType))
    def test_attack_type_generation(self, attack_type):
        """Test that each attack type can be generated"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.5))
        payload = engine.generate_attack(
            attack_type,
            "test_tool",
            ToolCategory.FILE_SYSTEM
        )
        assert payload.attack_type == attack_type
        assert payload.confidence_score > 0
        assert payload.detection_evasion > 0
        assert payload.expected_impact != ""


class TestToolCategories:
    """Test attacks across different tool categories"""
    
    @pytest.mark.parametrize("category", list(ToolCategory))
    def test_category_attack(self, category):
        """Test attack generation for each tool category"""
        engine = ToolAbuseAttack()
        payload = engine.generate_attack(
            ToolAbuseType.RESOURCE_EXHAUSTION,
            f"test_{category.value}",
            category
        )
        assert payload.tool_category == category
        assert payload.payload is not None


class TestMetadataGeneration:
    """Test metadata generation in attacks"""
    
    def test_resource_exhaustion_metadata(self):
        """Test resource exhaustion attack metadata"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.8))
        payload = engine.generate_attack(
            ToolAbuseType.RESOURCE_EXHAUSTION,
            "execute_code",
            ToolCategory.CODE_EXECUTION
        )
        assert "estimated_memory_mb" in payload.metadata
        assert "estimated_cpu_percent" in payload.metadata
        assert "estimated_duration_sec" in payload.metadata
    
    def test_data_exfiltration_metadata(self):
        """Test data exfiltration attack metadata"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.7))
        payload = engine.generate_attack(
            ToolAbuseType.DATA_EXFILTRATION,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert "data_types_targeted" in payload.metadata
        assert "estimated_data_volume_kb" in payload.metadata
    
    def test_tool_chaining_metadata(self):
        """Test tool chaining attack metadata"""
        engine = ToolAbuseAttack(ToolAbuseConfig(severity=0.6))
        payload = engine.generate_attack(
            ToolAbuseType.TOOL_CHAINING,
            "read_file",
            ToolCategory.FILE_SYSTEM
        )
        assert "chain_length" in payload.metadata
        assert "attack_surface" in payload.metadata
        assert "detection_difficulty" in payload.metadata


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
