"""Unit tests for wireless injection attacks."""

import pytest
import numpy as np
from neuro_red_kit.attacks.bci.injection import (
    WirelessInjector,
    InjectionConfig,
    InjectionResult,
    WirelessProtocol,
    InjectionMode,
    create_wireless_injection,
    simulate_eeg_spoofing,
)


class TestWirelessInjector:
    """Test cases for WirelessInjector class."""
    
    def test_init(self):
        """Test injector initialization."""
        injector = WirelessInjector()
        assert injector.sdr_device is None
        assert injector._packet_counter == 0
        
        injector_with_sdr = WirelessInjector(sdr_device="hackrf")
        assert injector_with_sdr.sdr_device == "hackrf"
    
    def test_execute_jamming_continuous(self):
        """Test continuous jamming attack."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.JAMMING,
            duration_seconds=1.0,
            jamming_pattern="continuous",
            noise_level=0.5
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "jamming"
        assert result.protocol == "openbci_2.4ghz"
        assert result.duration_seconds == 1.0
        assert result.packets_injected == 250  # 250 Hz sample rate * 1 second
        assert result.metadata["jamming_pattern"] == "continuous"
        assert result.metadata["noise_level"] == 0.5
    
    def test_execute_jamming_pulsed(self):
        """Test pulsed jamming attack."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.JAMMING,
            duration_seconds=1.0,
            jamming_pattern="pulsed",
            pulse_interval_ms=100
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "jamming"
        assert result.detection_evasion_score == 0.3  # Pulsed is harder to detect
    
    def test_execute_jamming_random(self):
        """Test random pattern jamming attack."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.JAMMING,
            duration_seconds=1.0,
            jamming_pattern="random"
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "jamming"
    
    def test_execute_jamming_invalid_pattern(self):
        """Test jamming with invalid pattern raises error."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.JAMMING,
            jamming_pattern="invalid"
        )
        
        with pytest.raises(ValueError, match="Unknown jamming pattern"):
            injector.execute(config)
    
    def test_execute_spoofing_with_data(self):
        """Test spoofing attack with provided EEG data."""
        injector = WirelessInjector()
        spoof_data = np.sin(np.linspace(0, 10 * np.pi, 250))  # 1 second of sine wave
        
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.SPOOFING,
            duration_seconds=1.0,
            spoof_data=spoof_data
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "spoofing"
        assert result.packets_injected > 0
        assert "signal_correlation" in result.metadata
    
    def test_execute_spoofing_synthetic(self):
        """Test spoofing attack with synthetic EEG generation."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.SPOOFING,
            duration_seconds=1.0
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "spoofing"
        assert result.packets_injected > 0
    
    def test_execute_spoofing_ble_protocol(self):
        """Test spoofing with BLE protocol."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.BLE,
            mode=InjectionMode.SPOOFING,
            duration_seconds=1.0
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.protocol == "bluetooth_le"
    
    def test_execute_injection(self):
        """Test injection attack into existing stream."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.INJECTION,
            duration_seconds=1.0
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "injection"
        assert result.packets_injected > 0
        assert "stealth_score" in result.metadata
    
    def test_execute_mitm(self):
        """Test man-in-the-middle attack."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode=InjectionMode.MITM,
            duration_seconds=1.0
        )
        
        result = injector.execute(config)
        
        assert result.success is True
        assert result.attack_type == "man_in_the_middle"
        assert result.packets_intercepted > 0
        assert result.packets_injected > 0
        assert result.metadata["intercept_rate_hz"] == 50
    
    def test_execute_invalid_mode(self):
        """Test execution with invalid mode raises error."""
        injector = WirelessInjector()
        config = InjectionConfig(
            protocol=WirelessProtocol.OPENBCI_24GHZ,
            mode="invalid_mode"  # type: ignore
        )
        
        with pytest.raises(ValueError, match="Unknown injection mode"):
            injector.execute(config)
    
    def test_generate_synthetic_eeg(self):
        """Test synthetic EEG signal generation."""
        injector = WirelessInjector()
        signal = injector._generate_synthetic_eeg(duration=1.0, sample_rate=250)
        
        assert len(signal) == 250
        assert isinstance(signal, np.ndarray)
        # Check that signal has reasonable amplitude (EEG is typically 10-100 μV)
        assert 0.01 < np.std(signal) < 2.0
    
    def test_encode_openbci_packets(self):
        """Test OpenBCI packet encoding."""
        injector = WirelessInjector()
        signal = np.random.randn(10)  # 10 samples
        
        packets = injector._encode_openbci_packets(signal)
        
        assert len(packets) == 10
        for packet in packets:
            assert len(packet) == 33  # OpenBCI packet size
            assert packet[0] == 0xA0  # Sync byte
            assert packet[-1] == 0xC0  # Footer
    
    def test_encode_openbci_packet_counter(self):
        """Test that packet counter increments correctly."""
        injector = WirelessInjector()
        signal = np.random.randn(5)
        
        packets = injector._encode_openbci_packets(signal)
        
        # Check sample numbers increment
        for i, packet in enumerate(packets):
            assert packet[1] == i  # Sample number
    
    def test_encode_ble_packets(self):
        """Test BLE packet encoding."""
        injector = WirelessInjector()
        signal = np.random.randn(8)  # 8 samples
        
        packets = injector._encode_ble_packets(signal)
        
        assert len(packets) == 2  # 4 samples per packet
        for packet in packets:
            assert len(packet) >= 4  # At least header + some payload + CRC
    
    def test_calculate_eeg_realism_good_signal(self):
        """Test EEG realism calculation with realistic signal."""
        injector = WirelessInjector()
        # Generate a signal with typical EEG characteristics
        t = np.linspace(0, 1, 250)
        realistic_signal = (
            0.5 * np.sin(2 * np.pi * 2 * t) +  # Delta
            0.3 * np.sin(2 * np.pi * 5 * t) +  # Theta
            0.4 * np.sin(2 * np.pi * 10 * t)   # Alpha
        )
        
        realism = injector._calculate_eeg_realism(realistic_signal)
        
        assert 0.0 <= realism <= 1.0
        assert realism > 0.5  # Should be reasonably realistic
    
    def test_calculate_eeg_realism_short_signal(self):
        """Test EEG realism with very short signal."""
        injector = WirelessInjector()
        short_signal = np.random.randn(50)
        
        realism = injector._calculate_eeg_realism(short_signal)
        
        assert realism == 0.5  # Default for short signals
    
    def test_create_injection_attack_convenience(self):
        """Test convenience method for creating attacks."""
        injector = WirelessInjector()
        
        result = injector.create_injection_attack(
            protocol="openbci_2.4ghz",
            mode="spoofing",
            duration=2.0,
            noise_level=0.3
        )
        
        assert result.success is True
        assert result.attack_type == "spoofing"
        assert result.duration_seconds == 2.0
    
    def test_create_injection_attack_protocol_mapping(self):
        """Test protocol string mapping."""
        injector = WirelessInjector()
        
        protocols = ["openbci_2.4ghz", "bluetooth_le", "wifi", "zigbee"]
        for protocol in protocols:
            result = injector.create_injection_attack(protocol=protocol, mode="jamming")
            assert result.success is True
    
    def test_create_injection_attack_mode_mapping(self):
        """Test mode string mapping."""
        injector = WirelessInjector()
        
        modes = ["jamming", "spoofing", "injection", "man_in_the_middle"]
        for mode in modes:
            result = injector.create_injection_attack(mode=mode, duration=0.1)
            assert result.success is True


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_wireless_injection(self):
        """Test create_wireless_injection function."""
        result = create_wireless_injection(
            protocol="openbci_2.4ghz",
            mode="injection",
            duration=0.5
        )
        
        assert isinstance(result, InjectionResult)
        assert result.success is True
    
    def test_simulate_eeg_spoofing(self):
        """Test simulate_eeg_spoofing function."""
        signal, result = simulate_eeg_spoofing(
            duration=0.5,
            sample_rate=250,
            protocol="openbci_2.4ghz"
        )
        
        assert isinstance(signal, np.ndarray)
        assert len(signal) == 125  # 0.5 seconds * 250 Hz
        assert isinstance(result, InjectionResult)
        assert result.success is True
        assert result.attack_type == "spoofing"


class TestInjectionResult:
    """Test InjectionResult dataclass."""
    
    def test_result_creation(self):
        """Test creating an InjectionResult."""
        result = InjectionResult(
            success=True,
            attack_type="test",
            protocol="test_protocol",
            duration_seconds=1.0
        )
        
        assert result.success is True
        assert result.attack_type == "test"
        assert result.protocol == "test_protocol"
        assert result.duration_seconds == 1.0
        assert result.packets_injected == 0  # Default
        assert result.packets_intercepted == 0  # Default
        assert result.signal_quality == 0.0  # Default
        assert result.detection_evasion_score == 0.0  # Default
        assert result.metadata == {}  # Default
    
    def test_result_with_metadata(self):
        """Test InjectionResult with metadata."""
        result = InjectionResult(
            success=True,
            attack_type="test",
            protocol="test",
            duration_seconds=1.0,
            packets_injected=100,
            metadata={"key": "value"}
        )
        
        assert result.packets_injected == 100
        assert result.metadata["key"] == "value"


class TestInjectionConfig:
    """Test InjectionConfig dataclass."""
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = InjectionConfig()
        
        assert config.protocol == WirelessProtocol.OPENBCI_24GHZ
        assert config.mode == InjectionMode.INJECTION
        assert config.channel == 0
        assert config.power_dbm == -20.0
        assert config.duration_seconds == 10.0
        assert config.target_mac is None
        assert config.spoof_data is None
        assert config.jamming_pattern == "continuous"
        assert config.pulse_interval_ms == 100
        assert config.noise_level == 0.5
    
    def test_config_custom(self):
        """Test custom configuration."""
        config = InjectionConfig(
            protocol=WirelessProtocol.BLE,
            mode=InjectionMode.JAMMING,
            channel=5,
            duration_seconds=5.0,
            noise_level=0.8
        )
        
        assert config.protocol == WirelessProtocol.BLE
        assert config.mode == InjectionMode.JAMMING
        assert config.channel == 5
        assert config.duration_seconds == 5.0
        assert config.noise_level == 0.8


class TestWirelessProtocol:
    """Test WirelessProtocol enum."""
    
    def test_protocol_values(self):
        """Test protocol enum values."""
        assert WirelessProtocol.OPENBCI_24GHZ.value == "openbci_2.4ghz"
        assert WirelessProtocol.BLE.value == "bluetooth_le"
        assert WirelessProtocol.WIFI.value == "wifi"
        assert WirelessProtocol.ZIGBEE.value == "zigbee"


class TestInjectionMode:
    """Test InjectionMode enum."""
    
    def test_mode_values(self):
        """Test mode enum values."""
        assert InjectionMode.JAMMING.value == "jamming"
        assert InjectionMode.SPOOFING.value == "spoofing"
        assert InjectionMode.INJECTION.value == "injection"
        assert InjectionMode.MITM.value == "man_in_the_middle"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
