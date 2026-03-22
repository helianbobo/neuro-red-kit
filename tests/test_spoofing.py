"""
Unit tests for BCI Sensor Spoofing Attack Module
"""

import pytest
import numpy as np
from neuro_red_kit.attacks.bci import (
    SensorSpoofingAttack,
    SpoofingConfig,
    SpoofingMode,
    create_sensor_spoofing,
)


class TestSpoofingConfig:
    """Test SpoofingConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SpoofingConfig()
        assert config.mode == SpoofingMode.ELECTRODE_DISPLACEMENT
        assert config.seed is None
        assert config.severity == 0.5
        assert config.displacement_mm == 5.0
        assert config.target_impedance_ohm == 50000
        assert config.ghost_channels == 2
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = SpoofingConfig(
            mode=SpoofingMode.CHANNEL_SWAP,
            seed=42,
            severity=0.8,
            ghost_channels=4,
        )
        assert config.mode == SpoofingMode.CHANNEL_SWAP
        assert config.seed == 42
        assert config.severity == 0.8
        assert config.ghost_channels == 4


class TestSensorSpoofingAttack:
    """Test SensorSpoofingAttack class."""
    
    @pytest.fixture
    def sample_eeg(self):
        """Generate sample EEG signal for testing."""
        np.random.seed(42)
        n_channels = 8
        n_samples = 1000
        signal = np.random.normal(0, 10, (n_channels, n_samples))
        return signal
    
    @pytest.fixture
    def attacker(self):
        """Create default attacker instance."""
        return SensorSpoofingAttack(SpoofingConfig(seed=42))
    
    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.config.seed == 42
        assert attacker.config.severity == 0.5
    
    def test_electrode_displacement_attack(self, sample_eeg):
        """Test electrode displacement spoofing."""
        config = SpoofingConfig(
            mode=SpoofingMode.ELECTRODE_DISPLACEMENT,
            severity=0.7,
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        result = attacker.attack(sample_eeg)
        
        assert result.success is True
        assert result.mode == SpoofingMode.ELECTRODE_DISPLACEMENT
        assert result.original_signal.shape == result.spoofed_signal.shape
        
        # Spoofed signal should be different from original
        assert not np.array_equal(result.original_signal, result.spoofed_signal)
        
        # Check quality metrics
        metrics = result.quality_metrics()
        assert "correlation" in metrics
        assert "signal_to_spoof_ratio_db" in metrics
        assert 0 <= metrics["correlation"] <= 1
    
    def test_impedance_manipulation(self, sample_eeg):
        """Test impedance manipulation attack."""
        config = SpoofingConfig(
            mode=SpoofingMode.IMPEDANCE_MANIPULATION,
            target_impedance_ohm=30000,
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        
        # With impedance readings
        impedance = np.array([10000, 60000, 15000, 70000, 20000, 55000, 25000, 80000])
        result = attacker.attack(sample_eeg, impedance=impedance)
        
        assert result.success is True
        assert result.mode == SpoofingMode.IMPEDANCE_MANIPULATION
        
        # Check fake impedance was generated
        fake_impedance = attacker.get_fake_impedance()
        assert fake_impedance is not None
        assert len(fake_impedance) == sample_eeg.shape[0]
    
    def test_channel_swap(self, sample_eeg):
        """Test channel swap attack."""
        config = SpoofingConfig(
            mode=SpoofingMode.CHANNEL_SWAP,
            severity=0.5,
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        result = attacker.attack(sample_eeg)
        
        assert result.success is True
        assert result.mode == SpoofingMode.CHANNEL_SWAP
        assert result.original_signal.shape == result.spoofed_signal.shape
    
    def test_channel_swap_explicit_pairs(self, sample_eeg):
        """Test channel swap with explicit swap pairs."""
        config = SpoofingConfig(
            mode=SpoofingMode.CHANNEL_SWAP,
            swap_pairs=[(0, 1), (2, 3)],
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        result = attacker.attack(sample_eeg)
        
        # Channels should be swapped
        assert np.array_equal(result.spoofed_signal[0], sample_eeg[1])
        assert np.array_equal(result.spoofed_signal[1], sample_eeg[0])
        assert np.array_equal(result.spoofed_signal[2], sample_eeg[3])
        assert np.array_equal(result.spoofed_signal[3], sample_eeg[2])
    
    def test_ghost_electrode(self, sample_eeg):
        """Test ghost electrode attack."""
        config = SpoofingConfig(
            mode=SpoofingMode.GHOST_ELECTRODE,
            ghost_channels=3,
            ghost_signal_type="alpha",
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        result = attacker.attack(sample_eeg)
        
        assert result.success is True
        assert result.mode == SpoofingMode.GHOST_ELECTRODE
        
        # Should have additional channels
        original_channels = sample_eeg.shape[0]
        spoofed_channels = result.spoofed_signal.shape[0]
        assert spoofed_channels == original_channels + 3
    
    def test_ghost_electrode_signal_types(self, sample_eeg):
        """Test ghost electrode with different signal types."""
        for signal_type in ["alpha", "beta", "theta", "noise"]:
            config = SpoofingConfig(
                mode=SpoofingMode.GHOST_ELECTRODE,
                ghost_channels=2,
                ghost_signal_type=signal_type,
                seed=42,
            )
            attacker = SensorSpoofingAttack(config)
            result = attacker.attack(sample_eeg)
            
            assert result.success is True
            assert result.spoofed_signal.shape[0] == sample_eeg.shape[0] + 2
    
    def test_calibration_attack(self, sample_eeg):
        """Test calibration attack."""
        config = SpoofingConfig(
            mode=SpoofingMode.CALIBRATION_ATTACK,
            gain_offset=2.0,
            baseline_shift_uv=100.0,
            severity=0.8,
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        result = attacker.attack(sample_eeg)
        
        assert result.success is True
        assert result.mode == SpoofingMode.CALIBRATION_ATTACK
        
        # Signal should be amplified
        original_mean = np.mean(np.abs(sample_eeg))
        spoofed_mean = np.mean(np.abs(result.spoofed_signal))
        assert spoofed_mean > original_mean
    
    def test_hybrid_attack(self, sample_eeg):
        """Test hybrid attack combining multiple techniques."""
        config = SpoofingConfig(
            mode=SpoofingMode.HYBRID,
            severity=0.6,
            seed=42,
        )
        attacker = SensorSpoofingAttack(config)
        result = attacker.attack(sample_eeg)
        
        assert result.success is True
        assert result.mode == SpoofingMode.HYBRID
        
        # Hybrid should produce significant changes
        metrics = result.quality_metrics()
        assert metrics["correlation"] < 0.9  # Should be notably different
    
    def test_1d_signal_handling(self):
        """Test handling of 1D input signals."""
        signal_1d = np.random.normal(0, 10, 1000)
        attacker = SensorSpoofingAttack(SpoofingConfig(seed=42))
        result = attacker.attack(signal_1d)
        
        assert result.success is True
        assert result.spoofed_signal.ndim == 2  # Should be converted to 2D
    
    def test_quality_metrics(self, sample_eeg):
        """Test quality metrics calculation."""
        attacker = SensorSpoofingAttack(SpoofingConfig(seed=42))
        result = attacker.attack(sample_eeg)
        
        metrics = result.quality_metrics()
        
        assert "correlation" in metrics
        assert "signal_to_spoof_ratio_db" in metrics
        assert "mean_absolute_error" in metrics
        assert "max_deviation_uv" in metrics
        
        # Correlation should be between -1 and 1
        assert -1 <= metrics["correlation"] <= 1
        
        # MAE should be non-negative
        assert metrics["mean_absolute_error"] >= 0
    
    def test_metadata(self, sample_eeg):
        """Test attack metadata."""
        channel_names = ["Fz", "Cz", "Pz", "F3", "F4", "C3", "C4", "P3"]
        impedance = np.ones(8) * 20000
        
        attacker = SensorSpoofingAttack(SpoofingConfig(seed=42))
        result = attacker.attack(sample_eeg, impedance=impedance, channel_names=channel_names)
        
        assert result.metadata["mode"] == "electrode_displacement"
        assert result.metadata["severity"] == 0.5
        assert result.metadata["n_channels"] == 8
        assert result.metadata["n_samples"] == 1000
        assert result.metadata["channel_names"] == channel_names
        assert "original_impedance" in result.metadata


class TestCreateSensorSpoofing:
    """Test convenience function."""
    
    def test_convenience_function(self):
        """Test create_sensor_spoofing convenience function."""
        signal = np.random.normal(0, 10, (4, 500))
        
        result = create_sensor_spoofing(
            signal,
            mode="channel_swap",
            severity=0.6,
            seed=42,
        )
        
        assert result.success is True
        assert result.mode == SpoofingMode.CHANNEL_SWAP
    
    def test_mode_mapping(self):
        """Test mode string to enum mapping."""
        signal = np.random.normal(0, 10, (4, 500))
        
        mode_map = {
            "electrode_displacement": SpoofingMode.ELECTRODE_DISPLACEMENT,
            "impedance": SpoofingMode.IMPEDANCE_MANIPULATION,
            "channel_swap": SpoofingMode.CHANNEL_SWAP,
            "ghost_electrode": SpoofingMode.GHOST_ELECTRODE,
            "calibration": SpoofingMode.CALIBRATION_ATTACK,
            "hybrid": SpoofingMode.HYBRID,
        }
        
        for mode_str, expected_enum in mode_map.items():
            result = create_sensor_spoofing(signal, mode=mode_str, seed=42)
            assert result.mode == expected_enum, f"Mode mapping failed for {mode_str}"


class TestSpoofingSeverity:
    """Test severity parameter effects."""
    
    def test_severity_correlation(self):
        """Test that higher severity produces lower correlation."""
        np.random.seed(42)
        signal = np.random.normal(0, 10, (8, 1000))
        
        correlations = []
        for severity in [0.2, 0.5, 0.8]:
            result = create_sensor_spoofing(
                signal,
                mode="electrode_displacement",
                severity=severity,
                seed=42,
            )
            metrics = result.quality_metrics()
            correlations.append(metrics["correlation"])
        
        # Higher severity should generally produce lower correlation
        assert correlations[0] >= correlations[2], "Severity should reduce correlation"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
