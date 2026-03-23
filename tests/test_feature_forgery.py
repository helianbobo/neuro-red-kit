"""
Tests for Feature Forgery Attack Module
"""

import pytest
import numpy as np
from neuro_red_kit.attacks.bci.feature_forgery import (
    FeatureForgeryAttack,
    ForgeryConfig,
    ForgeryType,
    create_feature_forgery,
)


class TestForgeryConfig:
    """Test ForgeryConfig validation."""
    
    def test_valid_config(self):
        """Test valid configuration."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.5,
            sampling_rate=250.0
        )
        assert config.validate() is True
    
    def test_invalid_severity_high(self):
        """Test invalid severity (> 1.0)."""
        config = ForgeryConfig(severity=1.5)
        assert config.validate() is False
    
    def test_invalid_severity_negative(self):
        """Test invalid severity (< 0.0)."""
        config = ForgeryConfig(severity=-0.1)
        assert config.validate() is False
    
    def test_invalid_sampling_rate(self):
        """Test invalid sampling rate."""
        config = ForgeryConfig(sampling_rate=0)
        assert config.validate() is False
    
    def test_invalid_target_bands(self):
        """Test invalid target band values."""
        config = ForgeryConfig(target_bands={'alpha': 3.0})
        assert config.validate() is False


class TestFeatureForgeryAttack:
    """Test FeatureForgeryAttack class."""
    
    @pytest.fixture
    def synthetic_eeg(self):
        """Generate synthetic EEG signal for testing."""
        np.random.seed(42)
        n_channels = 8
        n_samples = 2500  # 10 seconds at 250Hz
        t = np.arange(n_samples) / 250
        
        eeg_signal = np.zeros((n_channels, n_samples))
        for ch in range(n_channels):
            eeg_signal[ch] += np.sin(2 * np.pi * 10 * t) * (1 - ch * 0.1)  # Alpha
            eeg_signal[ch] += np.random.randn(n_samples) * 0.5
        
        return eeg_signal
    
    def test_psd_manipulation(self, synthetic_eeg):
        """Test PSD manipulation attack."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.7,
            target_bands={'alpha': 2.0, 'beta': 0.5},
            sampling_rate=250.0
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        assert 'forged_signal' in result
        assert result['forged_signal'].shape == synthetic_eeg.shape
        assert result['forgery_type'] == 'psd_manipulation'
        assert 'quality_metrics' in result
        assert 'correlation' in result['quality_metrics']
    
    def test_erp_synthesis(self, synthetic_eeg):
        """Test ERP synthesis attack."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.ERP_SYNTHESIS,
            severity=0.8,
            sampling_rate=250.0,
            erp_components={'P300': (300, 10.0), 'N400': (400, -5.0)}
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        assert result['forged_signal'].shape == synthetic_eeg.shape
        assert result['forgery_type'] == 'erp_synthesis'
        
        # Check that ERP components were added (signal should differ)
        diff = np.abs(result['forged_signal'] - synthetic_eeg)
        assert np.max(diff) > 0.1  # Should have noticeable deviation
    
    def test_connectivity_forgery(self, synthetic_eeg):
        """Test connectivity forgery attack."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.CONNECTIVITY_FORGERY,
            severity=0.6,
            sampling_rate=250.0
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        assert result['forged_signal'].shape == synthetic_eeg.shape
        assert result['forgery_type'] == 'connectivity_forgery'
    
    def test_microstate_manipulation(self, synthetic_eeg):
        """Test microstate manipulation attack."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.MICROSTATE_MANIPULATION,
            severity=0.5,
            sampling_rate=250.0,
            microstate_classes=4
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        assert result['forged_signal'].shape == synthetic_eeg.shape
        assert result['forgery_type'] == 'microstate_manipulation'
    
    def test_cross_frequency_coupling(self, synthetic_eeg):
        """Test cross-frequency coupling attack."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.CROSS_FREQUENCY_COUPLING,
            severity=0.6,
            sampling_rate=250.0,
            pac_frequency_band=(4, 8),
            pac_amplitude_band=(30, 50)
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        assert result['forged_signal'].shape == synthetic_eeg.shape
        assert result['forgery_type'] == 'cross_frequency_coupling'
    
    def test_hybrid_forgery(self, synthetic_eeg):
        """Test hybrid forgery attack."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.HYBRID,
            severity=0.5,
            sampling_rate=250.0
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        assert result['forged_signal'].shape == synthetic_eeg.shape
        assert result['forgery_type'] == 'hybrid'
        
        # Hybrid should have lower correlation due to multiple transformations
        assert result['quality_metrics']['correlation'] < 0.99
    
    def test_quality_metrics(self, synthetic_eeg):
        """Test quality metrics calculation."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.5,
            sampling_rate=250.0
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        metrics = result['quality_metrics']
        
        # Check all expected metrics are present
        assert 'correlation' in metrics
        assert 'mse' in metrics
        assert 'snr_db' in metrics
        assert 'max_deviation' in metrics
        assert 'spectral_correlation' in metrics
        
        # Check metric ranges
        assert -1.0 <= metrics['correlation'] <= 1.0
        assert metrics['mse'] >= 0
        assert metrics['max_deviation'] >= 0
    
    def test_metadata(self, synthetic_eeg):
        """Test attack metadata."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.7,
            sampling_rate=250.0
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(synthetic_eeg)
        
        metadata = result['metadata']
        assert metadata['severity'] == 0.7
        assert metadata['sampling_rate'] == 250.0
        assert metadata['n_channels'] == 8
        assert metadata['n_samples'] == 2500
        assert 'attack_timestamp' in metadata
    
    def test_1d_signal(self):
        """Test with 1D signal (single channel)."""
        np.random.seed(42)
        signal_1d = np.random.randn(2500)
        
        config = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.5,
            sampling_rate=250.0
        )
        attacker = FeatureForgeryAttack(config)
        result = attacker.attack(signal_1d)
        
        # Should be converted to 2D
        assert result['forged_signal'].ndim == 2
        assert result['forged_signal'].shape[0] == 1
    
    def test_invalid_forgery_type(self, synthetic_eeg):
        """Test with invalid forgery type."""
        config = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.5,
            sampling_rate=250.0
        )
        # Manually set invalid type
        config.forgery_type = "invalid_type"
        
        attacker = FeatureForgeryAttack(config)
        
        with pytest.raises(ValueError):
            attacker.attack(synthetic_eeg)


class TestCreateFeatureForgery:
    """Test convenience function."""
    
    @pytest.fixture
    def synthetic_eeg(self):
        """Generate synthetic EEG signal for testing."""
        np.random.seed(42)
        return np.random.randn(8, 2500)
    
    def test_convenience_function_psd(self, synthetic_eeg):
        """Test convenience function with PSD manipulation."""
        result = create_feature_forgery(
            synthetic_eeg,
            forgery_type="psd_manipulation",
            severity=0.6,
            target_bands={'alpha': 1.5},
            sampling_rate=250.0
        )
        
        assert 'forged_signal' in result
        assert result['forgery_type'] == 'psd_manipulation'
    
    def test_convenience_function_erp(self, synthetic_eeg):
        """Test convenience function with ERP synthesis."""
        result = create_feature_forgery(
            synthetic_eeg,
            forgery_type="erp_synthesis",
            severity=0.7,
            sampling_rate=250.0
        )
        
        assert result['forgery_type'] == 'erp_synthesis'
    
    def test_convenience_function_hybrid(self, synthetic_eeg):
        """Test convenience function with hybrid forgery."""
        result = create_feature_forgery(
            synthetic_eeg,
            forgery_type="hybrid",
            severity=0.5,
            sampling_rate=250.0
        )
        
        assert result['forgery_type'] == 'hybrid'
    
    def test_convenience_function_invalid_type(self, synthetic_eeg):
        """Test convenience function with invalid type."""
        with pytest.raises(ValueError, match="Unknown forgery type"):
            create_feature_forgery(
                synthetic_eeg,
                forgery_type="invalid_type",
                sampling_rate=250.0
            )


class TestSeverityEffects:
    """Test that severity parameter has expected effects."""
    
    @pytest.fixture
    def synthetic_eeg(self):
        """Generate synthetic EEG signal for testing."""
        np.random.seed(42)
        return np.random.randn(4, 2500)
    
    def test_higher_severity_lower_correlation(self, synthetic_eeg):
        """Test that higher severity leads to lower correlation."""
        config_low = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.2,
            sampling_rate=250.0
        )
        config_high = ForgeryConfig(
            forgery_type=ForgeryType.PSD_MANIPULATION,
            severity=0.9,
            sampling_rate=250.0
        )
        
        attacker_low = FeatureForgeryAttack(config_low)
        attacker_high = FeatureForgeryAttack(config_high)
        
        result_low = attacker_low.attack(synthetic_eeg)
        result_high = attacker_high.attack(synthetic_eeg)
        
        # Higher severity should generally lead to lower correlation
        assert result_low['quality_metrics']['correlation'] > result_high['quality_metrics']['correlation']
    
    def test_higher_severity_higher_mse(self, synthetic_eeg):
        """Test that higher severity leads to higher MSE."""
        config_low = ForgeryConfig(
            forgery_type=ForgeryType.ERP_SYNTHESIS,
            severity=0.3,
            sampling_rate=250.0
        )
        config_high = ForgeryConfig(
            forgery_type=ForgeryType.ERP_SYNTHESIS,
            severity=0.9,
            sampling_rate=250.0
        )
        
        attacker_low = FeatureForgeryAttack(config_low)
        attacker_high = FeatureForgeryAttack(config_high)
        
        result_low = attacker_low.attack(synthetic_eeg)
        result_high = attacker_high.attack(synthetic_eeg)
        
        # Higher severity should lead to higher MSE
        assert result_high['quality_metrics']['mse'] > result_low['quality_metrics']['mse']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
