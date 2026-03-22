"""
Tests for BCI Replay Attack Module
"""

import pytest
import numpy as np
from pathlib import Path
import tempfile
import shutil

from neuro_red_kit.attacks.bci.replay import ReplayAttackBCI, create_replay_attack


class TestReplayAttackBCI:
    """Test suite for ReplayAttackBCI class."""
    
    @pytest.fixture
    def sample_signal(self):
        """Create a sample EEG signal for testing."""
        sampling_rate = 250.0
        duration_sec = 2.0
        n_channels = 8
        n_samples = int(sampling_rate * duration_sec)
        
        t = np.linspace(0, duration_sec, n_samples)
        signal = np.zeros((n_channels, n_samples))
        for ch in range(n_channels):
            mu_rhythm = np.sin(2 * np.pi * 10 * t + ch * 0.1)
            noise = 0.1 * np.random.randn(n_samples)
            signal[ch] = mu_rhythm + noise
        
        return signal
    
    @pytest.fixture
    def attacker(self):
        """Create a ReplayAttackBCI instance."""
        return ReplayAttackBCI(sampling_rate=250.0)
    
    def test_init(self, attacker):
        """Test initialization."""
        assert attacker.sampling_rate == 250.0
        assert attacker.channel_names == []
        assert len(attacker.recorded_signals) == 0
    
    def test_record_signal(self, attacker, sample_signal):
        """Test signal recording."""
        signal_hash = attacker.record_signal(
            sample_signal,
            label='test_signal',
            user_id='user1',
            task_context='motor_imagery'
        )
        
        assert len(signal_hash) == 16
        assert 'test_signal' in attacker.recorded_signals
        assert attacker.metadata['test_signal']['user_id'] == 'user1'
        assert attacker.metadata['test_signal']['task_context'] == 'motor_imagery'
        assert attacker.recorded_signals['test_signal'].shape == sample_signal.shape
    
    def test_record_signal_save_to_disk(self, sample_signal):
        """Test signal recording with disk save."""
        with tempfile.TemporaryDirectory() as tmpdir:
            attacker = ReplayAttackBCI(sampling_rate=250.0)
            save_path = Path(tmpdir)
            
            signal_hash = attacker.record_signal(
                sample_signal,
                label='test_signal',
                save_path=save_path
            )
            
            # Check files were created
            assert (save_path / 'test_signal.npy').exists()
            assert (save_path / 'test_signal.meta.json').exists()
    
    def test_load_signal(self, attacker, sample_signal):
        """Test loading signal from disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = Path(tmpdir)
            
            # Save signal
            attacker.record_signal(
                sample_signal,
                label='test_signal',
                save_path=save_path
            )
            
            # Create new attacker and load
            attacker2 = ReplayAttackBCI(sampling_rate=250.0)
            loaded_signal = attacker2.load_signal(save_path, 'test_signal')
            
            assert np.allclose(loaded_signal, sample_signal)
    
    def test_direct_replay(self, attacker, sample_signal):
        """Test direct replay attack."""
        attacker.record_signal(sample_signal, label='test_signal')
        
        replayed, metadata = attacker.direct_replay('test_signal')
        
        assert replayed.shape == sample_signal.shape
        assert np.allclose(replayed, sample_signal)
        assert metadata['attack_type'] == 'direct_replay'
        assert metadata['detection_risk'] == 'HIGH'
    
    def test_direct_replay_not_found(self, attacker):
        """Test direct replay with non-existent label."""
        with pytest.raises(ValueError, match="not found"):
            attacker.direct_replay('nonexistent')
    
    def test_time_stretched_replay(self, attacker, sample_signal):
        """Test time-stretched replay attack."""
        attacker.record_signal(sample_signal, label='test_signal')
        
        # Stretch by 1.5x (slower)
        stretched, metadata = attacker.time_stretched_replay('test_signal', stretch_factor=1.5)
        
        assert stretched.shape[0] == sample_signal.shape[0]
        assert stretched.shape[1] < sample_signal.shape[1]  # Fewer samples when slower
        assert metadata['time_stretch_factor'] == 1.5
        assert metadata['detection_risk'] == 'MEDIUM'
    
    def test_segmented_replay(self, attacker, sample_signal):
        """Test segmented replay attack."""
        attacker.record_signal(sample_signal, label='test_signal')
        
        segments, metadata = attacker.segmented_replay(
            'test_signal',
            segment_duration=0.5,
            overlap=0.1
        )
        
        assert len(segments) > 1
        assert metadata['attack_type'] == 'segmented_replay'
        assert metadata['num_segments'] == len(segments)
    
    def test_hybrid_replay(self, attacker, sample_signal):
        """Test hybrid replay attack."""
        # Record multiple signals
        attacker.record_signal(sample_signal, label='signal1')
        attacker.record_signal(sample_signal * 0.9, label='signal2')
        
        combined, metadata = attacker.hybrid_replay(['signal1', 'signal2'])
        
        assert combined.shape == sample_signal.shape
        assert metadata['attack_type'] == 'hybrid_replay'
        assert len(metadata['source_labels']) == 2
    
    def test_add_noise_gaussian(self, attacker, sample_signal):
        """Test adding Gaussian noise."""
        noisy = attacker.add_noise(sample_signal, noise_level=0.1, noise_type='gaussian')
        
        assert noisy.shape == sample_signal.shape
        assert not np.allclose(noisy, sample_signal)
        assert np.mean(np.abs(noisy - sample_signal)) > 0
    
    def test_add_noise_uniform(self, attacker, sample_signal):
        """Test adding uniform noise."""
        noisy = attacker.add_noise(sample_signal, noise_level=0.1, noise_type='uniform')
        
        assert noisy.shape == sample_signal.shape
        assert not np.allclose(noisy, sample_signal)
    
    def test_add_noise_pink(self, attacker, sample_signal):
        """Test adding pink noise."""
        noisy = attacker.add_noise(sample_signal, noise_level=0.1, noise_type='pink')
        
        assert noisy.shape == sample_signal.shape
        assert not np.allclose(noisy, sample_signal)
    
    def test_add_noise_invalid_type(self, attacker, sample_signal):
        """Test adding noise with invalid type."""
        with pytest.raises(ValueError, match="Unknown noise type"):
            attacker.add_noise(sample_signal, noise_type='invalid')
    
    def test_evaluate_replay_success_identical(self, attacker, sample_signal):
        """Test evaluation with identical signals."""
        metrics = attacker.evaluate_replay_success(sample_signal, sample_signal)
        
        assert metrics['correlation'] == pytest.approx(1.0, abs=0.01)
        assert metrics['similarity_score'] == pytest.approx(1.0, abs=0.01)
        assert metrics['success'] == True
    
    def test_evaluate_replay_success_different(self, attacker, sample_signal):
        """Test evaluation with different signals."""
        different_signal = np.random.randn(*sample_signal.shape)
        metrics = attacker.evaluate_replay_success(sample_signal, different_signal)
        
        assert metrics['correlation'] < 0.5  # Should be low for random signals
        assert metrics['success'] == False
    
    def test_evaluate_replay_success_with_noise(self, attacker, sample_signal):
        """Test evaluation with noisy replay."""
        noisy_signal = attacker.add_noise(sample_signal, noise_level=0.01)
        metrics = attacker.evaluate_replay_success(sample_signal, noisy_signal)
        
        assert metrics['correlation'] > 0.9  # Should still be high with low noise
        assert metrics['snr_db'] > 20  # Good SNR


class TestCreateReplayAttack:
    """Test suite for create_replay_attack convenience function."""
    
    @pytest.fixture
    def sample_signal(self):
        """Create a sample EEG signal for testing."""
        sampling_rate = 250.0
        duration_sec = 1.0
        n_channels = 4
        n_samples = int(sampling_rate * duration_sec)
        return np.random.randn(n_channels, n_samples).astype(np.float32)
    
    def test_create_replay_direct(self, sample_signal):
        """Test creating direct replay attack."""
        replayed, metadata = create_replay_attack(
            sample_signal,
            attack_type='direct',
            sampling_rate=250.0
        )
        
        assert replayed.shape == sample_signal.shape
        assert metadata['attack_type'] == 'direct_replay'
    
    def test_create_replay_stretched(self, sample_signal):
        """Test creating stretched replay attack."""
        replayed, metadata = create_replay_attack(
            sample_signal,
            attack_type='stretched',
            sampling_rate=250.0,
            stretch_factor=1.2
        )
        
        assert metadata['attack_type'] == 'time_stretched_replay'
        assert metadata['time_stretch_factor'] == 1.2
    
    def test_create_replay_segmented(self, sample_signal):
        """Test creating segmented replay attack."""
        segments, metadata = create_replay_attack(
            sample_signal,
            attack_type='segmented',
            sampling_rate=250.0,
            segment_duration=0.5
        )
        
        assert isinstance(segments, list)
        assert len(segments) > 1
    
    def test_create_replay_invalid_type(self, sample_signal):
        """Test creating replay with invalid type."""
        with pytest.raises(ValueError, match="Unknown attack type"):
            create_replay_attack(
                sample_signal,
                attack_type='invalid',
                sampling_rate=250.0
            )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
