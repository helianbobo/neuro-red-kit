"""Tests for BCI adversarial attack module."""

import pytest
import numpy as np
import torch
import torch.nn as nn
from neuro_red_kit.attacks.bci import AdversarialBCIAttack, create_eeg_adversarial_sample


class DummyEEGModel(nn.Module):
    """Dummy EEG classification model for testing."""
    
    def __init__(self, n_channels=8, n_classes=4):
        super().__init__()
        self.conv = nn.Conv1d(n_channels, 16, 3)
        self.fc = nn.Linear(16 * 100, n_classes)
    
    def forward(self, x):
        x = torch.relu(self.conv(x))
        x = x.view(x.size(0), -1)
        return self.fc(x)


class TestAdversarialBCIAttack:
    """Test suite for AdversarialBCIAttack class."""
    
    @pytest.fixture
    def model(self):
        """Create a dummy model for testing."""
        return DummyEEGModel()
    
    @pytest.fixture
    def sample_data(self):
        """Create sample EEG data for testing."""
        x = np.random.randn(2, 8, 128).astype(np.float32)  # batch=2, channels=8, time=128
        y = np.array([0, 1])
        return x, y
    
    @pytest.fixture
    def attacker(self, model):
        """Create an attacker instance."""
        return AdversarialBCIAttack(model, epsilon=0.01, alpha=0.001, steps=10)
    
    def test_fgsm_attack(self, attacker, sample_data):
        """Test FGSM attack generates adversarial examples."""
        x, y = sample_data
        x_adv, perturbation = attacker.fgsm(x, y)
        
        # Check shapes
        assert x_adv.shape == x.shape
        assert perturbation.shape == x.shape
        
        # Check perturbation magnitude
        assert torch.all(torch.abs(perturbation) <= attacker.epsilon + 1e-6)
        
        # Check adversarial example is different from original
        assert not torch.allclose(x_adv, torch.from_numpy(x))
    
    def test_pgd_attack(self, attacker, sample_data):
        """Test PGD attack generates adversarial examples."""
        x, y = sample_data
        x_adv, perturbation = attacker.pgd(x, y)
        
        # Check shapes
        assert x_adv.shape == x.shape
        assert perturbation.shape == x.shape
        
        # Check perturbation is within epsilon ball
        assert torch.all(torch.abs(perturbation) <= attacker.epsilon + 1e-6)
    
    def test_targeted_attack(self, attacker, sample_data):
        """Test targeted attack mode."""
        x, y = sample_data
        x_adv, perturbation = attacker.fgsm(x, y, targeted=True)
        
        # Should still produce valid adversarial examples
        assert x_adv.shape == x.shape
        assert not torch.allclose(x_adv, torch.from_numpy(x))
    
    def test_attack_success_rate(self, attacker, sample_data):
        """Test attack success rate computation."""
        x, y = sample_data
        success_rate = attacker.attack_success_rate(x, y, method="fgsm")
        
        # Success rate should be between 0 and 1
        assert 0.0 <= success_rate <= 1.0


class TestCreateEEGAdversarialSample:
    """Test convenience function."""
    
    def test_convenience_function(self):
        """Test create_eeg_adversarial_sample function."""
        model = DummyEEGModel()
        eeg_signal = np.random.randn(8, 128).astype(np.float32)
        true_label = 0
        
        x_adv, pert_mag = create_eeg_adversarial_sample(
            eeg_signal, model, true_label, method="fgsm"
        )
        
        # Check output shape matches input
        assert x_adv.shape == eeg_signal.shape
        
        # Perturbation magnitude should be positive
        assert pert_mag > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
