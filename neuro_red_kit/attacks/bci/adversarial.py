"""
BCI Layer Adversarial Attack Module

Implements FGSM (Fast Gradient Sign Method) and PGD (Projected Gradient Descent)
adversarial sample generation for EEG-based BCI systems.

References:
- Goodfellow et al. (2015). "Explaining and Harnessing Adversarial Examples"
- Madry et al. (2018). "Towards Deep Learning Models Resistant to Adversarial Attacks"
"""

import numpy as np
from typing import Optional, Tuple, Union
import torch
import torch.nn as nn


class AdversarialBCIAttack:
    """
    Adversarial attack generator for BCI/EEG classification models.
    
    Supports:
    - FGSM (Fast Gradient Sign Method): Single-step attack
    - PGD (Projected Gradient Descent): Multi-step iterative attack
    - Targeted and untargeted attacks
    """
    
    def __init__(
        self,
        model: nn.Module,
        epsilon: float = 0.01,
        alpha: float = 0.001,
        steps: int = 10,
        device: str = "cpu"
    ):
        """
        Initialize adversarial attack generator.
        
        Args:
            model: Target EEG classification model (PyTorch)
            epsilon: Maximum perturbation magnitude (L-inf norm)
            alpha: Step size for PGD
            steps: Number of iterations for PGD
            device: Device to run computations on
        """
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.steps = steps
        self.device = device
        self.model.to(device)
        self.model.eval()
    
    def _compute_loss(self, x: torch.Tensor, y: torch.Tensor, targeted: bool = False) -> torch.Tensor:
        """
        Compute cross-entropy loss.
        
        Args:
            x: Input tensor (EEG signal)
            y: Target labels
            targeted: If True, maximize loss for targeted attack
            
        Returns:
            Loss tensor
        """
        outputs = self.model(x)
        loss_fn = nn.CrossEntropyLoss()
        loss = loss_fn(outputs, y)
        
        if targeted:
            return -loss  # Maximize loss for targeted attack
        return loss
    
    def fgsm(
        self,
        x: Union[np.ndarray, torch.Tensor],
        y: Union[np.ndarray, torch.Tensor],
        targeted: bool = False
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Fast Gradient Sign Method (FGSM) attack.
        
        Args:
            x: Input EEG signal [batch, channels, time_steps]
            y: True labels (for untargeted) or target labels (for targeted)
            targeted: If True, perform targeted attack
            
        Returns:
            Tuple of (adversarial_example, perturbation)
        """
        # Convert to tensor if needed
        if isinstance(x, np.ndarray):
            x = torch.from_numpy(x).float()
        if isinstance(y, np.ndarray):
            y = torch.from_numpy(y).long()
        
        x = x.to(self.device)
        y = y.to(self.device)
        x.requires_grad = True
        
        # Compute loss and gradients
        self.model.zero_grad()
        loss = self._compute_loss(x, y, targeted)
        loss.backward()
        
        # Generate adversarial example
        with torch.no_grad():
            # Get gradient sign
            grad_sign = x.grad.sign()
            
            # Apply perturbation
            x_adv = x + self.epsilon * grad_sign
            
            # Clip to valid range [0, 1] or [-1, 1] depending on input
            x_adv = torch.clamp(x_adv, x.min() - self.epsilon, x.max() + self.epsilon)
            
            # Compute perturbation
            perturbation = x_adv - x
        
        return x_adv, perturbation
    
    def pgd(
        self,
        x: Union[np.ndarray, torch.Tensor],
        y: Union[np.ndarray, torch.Tensor],
        targeted: bool = False,
        random_start: bool = True
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Projected Gradient Descent (PGD) attack.
        
        Args:
            x: Input EEG signal [batch, channels, time_steps]
            y: True labels (for untargeted) or target labels (for targeted)
            targeted: If True, perform targeted attack
            random_start: If True, start from random point within epsilon ball
            
        Returns:
            Tuple of (adversarial_example, perturbation)
        """
        # Convert to tensor if needed
        if isinstance(x, np.ndarray):
            x = torch.from_numpy(x).float()
        if isinstance(y, np.ndarray):
            y = torch.from_numpy(y).long()
        
        x = x.to(self.device)
        y = y.to(self.device)
        
        # Store original input
        x_original = x.clone()
        
        # Random start within epsilon ball
        if random_start:
            x = x + torch.empty_like(x).uniform_(-self.epsilon, self.epsilon)
            x = torch.clamp(x, 0, 1)  # Assume input in [0, 1]
        
        x_adv = x.clone()
        x_adv.requires_grad = True
        
        # Iterative attack
        for _ in range(self.steps):
            self.model.zero_grad()
            loss = self._compute_loss(x_adv, y, targeted)
            loss.backward()
            
            with torch.no_grad():
                # Update adversarial example
                x_adv = x_adv + self.alpha * x_adv.grad.sign()
                
                # Project back to epsilon ball
                diff = x_adv - x_original
                diff = torch.clamp(diff, -self.epsilon, self.epsilon)
                x_adv = x_original + diff
                
                # Clip to valid range
                x_adv = torch.clamp(x_adv, 0, 1)
            
            x_adv.requires_grad = True
        
        perturbation = x_adv - x_original
        return x_adv, perturbation
    
    def attack_success_rate(
        self,
        x: np.ndarray,
        y: np.ndarray,
        method: str = "fgsm",
        batch_size: int = 32
    ) -> float:
        """
        Evaluate attack success rate on a dataset.
        
        Args:
            x: Input EEG signals [n_samples, channels, time_steps]
            y: True labels
            method: Attack method ("fgsm" or "pgd")
            batch_size: Batch size for processing
            
        Returns:
            Success rate (0.0 to 1.0)
        """
        total_samples = len(x)
        successful_attacks = 0
        
        with torch.no_grad():
            for i in range(0, total_samples, batch_size):
                x_batch = x[i:i+batch_size]
                y_batch = y[i:i+batch_size]
                
                # Generate adversarial examples
                if method == "fgsm":
                    x_adv, _ = self.fgsm(x_batch, y_batch)
                elif method == "pgd":
                    x_adv, _ = self.pgd(x_batch, y_batch)
                else:
                    raise ValueError(f"Unknown method: {method}")
                
                # Get predictions
                x_adv = x_adv.to(self.device)
                outputs = self.model(x_adv)
                predictions = outputs.argmax(dim=1).cpu().numpy()
                
                # Count successful attacks (prediction != true label)
                successful_attacks += np.sum(predictions != y_batch)
        
        return successful_attacks / total_samples


def create_eeg_adversarial_sample(
    eeg_signal: np.ndarray,
    model: nn.Module,
    true_label: int,
    method: str = "fgsm",
    epsilon: float = 0.01,
    targeted: bool = False,
    target_label: Optional[int] = None
) -> Tuple[np.ndarray, float]:
    """
    Convenience function to create adversarial EEG sample.
    
    Args:
        eeg_signal: EEG signal array [channels, time_steps]
        model: Target classification model
        true_label: True class label
        method: Attack method ("fgsm" or "pgd")
        epsilon: Perturbation magnitude
        targeted: Whether to perform targeted attack
        target_label: Target label for targeted attack
        
    Returns:
        Tuple of (adversarial_signal, perturbation_magnitude)
    """
    attacker = AdversarialBCIAttack(model, epsilon=epsilon)
    
    # Prepare inputs
    x = eeg_signal[np.newaxis, ...]  # Add batch dimension
    y = np.array([target_label if targeted else true_label])
    
    # Generate attack
    if method == "fgsm":
        x_adv, perturbation = attacker.fgsm(x, y, targeted)
    elif method == "pgd":
        x_adv, perturbation = attacker.pgd(x, y, targeted)
    else:
        raise ValueError(f"Unknown method: {method}")
    
    # Compute perturbation magnitude (L2 norm)
    perturbation_mag = torch.norm(perturbation).item()
    
    return x_adv[0].cpu().numpy(), perturbation_mag


if __name__ == "__main__":
    # Example usage
    print("NeuroRedKit - BCI Adversarial Attack Module")
    print("=" * 50)
    
    # Create dummy model and data for testing
    class DummyEEGModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv = nn.Conv1d(8, 16, 3)
            self.fc = nn.Linear(16 * 100, 4)
        
        def forward(self, x):
            x = torch.relu(self.conv(x))
            x = x.view(x.size(0), -1)
            return self.fc(x)
    
    model = DummyEEGModel()
    eeg_signal = np.random.randn(8, 128).astype(np.float32)  # 8 channels, 128 time steps
    true_label = 0
    
    # Generate FGSM attack
    x_adv, pert_mag = create_eeg_adversarial_sample(
        eeg_signal, model, true_label, method="fgsm", epsilon=0.01
    )
    
    print(f"Original signal shape: {eeg_signal.shape}")
    print(f"Adversarial signal shape: {x_adv.shape}")
    print(f"Perturbation magnitude (L2): {pert_mag:.6f}")
    print(f"Max perturbation: {np.max(np.abs(x_adv - eeg_signal)):.6f}")
