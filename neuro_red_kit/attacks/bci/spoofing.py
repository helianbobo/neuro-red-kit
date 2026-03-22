"""
BCI Sensor Spoofing Attack Module

This module implements sensor-level spoofing attacks that manipulate or fake
EEG sensor readings to deceive BCI systems.

Attack Types:
1. Electrode Displacement Spoofing - Simulate poor electrode contact
2. Impedance Manipulation - Fake impedance readings to bypass quality checks
3. Channel Swap Attack - Swap channel mappings to corrupt spatial information
4. Ghost Electrode Attack - Inject fake channels that don't exist
5. Sensor Calibration Attack - Manipulate calibration parameters

Author: Sol (OpenClaw)
Date: 2026-03-23
"""

import numpy as np
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum


class SpoofingMode(Enum):
    """Sensor spoofing attack modes."""
    ELECTRODE_DISPLACEMENT = "electrode_displacement"
    IMPEDANCE_MANIPULATION = "impedance_manipulation"
    CHANNEL_SWAP = "channel_swap"
    GHOST_ELECTRODE = "ghost_electrode"
    CALIBRATION_ATTACK = "calibration_attack"
    HYBRID = "hybrid"


@dataclass
class SpoofingConfig:
    """Configuration for sensor spoofing attacks."""
    mode: SpoofingMode = SpoofingMode.ELECTRODE_DISPLACEMENT
    seed: Optional[int] = None
    severity: float = 0.5  # 0.0-1.0, attack intensity
    
    # Electrode displacement parameters
    displacement_mm: float = 5.0  # mm of simulated displacement
    affected_channels: Optional[List[int]] = None
    
    # Impedance manipulation parameters
    target_impedance_ohm: float = 50000  # Target fake impedance (Ω)
    impedance_variance: float = 0.1  # Variance in impedance readings
    
    # Channel swap parameters
    swap_pairs: Optional[List[Tuple[int, int]]] = None
    
    # Ghost electrode parameters
    ghost_channels: int = 2  # Number of fake channels to add
    ghost_signal_type: str = "alpha"  # Type of signal for ghost channels
    
    # Calibration attack parameters
    gain_offset: float = 1.5  # Gain multiplier
    baseline_shift_uv: float = 50.0  # Baseline shift in microvolts


@dataclass
class SpoofingResult:
    """Result of a sensor spoofing attack."""
    success: bool
    mode: SpoofingMode
    original_signal: np.ndarray
    spoofed_signal: np.ndarray
    metadata: Dict = field(default_factory=dict)
    
    def quality_metrics(self) -> Dict[str, float]:
        """Calculate quality metrics for the spoofing attack."""
        if self.original_signal.shape != self.spoofed_signal.shape:
            return {"error": "Shape mismatch"}
        
        # Correlation between original and spoofed
        if self.original_signal.size > 1:
            correlation = np.corrcoef(
                self.original_signal.flatten(),
                self.spoofed_signal.flatten()
            )[0, 1]
        else:
            correlation = 1.0
        
        # Signal-to-spoof ratio
        signal_power = np.mean(self.original_signal ** 2)
        spoof_power = np.mean((self.spoofed_signal - self.original_signal) ** 2)
        ssr = 10 * np.log10(signal_power / (spoof_power + 1e-10))
        
        return {
            "correlation": float(correlation),
            "signal_to_spoof_ratio_db": float(ssr),
            "mean_absolute_error": float(np.mean(np.abs(self.spoofed_signal - self.original_signal))),
            "max_deviation_uv": float(np.max(np.abs(self.spoofed_signal - self.original_signal))),
        }


class SensorSpoofingAttack:
    """
    BCI Sensor Spoofing Attack Engine
    
    Implements various sensor-level spoofing techniques to manipulate
    EEG signal acquisition at the hardware/sensor level.
    """
    
    # Standard 10-20 EEG channel names
    STANDARD_CHANNELS = [
        "Fz", "Cz", "Pz", "F3", "F4", "C3", "C4", "P3", "P4",
        "F7", "F8", "T3", "T4", "T5", "T6", "O1", "O2"
    ]
    
    def __init__(self, config: Optional[SpoofingConfig] = None):
        self.config = config or SpoofingConfig()
        if self.config.seed is not None:
            np.random.seed(self.config.seed)
    
    def attack(self, eeg_signal: np.ndarray, 
               impedance: Optional[np.ndarray] = None,
               channel_names: Optional[List[str]] = None) -> SpoofingResult:
        """
        Execute sensor spoofing attack.
        
        Args:
            eeg_signal: EEG signal array, shape (channels, samples) or (samples,)
            impedance: Optional impedance readings per channel (Ω)
            channel_names: Optional channel names
            
        Returns:
            SpoofingResult with spoofed signal and metadata
        """
        # Normalize input
        if eeg_signal.ndim == 1:
            eeg_signal = eeg_signal.reshape(1, -1)
        
        n_channels, n_samples = eeg_signal.shape
        
        if channel_names is None:
            channel_names = self.STANDARD_CHANNELS[:n_channels]
        
        # Select attack mode
        if self.config.mode == SpoofingMode.ELECTRODE_DISPLACEMENT:
            spoofed = self._electrode_displacement(eeg_signal)
        elif self.config.mode == SpoofingMode.IMPEDANCE_MANIPULATION:
            spoofed = self._impedance_manipulation(eeg_signal, impedance)
        elif self.config.mode == SpoofingMode.CHANNEL_SWAP:
            spoofed = self._channel_swap(eeg_signal)
        elif self.config.mode == SpoofingMode.GHOST_ELECTRODE:
            spoofed = self._ghost_electrode(eeg_signal)
        elif self.config.mode == SpoofingMode.CALIBRATION_ATTACK:
            spoofed = self._calibration_attack(eeg_signal)
        elif self.config.mode == SpoofingMode.HYBRID:
            spoofed = self._hybrid_attack(eeg_signal, impedance)
        else:
            raise ValueError(f"Unknown spoofing mode: {self.config.mode}")
        
        # Build metadata
        metadata = {
            "mode": self.config.mode.value,
            "severity": self.config.severity,
            "n_channels": n_channels,
            "n_samples": n_samples,
            "channel_names": channel_names,
        }
        
        if impedance is not None:
            metadata["original_impedance"] = impedance.tolist()
        
        return SpoofingResult(
            success=True,
            mode=self.config.mode,
            original_signal=eeg_signal.copy(),
            spoofed_signal=spoofed,
            metadata=metadata
        )
    
    def _electrode_displacement(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Simulate electrode displacement effects.
        
        When electrodes are displaced from their standard 10-20 positions,
        the recorded signal changes due to different underlying neural sources.
        This attack simulates such displacement by:
        1. Adding channel-specific noise
        2. Applying spatial blurring
        3. Simulating signal attenuation
        """
        n_channels, n_samples = eeg_signal.shape
        spoofed = eeg_signal.copy()
        
        # Determine affected channels
        if self.config.affected_channels:
            affected = self.config.affected_channels
        else:
            # Randomly select channels based on severity
            n_affected = max(1, int(n_channels * self.config.severity))
            affected = np.random.choice(n_channels, n_affected, replace=False).tolist()
        
        # Apply displacement effects to affected channels
        for ch in affected:
            # 1. Signal attenuation (displaced electrodes have weaker signal)
            attenuation = 1.0 - (0.3 * self.config.severity)
            spoofed[ch] *= attenuation
            
            # 2. Add displacement noise (movement artifacts)
            noise_std = np.std(spoofed[ch]) * self.config.severity * 0.5
            displacement_noise = np.random.normal(0, noise_std, n_samples)
            spoofed[ch] += displacement_noise
            
            # 3. Simulate spatial blurring (low-pass filter effect)
            if self.config.displacement_mm > 0:
                # Simple moving average to simulate blurring
                window_size = int(self.config.displacement_mm / 2) + 1
                if window_size > 1:
                    kernel = np.ones(window_size) / window_size
                    spoofed[ch] = np.convolve(spoofed[ch], kernel, mode='same')
        
        return spoofed
    
    def _impedance_manipulation(self, eeg_signal: np.ndarray,
                                impedance: Optional[np.ndarray] = None) -> np.ndarray:
        """
        Manipulate impedance readings to bypass quality checks.
        
        High impedance (>50kΩ) indicates poor electrode contact.
        This attack fakes impedance readings to make poor signals appear valid.
        """
        n_channels, n_samples = eeg_signal.shape
        spoofed = eeg_signal.copy()
        
        # Generate fake impedance readings
        if impedance is None:
            impedance = np.ones(n_channels) * 10000  # Assume good contact
        
        # Manipulate impedance to appear within acceptable range
        fake_impedance = np.ones(n_channels) * self.config.target_impedance_ohm
        
        # Add variance to look realistic
        variance = fake_impedance * self.config.impedance_variance
        fake_impedance += np.random.normal(0, variance)
        fake_impedance = np.clip(fake_impedance, 1000, 100000)  # Realistic range
        
        # If actual impedance is high, add noise to simulate poor contact
        high_impedance_mask = impedance > 50000
        if np.any(high_impedance_mask):
            for ch in np.where(high_impedance_mask)[0]:
                # Add high-frequency noise typical of poor contact
                noise_std = np.std(spoofed[ch]) * self.config.severity
                hf_noise = np.random.normal(0, noise_std, n_samples)
                spoofed[ch] += hf_noise
        
        # Store fake impedance in metadata (would be returned to BCI system)
        self._fake_impedance = fake_impedance
        
        return spoofed
    
    def _channel_swap(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Swap channel mappings to corrupt spatial information.
        
        Many BCI systems rely on spatial patterns (e.g., motor imagery).
        Swapping channels disrupts these patterns while maintaining signal quality.
        """
        n_channels, _ = eeg_signal.shape
        spoofed = eeg_signal.copy()
        
        if self.config.swap_pairs:
            swap_pairs = self.config.swap_pairs
        else:
            # Generate random swap pairs based on severity
            n_swaps = max(1, int(n_channels * self.config.severity / 2))
            available = list(range(n_channels))
            swap_pairs = []
            for _ in range(n_swaps):
                if len(available) < 2:
                    break
                ch1 = np.random.choice(available)
                available.remove(ch1)
                ch2 = np.random.choice(available)
                available.remove(ch2)
                swap_pairs.append((ch1, ch2))
        
        # Execute swaps
        for ch1, ch2 in swap_pairs:
            if ch1 < n_channels and ch2 < n_channels:
                spoofed[[ch1, ch2]] = spoofed[[ch2, ch1]]
        
        return spoofed
    
    def _ghost_electrode(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Inject fake "ghost" electrode channels.
        
        Adds synthetic channels that appear to be real EEG recordings,
        potentially confusing source localization or spatial filtering.
        """
        n_channels, n_samples = eeg_signal.shape
        n_ghost = self.config.ghost_channels
        
        # Start with copy of original signal
        spoofed = eeg_signal.copy()
        
        # Generate ghost signals based on specified type
        ghost_signals = []
        for i in range(n_ghost):
            if self.config.ghost_signal_type == "alpha":
                # 8-13 Hz alpha rhythm
                freq = np.random.uniform(8, 13)
            elif self.config.ghost_signal_type == "beta":
                # 13-30 Hz beta rhythm
                freq = np.random.uniform(13, 30)
            elif self.config.ghost_signal_type == "theta":
                # 4-8 Hz theta rhythm
                freq = np.random.uniform(4, 8)
            elif self.config.ghost_signal_type == "noise":
                # Pure noise
                ghost = np.random.normal(0, 10, n_samples)
                ghost_signals.append(ghost)
                continue
            else:
                freq = 10  # Default alpha
            
            # Generate sinusoidal signal with realistic EEG characteristics
            t = np.arange(n_samples) / 250  # Assume 250 Hz sampling
            ghost = 20 * np.sin(2 * np.pi * freq * t)  # 20 μV amplitude
            
            # Add realistic noise
            noise = np.random.normal(0, 5, n_samples)
            ghost += noise
            
            # Apply 1/f power spectrum characteristic of EEG
            ghost = self._apply_one_over_f(ghost)
            
            ghost_signals.append(ghost)
        
        # Concatenate ghost channels
        ghost_array = np.array(ghost_signals)
        spoofed = np.vstack([spoofed, ghost_array])
        
        return spoofed
    
    def _calibration_attack(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Manipulate calibration parameters.
        
        BCI systems calibrate gain and baseline for each channel.
        This attack corrupts these parameters to distort signals.
        """
        n_channels, n_samples = eeg_signal.shape
        spoofed = eeg_signal.copy()
        
        # Apply gain offset
        gain = 1.0 + (self.config.gain_offset - 1.0) * self.config.severity
        spoofed *= gain
        
        # Apply baseline shift
        for ch in range(n_channels):
            shift = np.random.normal(
                self.config.baseline_shift_uv * self.config.severity,
                5.0
            )
            spoofed[ch] += shift
        
        return spoofed
    
    def _hybrid_attack(self, eeg_signal: np.ndarray,
                       impedance: Optional[np.ndarray] = None) -> np.ndarray:
        """
        Combine multiple spoofing techniques.
        
        Executes a sequence of attacks for maximum effectiveness.
        """
        # Start with electrode displacement
        self.config.mode = SpoofingMode.ELECTRODE_DISPLACEMENT
        spoofed = self._electrode_displacement(eeg_signal)
        
        # Add calibration attack
        self.config.mode = SpoofingMode.CALIBRATION_ATTACK
        spoofed = self._calibration_attack(spoofed)
        
        # Add impedance manipulation
        if impedance is not None or np.random.random() < 0.5:
            self.config.mode = SpoofingMode.IMPEDANCE_MANIPULATION
            spoofed = self._impedance_manipulation(spoofed, impedance)
        
        return spoofed
    
    def _apply_one_over_f(self, signal: np.ndarray) -> np.ndarray:
        """Apply 1/f power spectrum characteristic of EEG signals."""
        # FFT
        fft_signal = np.fft.rfft(signal)
        freqs = np.fft.rfftfreq(len(signal))
        
        # Apply 1/f filter (avoid division by zero)
        with np.errstate(divide='ignore', invalid='ignore'):
            filter_response = 1.0 / np.sqrt(freqs + 0.1)
        filter_response[0] = 0  # Remove DC component
        
        # Apply filter
        fft_filtered = fft_signal * filter_response
        
        # Inverse FFT
        return np.fft.irfft(fft_filtered, len(signal))
    
    def get_fake_impedance(self) -> Optional[np.ndarray]:
        """Get the fake impedance readings from last attack."""
        return getattr(self, '_fake_impedance', None)


def create_sensor_spoofing(eeg_signal: np.ndarray,
                          mode: str = "electrode_displacement",
                          severity: float = 0.5,
                          **kwargs) -> SpoofingResult:
    """
    Convenience function for creating sensor spoofing attacks.
    
    Args:
        eeg_signal: EEG signal array
        mode: Spoofing mode ("electrode_displacement", "impedance", 
              "channel_swap", "ghost_electrode", "calibration", "hybrid")
        severity: Attack severity (0.0-1.0)
        **kwargs: Additional config parameters
        
    Returns:
        SpoofingResult with spoofed signal
    """
    mode_map = {
        "electrode_displacement": SpoofingMode.ELECTRODE_DISPLACEMENT,
        "impedance": SpoofingMode.IMPEDANCE_MANIPULATION,
        "channel_swap": SpoofingMode.CHANNEL_SWAP,
        "ghost_electrode": SpoofingMode.GHOST_ELECTRODE,
        "calibration": SpoofingMode.CALIBRATION_ATTACK,
        "hybrid": SpoofingMode.HYBRID,
    }
    
    config = SpoofingConfig(
        mode=mode_map.get(mode, SpoofingMode.ELECTRODE_DISPLACEMENT),
        severity=severity,
        **kwargs
    )
    
    attacker = SensorSpoofingAttack(config)
    return attacker.attack(eeg_signal)


# Example usage and testing
if __name__ == "__main__":
    # Test electrode displacement attack
    print("Testing Sensor Spoofing Attack Module")
    print("=" * 50)
    
    # Generate synthetic EEG signal (8 channels, 10 seconds at 250 Hz)
    n_channels = 8
    n_samples = 2500
    t = np.arange(n_samples) / 250
    
    eeg_signal = np.zeros((n_channels, n_samples))
    for ch in range(n_channels):
        # Mix of alpha, beta, theta rhythms
        alpha = 20 * np.sin(2 * np.pi * 10 * t + ch * 0.1)
        beta = 10 * np.sin(2 * np.pi * 20 * t + ch * 0.2)
        theta = 15 * np.sin(2 * np.pi * 6 * t + ch * 0.3)
        noise = np.random.normal(0, 5, n_samples)
        eeg_signal[ch] = alpha + beta + theta + noise
    
    # Test 1: Electrode displacement
    print("\n1. Electrode Displacement Attack")
    result = create_sensor_spoofing(eeg_signal, mode="electrode_displacement", severity=0.7)
    metrics = result.quality_metrics()
    print(f"   Correlation: {metrics['correlation']:.3f}")
    print(f"   SSR (dB): {metrics['signal_to_spoof_ratio_db']:.1f}")
    print(f"   MAE (μV): {metrics['mean_absolute_error']:.2f}")
    
    # Test 2: Channel swap
    print("\n2. Channel Swap Attack")
    result = create_sensor_spoofing(eeg_signal, mode="channel_swap", severity=0.5)
    metrics = result.quality_metrics()
    print(f"   Correlation: {metrics['correlation']:.3f}")
    print(f"   Channels swapped: {result.metadata.get('n_channels', 'N/A')}")
    
    # Test 3: Ghost electrode
    print("\n3. Ghost Electrode Attack")
    result = create_sensor_spoofing(eeg_signal, mode="ghost_electrode", ghost_channels=2)
    print(f"   Original channels: {n_channels}")
    print(f"   Spoofed channels: {result.spoofed_signal.shape[0]}")
    print(f"   Ghost signal type: alpha")
    
    # Test 4: Hybrid attack
    print("\n4. Hybrid Attack (Multiple Techniques)")
    result = create_sensor_spoofing(eeg_signal, mode="hybrid", severity=0.6)
    metrics = result.quality_metrics()
    print(f"   Correlation: {metrics['correlation']:.3f}")
    print(f"   SSR (dB): {metrics['signal_to_spoof_ratio_db']:.1f}")
    
    print("\n✅ All tests completed successfully!")
