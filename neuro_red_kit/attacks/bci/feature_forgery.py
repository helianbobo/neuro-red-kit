"""
Feature Forgery Attacks - BCI Layer Attack Module

This module implements feature forgery attacks that manipulate extracted EEG features
to deceive downstream classifiers or intent decoding systems.

Attack Types:
1. Power Spectral Density (PSD) Manipulation - Alter frequency band powers
2. Connectivity Feature Forgery - Fake functional connectivity patterns
3. Event-Related Potential (ERP) Synthesis - Generate fake ERP components
4. Microstate Sequence Manipulation - Alter EEG microstate sequences
5. Cross-Frequency Coupling (CFC) Forgery - Manipulate phase-amplitude coupling

Author: Sol (Clawdbot Research Agent)
Date: 2026-03-23
"""

import numpy as np
from scipy import signal
from scipy.fft import fft, ifft, fftfreq
from dataclasses import dataclass, field
from typing import Literal, Optional, Tuple, Dict, Any
from enum import Enum


class ForgeryType(Enum):
    """Types of feature forgery attacks."""
    PSD_MANIPULATION = "psd_manipulation"
    CONNECTIVITY_FORGERY = "connectivity_forgery"
    ERP_SYNTHESIS = "erp_synthesis"
    MICROSTATE_MANIPULATION = "microstate_manipulation"
    CROSS_FREQUENCY_COUPLING = "cross_frequency_coupling"
    HYBRID = "hybrid"


@dataclass
class ForgeryConfig:
    """Configuration for feature forgery attacks."""
    forgery_type: ForgeryType = ForgeryType.PSD_MANIPULATION
    severity: float = 0.5  # 0.0-1.0, intensity of forgery
    target_bands: Dict[str, float] = field(default_factory=lambda: {
        'delta': 1.0,   # 0.5-4 Hz
        'theta': 1.0,   # 4-8 Hz
        'alpha': 1.0,   # 8-13 Hz
        'beta': 1.0,    # 13-30 Hz
        'gamma': 1.0,   # 30-100 Hz
    })
    connectivity_pattern: Optional[np.ndarray] = None  # Target connectivity matrix
    erp_components: Dict[str, Tuple[float, float]] = field(default_factory=lambda: {
        # (latency_ms, amplitude_uv)
        'P100': (100, 5.0),
        'N170': (170, -3.0),
        'P300': (300, 8.0),
        'N400': (400, -4.0),
    })
    microstate_classes: int = 4  # Number of microstate classes (A, B, C, D)
    pac_frequency_band: Tuple[float, float] = (4, 8)  # Phase frequency (theta)
    pac_amplitude_band: Tuple[float, float] = (30, 50)  # Amplitude frequency (gamma)
    sampling_rate: float = 250.0  # Hz
    add_noise: bool = True
    noise_level: float = 0.1  # Standard deviation of added noise
    
    def validate(self) -> bool:
        """Validate configuration parameters."""
        if not 0.0 <= self.severity <= 1.0:
            return False
        if not all(0.0 <= v <= 2.0 for v in self.target_bands.values()):
            return False
        if self.sampling_rate <= 0:
            return False
        return True


class FeatureForgeryAttack:
    """
    Feature Forgery Attack Engine
    
    Manipulates extracted EEG features to deceive classifiers while maintaining
    superficial signal authenticity.
    """
    
    def __init__(self, config: ForgeryConfig):
        if not config.validate():
            raise ValueError("Invalid ForgeryConfig parameters")
        self.config = config
        self.sampling_rate = config.sampling_rate
        
    def attack(self, eeg_signal: np.ndarray, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Execute feature forgery attack on EEG signal.
        
        Args:
            eeg_signal: EEG signal array, shape (channels, samples) or (samples,)
            metadata: Optional metadata (channel_names, timestamps, etc.)
            
        Returns:
            Dictionary containing:
                - forged_signal: The manipulated EEG signal
                - forgery_type: Type of forgery applied
                - quality_metrics: Metrics comparing original vs forged
                - metadata: Attack metadata
        """
        # Ensure 2D array
        if eeg_signal.ndim == 1:
            eeg_signal = eeg_signal.reshape(1, -1)
        
        n_channels, n_samples = eeg_signal.shape
        
        # Apply forgery based on type
        if self.config.forgery_type == ForgeryType.PSD_MANIPULATION:
            forged_signal = self._psd_manipulation(eeg_signal)
        elif self.config.forgery_type == ForgeryType.CONNECTIVITY_FORGERY:
            forged_signal = self._connectivity_forgery(eeg_signal)
        elif self.config.forgery_type == ForgeryType.ERP_SYNTHESIS:
            forged_signal = self._erp_synthesis(eeg_signal)
        elif self.config.forgery_type == ForgeryType.MICROSTATE_MANIPULATION:
            forged_signal = self._microstate_manipulation(eeg_signal)
        elif self.config.forgery_type == ForgeryType.CROSS_FREQUENCY_COUPLING:
            forged_signal = self._cross_frequency_coupling(eeg_signal)
        elif self.config.forgery_type == ForgeryType.HYBRID:
            forged_signal = self._hybrid_forgery(eeg_signal)
        else:
            raise ValueError(f"Unknown forgery type: {self.config.forgery_type}")
        
        # Add noise if configured
        if self.config.add_noise:
            noise = np.random.normal(0, self.config.noise_level, forged_signal.shape)
            forged_signal = forged_signal + noise
        
        # Calculate quality metrics
        quality_metrics = self._calculate_quality_metrics(eeg_signal, forged_signal)
        
        return {
            'forged_signal': forged_signal,
            'forgery_type': self.config.forgery_type.value,
            'quality_metrics': quality_metrics,
            'metadata': {
                'severity': self.config.severity,
                'sampling_rate': self.sampling_rate,
                'n_channels': n_channels,
                'n_samples': n_samples,
                'attack_timestamp': self._get_timestamp(),
            }
        }
    
    def _psd_manipulation(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Manipulate Power Spectral Density (PSD) of EEG signal.
        
        Alters the power in specific frequency bands to mimic different
        cognitive states or evade detection.
        """
        n_channels, n_samples = eeg_signal.shape
        forged_signal = np.zeros_like(eeg_signal)
        
        # Frequency band definitions (Hz)
        bands = {
            'delta': (0.5, 4),
            'theta': (4, 8),
            'alpha': (8, 13),
            'beta': (13, 30),
            'gamma': (30, 100),
        }
        
        for ch in range(n_channels):
            # FFT of original signal
            fft_signal = fft(eeg_signal[ch])
            freqs = fftfreq(n_samples, 1/self.sampling_rate)
            
            # Apply band-specific scaling
            fft_forged = fft_signal.copy()
            for band_name, (low_freq, high_freq) in bands.items():
                scale_factor = self.config.target_bands.get(band_name, 1.0)
                # Interpolate scale factor based on severity
                scale_factor = 1.0 + (scale_factor - 1.0) * self.config.severity
                
                # Find frequency indices for this band
                band_mask = (np.abs(freqs) >= low_freq) & (np.abs(freqs) < high_freq)
                fft_forged[band_mask] *= scale_factor
            
            # Inverse FFT to get time-domain signal
            forged_signal[ch] = np.real(ifft(fft_forged))
        
        return forged_signal
    
    def _connectivity_forgery(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Forge functional connectivity patterns between channels.
        
        Manipulates phase relationships to create fake connectivity patterns
        that mimic specific brain states or pathologies.
        """
        n_channels, n_samples = eeg_signal.shape
        
        # If no target pattern specified, generate one based on severity
        if self.config.connectivity_pattern is None:
            # Create a synthetic connectivity matrix
            target_pattern = np.eye(n_channels) * 0.5
            for i in range(n_channels):
                for j in range(i+1, n_channels):
                    # Create some cross-channel correlation
                    conn_strength = 0.3 * self.config.severity
                    target_pattern[i, j] = conn_strength
                    target_pattern[j, i] = conn_strength
        else:
            target_pattern = self.config.connectivity_pattern
        
        forged_signal = np.zeros_like(eeg_signal)
        
        # Generate signals with target connectivity using Cholesky decomposition
        try:
            # Ensure positive semi-definite
            target_pattern = (target_pattern + target_pattern.T) / 2
            eigenvalues = np.linalg.eigvalsh(target_pattern)
            if np.min(eigenvalues) < 0:
                target_pattern += np.eye(n_channels) * (abs(np.min(eigenvalues)) + 0.01)
            
            L = np.linalg.cholesky(target_pattern)
            
            # Generate independent signals first
            for ch in range(n_channels):
                # Band-pass filter to add realistic structure
                forged_signal[ch] = self._bandpass_filter(eeg_signal[ch], 1, 50)
            
            # Mix signals according to connectivity pattern
            forged_signal = L @ forged_signal
            
        except np.linalg.LinAlgError:
            # Fallback: simple linear mixing
            for ch in range(n_channels):
                forged_signal[ch] = eeg_signal[ch] * (1 - self.config.severity)
                if ch > 0:
                    forged_signal[ch] += np.roll(eeg_signal[0], ch * 10) * self.config.severity
        
        return forged_signal
    
    def _erp_synthesis(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Synthesize fake Event-Related Potential (ERP) components.
        
        Adds synthetic ERP components (P300, N400, etc.) to the signal
        to trigger specific classifier responses.
        """
        n_channels, n_samples = eeg_signal.shape
        forged_signal = eeg_signal.copy()
        
        # Time axis in milliseconds
        time_ms = np.arange(n_samples) * (1000 / self.sampling_rate)
        
        # Add ERP components
        for component_name, (latency, amplitude) in self.config.erp_components.items():
            # Scale amplitude by severity
            amp_scaled = amplitude * self.config.severity
            
            # Create Gaussian ERP component
            # Width varies by component type
            if component_name.startswith('P'):
                width = 30  # Positive components are narrower
            else:
                width = 40  # Negative components are broader
            
            erp_wave = amp_scaled * np.exp(-((time_ms - latency) ** 2) / (2 * width ** 2))
            
            # Add to all channels (or could be topography-specific)
            for ch in range(n_channels):
                # Frontal channels get stronger ERP
                topography_factor = 1.0 - (ch / n_channels) * 0.3
                forged_signal[ch] += erp_wave * topography_factor
        
        return forged_signal
    
    def _microstate_manipulation(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Manipulate EEG microstate sequences.
        
        Alters the temporal sequence of EEG microstates to disrupt
        state classification or mimic different cognitive processes.
        """
        n_channels, n_samples = eeg_signal.shape
        forged_signal = np.zeros_like(eeg_signal)
        
        # Define canonical microstate topographies (simplified)
        # In practice, these would be derived from clustering
        n_microstates = min(self.config.microstate_classes, n_channels)
        microstate_maps = np.zeros((n_microstates, n_channels))
        
        for ms in range(n_microstates):
            # Create distinct topographic patterns
            for ch in range(n_channels):
                microstate_maps[ms, ch] = np.sin(2 * np.pi * (ms + 1) * ch / n_channels)
        
        # Segment signal into microstate-length windows (~80-120ms)
        window_size = int(0.1 * self.sampling_rate)  # 100ms windows
        n_windows = n_samples // window_size
        
        for ch in range(n_channels):
            for w in range(n_windows):
                start_idx = w * window_size
                end_idx = start_idx + window_size
                
                # Select microstate (possibly shuffled to disrupt sequence)
                ms_idx = w % n_microstates
                if self.config.severity > 0.5:
                    # Randomize microstate sequence
                    ms_idx = np.random.randint(0, n_microstates)
                
                # Scale original signal by microstate map
                scale = microstate_maps[ms_idx, ch]
                forged_signal[ch, start_idx:end_idx] = eeg_signal[ch, start_idx:end_idx] * (1 + scale * self.config.severity)
        
        return forged_signal
    
    def _cross_frequency_coupling(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Forge Cross-Frequency Coupling (CFC) patterns.
        
        Manipulates phase-amplitude coupling (PAC) between frequency bands
        to mimic specific brain states or pathologies.
        """
        n_channels, n_samples = eeg_signal.shape
        forged_signal = np.zeros_like(eeg_signal)
        
        phase_band = self.config.pac_frequency_band  # (low, high) for phase
        amp_band = self.config.pac_amplitude_band    # (low, high) for amplitude
        
        for ch in range(n_channels):
            # Extract phase from low-frequency band
            phase_signal = self._bandpass_filter(eeg_signal[ch], phase_band[0], phase_band[1])
            instantaneous_phase = np.angle(signal.hilbert(phase_signal))
            
            # Extract amplitude from high-frequency band
            amp_signal = self._bandpass_filter(eeg_signal[ch], amp_band[0], amp_band[1])
            instantaneous_amp = np.abs(signal.hilbert(amp_signal))
            
            # Modulate amplitude by phase (create PAC)
            pac_modulation = 1 + self.config.severity * np.sin(instantaneous_phase)
            modulated_amp = instantaneous_amp * pac_modulation
            
            # Reconstruct signal with modified PAC
            # Use original phase, modified amplitude
            analytic_original = signal.hilbert(eeg_signal[ch])
            original_phase = np.angle(analytic_original)
            original_amp = np.abs(analytic_original)
            
            # Blend original and modulated amplitude
            blended_amp = original_amp * (1 - self.config.severity) + modulated_amp * self.config.severity
            
            # Reconstruct
            forged_signal[ch] = np.real(blended_amp * np.exp(1j * original_phase))
        
        return forged_signal
    
    def _hybrid_forgery(self, eeg_signal: np.ndarray) -> np.ndarray:
        """
        Apply hybrid forgery combining multiple techniques.
        
        Sequentially applies PSD manipulation, ERP synthesis, and CFC forgery
        for maximum deception capability.
        """
        # Store original config
        original_severity = self.config.severity
        
        # Apply PSD manipulation (50% weight)
        self.config.severity = original_severity * 0.5
        forged = self._psd_manipulation(eeg_signal)
        
        # Apply ERP synthesis (30% weight)
        self.config.severity = original_severity * 0.3
        # Temporarily change forgery type
        original_type = self.config.forgery_type
        self.config.forgery_type = ForgeryType.ERP_SYNTHESIS
        forged = self._erp_synthesis(forged)
        
        # Apply CFC forgery (20% weight)
        self.config.severity = original_severity * 0.2
        self.config.forgery_type = ForgeryType.CROSS_FREQUENCY_COUPLING
        forged = self._cross_frequency_coupling(forged)
        
        # Restore original config
        self.config.severity = original_severity
        self.config.forgery_type = original_type
        
        return forged
    
    def _bandpass_filter(self, signal_data: np.ndarray, low_freq: float, high_freq: float) -> np.ndarray:
        """Apply bandpass filter to signal."""
        nyquist = self.sampling_rate / 2
        low = low_freq / nyquist
        high = high_freq / nyquist
        
        # Ensure frequencies are valid
        low = max(0.001, min(low, 0.999))
        high = max(low + 0.001, min(high, 0.999))
        
        try:
            b, a = signal.butter(4, [low, high], btype='band')
            return signal.filtfilt(b, a, signal_data)
        except Exception:
            return signal_data
    
    def _calculate_quality_metrics(self, original: np.ndarray, forged: np.ndarray) -> Dict[str, float]:
        """Calculate quality metrics comparing original and forged signals."""
        # Correlation
        correlation = np.corrcoef(original.flatten(), forged.flatten())[0, 1]
        
        # Mean Squared Error
        mse = np.mean((original - forged) ** 2)
        
        # Signal-to-Noise Ratio (treating difference as noise)
        signal_power = np.mean(original ** 2)
        noise_power = np.mean((original - forged) ** 2)
        snr_db = 10 * np.log10(signal_power / (noise_power + 1e-10))
        
        # Maximum absolute deviation
        max_deviation = np.max(np.abs(original - forged))
        
        # Spectral similarity (PSD correlation)
        psd_original = np.abs(fft(original)) ** 2
        psd_forged = np.abs(fft(forged)) ** 2
        spectral_corr = np.corrcoef(psd_original.flatten(), psd_forged.flatten())[0, 1]
        
        return {
            'correlation': float(correlation),
            'mse': float(mse),
            'snr_db': float(snr_db),
            'max_deviation': float(max_deviation),
            'spectral_correlation': float(spectral_corr),
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp string."""
        from datetime import datetime
        return datetime.now().isoformat()


def create_feature_forgery(
    eeg_signal: np.ndarray,
    forgery_type: str = "psd_manipulation",
    severity: float = 0.5,
    target_bands: Optional[Dict[str, float]] = None,
    sampling_rate: float = 250.0,
    **kwargs
) -> Dict[str, Any]:
    """
    Convenience function for creating feature forgery attacks.
    
    Args:
        eeg_signal: Input EEG signal (channels, samples) or (samples,)
        forgery_type: Type of forgery ("psd_manipulation", "connectivity_forgery", 
                     "erp_synthesis", "microstate_manipulation", "cross_frequency_coupling", "hybrid")
        severity: Attack intensity (0.0-1.0)
        target_bands: Dictionary mapping frequency bands to scaling factors
        sampling_rate: Sampling rate in Hz
        **kwargs: Additional ForgeryConfig parameters
        
    Returns:
        Dictionary with forged_signal, forgery_type, quality_metrics, and metadata
        
    Example:
        >>> import numpy as np
        >>> eeg = np.random.randn(8, 2500)  # 8 channels, 10 seconds at 250Hz
        >>> result = create_feature_forgery(
        ...     eeg,
        ...     forgery_type="erp_synthesis",
        ...     severity=0.7,
        ...     target_bands={'alpha': 1.5, 'beta': 0.5}
        ... )
        >>> forged_eeg = result['forged_signal']
        >>> print(f"Correlation: {result['quality_metrics']['correlation']:.3f}")
    """
    # Map string to enum
    type_mapping = {
        "psd_manipulation": ForgeryType.PSD_MANIPULATION,
        "connectivity_forgery": ForgeryType.CONNECTIVITY_FORGERY,
        "erp_synthesis": ForgeryType.ERP_SYNTHESIS,
        "microstate_manipulation": ForgeryType.MICROSTATE_MANIPULATION,
        "cross_frequency_coupling": ForgeryType.CROSS_FREQUENCY_COUPLING,
        "hybrid": ForgeryType.HYBRID,
    }
    
    if forgery_type not in type_mapping:
        raise ValueError(f"Unknown forgery type: {forgery_type}")
    
    config = ForgeryConfig(
        forgery_type=type_mapping[forgery_type],
        severity=severity,
        target_bands=target_bands or {},
        sampling_rate=sampling_rate,
        **kwargs
    )
    
    attacker = FeatureForgeryAttack(config)
    return attacker.attack(eeg_signal)


if __name__ == "__main__":
    # Demo: Feature Forgery Attack
    print("=" * 60)
    print("NeuroRedKit - Feature Forgery Attack Demo")
    print("=" * 60)
    
    # Generate synthetic EEG signal (8 channels, 10 seconds at 250Hz)
    np.random.seed(42)
    n_channels = 8
    duration_sec = 10
    sampling_rate = 250
    n_samples = duration_sec * sampling_rate
    
    # Create realistic synthetic EEG with multiple frequency components
    t = np.arange(n_samples) / sampling_rate
    eeg_signal = np.zeros((n_channels, n_samples))
    
    for ch in range(n_channels):
        # Add frequency band components with channel-specific weights
        eeg_signal[ch] += np.sin(2 * np.pi * 3 * t) * (1 - ch * 0.1)   # Delta
        eeg_signal[ch] += np.sin(2 * np.pi * 6 * t) * (1 - ch * 0.15)  # Theta
        eeg_signal[ch] += np.sin(2 * np.pi * 10 * t) * (1 - ch * 0.2)  # Alpha
        eeg_signal[ch] += np.sin(2 * np.pi * 20 * t) * (1 - ch * 0.25) # Beta
        eeg_signal[ch] += np.random.randn(n_samples) * 0.5             # Noise
    
    print(f"\nOriginal signal shape: {eeg_signal.shape}")
    print(f"Duration: {duration_sec}s, Sampling rate: {sampling_rate}Hz")
    
    # Test 1: PSD Manipulation
    print("\n" + "-" * 60)
    print("Test 1: PSD Manipulation (Alpha enhancement)")
    print("-" * 60)
    
    result = create_feature_forgery(
        eeg_signal,
        forgery_type="psd_manipulation",
        severity=0.7,
        target_bands={'alpha': 2.0, 'beta': 0.5},
        sampling_rate=sampling_rate
    )
    
    metrics = result['quality_metrics']
    print(f"Correlation: {metrics['correlation']:.3f}")
    print(f"SNR: {metrics['snr_db']:.1f} dB")
    print(f"Spectral Correlation: {metrics['spectral_correlation']:.3f}")
    
    # Test 2: ERP Synthesis
    print("\n" + "-" * 60)
    print("Test 2: ERP Synthesis (P300 injection)")
    print("-" * 60)
    
    result = create_feature_forgery(
        eeg_signal,
        forgery_type="erp_synthesis",
        severity=0.8,
        sampling_rate=sampling_rate,
        erp_components={'P300': (300, 10.0), 'N400': (400, -5.0)}
    )
    
    metrics = result['quality_metrics']
    print(f"Correlation: {metrics['correlation']:.3f}")
    print(f"SNR: {metrics['snr_db']:.1f} dB")
    print(f"Max Deviation: {metrics['max_deviation']:.2f} μV")
    
    # Test 3: Cross-Frequency Coupling
    print("\n" + "-" * 60)
    print("Test 3: Cross-Frequency Coupling (Theta-Gamma PAC)")
    print("-" * 60)
    
    result = create_feature_forgery(
        eeg_signal,
        forgery_type="cross_frequency_coupling",
        severity=0.6,
        sampling_rate=sampling_rate,
        pac_frequency_band=(4, 8),
        pac_amplitude_band=(30, 50)
    )
    
    metrics = result['quality_metrics']
    print(f"Correlation: {metrics['correlation']:.3f}")
    print(f"SNR: {metrics['snr_db']:.1f} dB")
    print(f"Spectral Correlation: {metrics['spectral_correlation']:.3f}")
    
    # Test 4: Hybrid Forgery
    print("\n" + "-" * 60)
    print("Test 4: Hybrid Forgery (Combined attack)")
    print("-" * 60)
    
    result = create_feature_forgery(
        eeg_signal,
        forgery_type="hybrid",
        severity=0.5,
        sampling_rate=sampling_rate
    )
    
    metrics = result['quality_metrics']
    print(f"Correlation: {metrics['correlation']:.3f}")
    print(f"SNR: {metrics['snr_db']:.1f} dB")
    print(f"Max Deviation: {metrics['max_deviation']:.2f} μV")
    
    print("\n" + "=" * 60)
    print("Feature Forgery Demo Complete!")
    print("=" * 60)
