"""
BCI Layer Replay Attack Module

Implements EEG signal replay attacks for BCI systems.
Replay attacks involve recording legitimate EEG signals and replaying them
to impersonate a user or trigger specific commands without the user's intent.

References:
- Campisi et al. (2018). "Vulnerabilities of EEG-based Biometric Systems"
- Maiorana et al. (2020). "Replay Attacks on EEG Biometric Systems"
"""

import numpy as np
from typing import Optional, Tuple, Dict, List
from pathlib import Path
import json
import hashlib
from datetime import datetime


class ReplayAttackBCI:
    """
    EEG Signal Replay Attack Generator.
    
    This class implements various replay attack strategies:
    - Direct replay: Replay recorded EEG signals as-is
    - Time-stretched replay: Modify playback speed to evade detection
    - Segmented replay: Replay signal fragments in sequence
    - Hybrid replay: Combine multiple recorded signals
    
    Security Note: This module is for RED TEAM / SECURITY RESEARCH only.
    """
    
    def __init__(
        self,
        sampling_rate: float = 250.0,
        channel_names: Optional[List[str]] = None
    ):
        """
        Initialize replay attack generator.
        
        Args:
            sampling_rate: EEG sampling rate in Hz (default: 250Hz for OpenBCI Cyton)
            channel_names: List of EEG channel names (e.g., ['Fz', 'Cz', 'Pz', ...])
        """
        self.sampling_rate = sampling_rate
        self.channel_names = channel_names or []
        self.recorded_signals: Dict[str, np.ndarray] = {}
        self.metadata: Dict[str, dict] = {}
    
    def record_signal(
        self,
        signal: np.ndarray,
        label: str,
        user_id: Optional[str] = None,
        task_context: Optional[str] = None,
        save_path: Optional[Path] = None
    ) -> str:
        """
        Record/store an EEG signal for later replay.
        
        Args:
            signal: EEG signal array [channels, time_steps]
            label: Unique label for this signal (e.g., 'user1_left_hand')
            user_id: Optional user identifier
            task_context: Optional context (e.g., 'motor_imagery_left')
            save_path: Optional path to save signal to disk
            
        Returns:
            Signal hash (unique identifier)
        """
        # Compute hash for deduplication and integrity
        signal_hash = hashlib.sha256(signal.tobytes()).hexdigest()[:16]
        
        # Store in memory
        self.recorded_signals[label] = signal.copy()
        self.metadata[label] = {
            'hash': signal_hash,
            'user_id': user_id,
            'task_context': task_context,
            'recorded_at': datetime.now().isoformat(),
            'shape': signal.shape,
            'duration_sec': signal.shape[1] / self.sampling_rate if len(signal.shape) > 1 else 0
        }
        
        # Optionally save to disk
        if save_path:
            save_path = Path(save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            np.save(save_path / f"{label}.npy", signal)
            
            # Save metadata
            meta_path = save_path / f"{label}.meta.json"
            with open(meta_path, 'w') as f:
                json.dump(self.metadata[label], f, indent=2)
        
        return signal_hash
    
    def load_signal(self, path: Path, label: str) -> np.ndarray:
        """
        Load a previously recorded signal from disk.
        
        Args:
            path: Directory containing saved signals
            label: Signal label to load
            
        Returns:
            Loaded EEG signal array
        """
        path = Path(path)
        signal_path = path / f"{label}.npy"
        meta_path = path / f"{label}.meta.json"
        
        if not signal_path.exists():
            raise FileNotFoundError(f"Signal file not found: {signal_path}")
        
        signal = np.load(signal_path)
        
        # Load metadata if available
        if meta_path.exists():
            with open(meta_path, 'r') as f:
                self.metadata[label] = json.load(f)
        
        self.recorded_signals[label] = signal
        return signal
    
    def direct_replay(self, label: str) -> Tuple[np.ndarray, dict]:
        """
        Direct replay attack - replay signal as-is.
        
        Args:
            label: Label of recorded signal to replay
            
        Returns:
            Tuple of (replayed_signal, attack_metadata)
        """
        if label not in self.recorded_signals:
            raise ValueError(f"Signal '{label}' not found in recorded signals")
        
        signal = self.recorded_signals[label].copy()
        
        metadata = {
            'attack_type': 'direct_replay',
            'source_label': label,
            'original_duration': self.metadata[label]['duration_sec'],
            'replay_duration': self.metadata[label]['duration_sec'],
            'time_stretch_factor': 1.0,
            'detection_risk': 'HIGH'  # Direct replay is easily detectable
        }
        
        return signal, metadata
    
    def time_stretched_replay(
        self,
        label: str,
        stretch_factor: float = 1.0
    ) -> Tuple[np.ndarray, dict]:
        """
        Time-stretched replay - modify playback speed to evade detection.
        
        Args:
            label: Label of recorded signal to replay
            stretch_factor: Time stretch factor (>1 = slower, <1 = faster)
            
        Returns:
            Tuple of (stretched_signal, attack_metadata)
        """
        if label not in self.recorded_signals:
            raise ValueError(f"Signal '{label}' not found")
        
        signal = self.recorded_signals[label]
        
        # Resample signal
        original_length = signal.shape[1]
        new_length = int(original_length / stretch_factor)
        
        # Use linear interpolation for resampling
        time_original = np.linspace(0, 1, original_length)
        time_new = np.linspace(0, 1, new_length)
        
        stretched_signal = np.zeros((signal.shape[0], new_length))
        for ch in range(signal.shape[0]):
            stretched_signal[ch] = np.interp(time_new, time_original, signal[ch])
        
        metadata = {
            'attack_type': 'time_stretched_replay',
            'source_label': label,
            'original_duration': self.metadata[label]['duration_sec'],
            'replay_duration': self.metadata[label]['duration_sec'] * stretch_factor,
            'time_stretch_factor': stretch_factor,
            'detection_risk': 'MEDIUM' if 0.8 <= stretch_factor <= 1.2 else 'LOW'
        }
        
        return stretched_signal, metadata
    
    def segmented_replay(
        self,
        label: str,
        segment_duration: float = 1.0,
        overlap: float = 0.0
    ) -> Tuple[List[np.ndarray], dict]:
        """
        Segmented replay - replay signal in fragments to evade detection.
        
        Args:
            label: Label of recorded signal to replay
            segment_duration: Duration of each segment in seconds
            overlap: Overlap between segments (0.0 to 1.0)
            
        Returns:
            Tuple of (list_of_segments, attack_metadata)
        """
        if label not in self.recorded_signals:
            raise ValueError(f"Signal '{label}' not found")
        
        signal = self.recorded_signals[label]
        samples_per_segment = int(segment_duration * self.sampling_rate)
        overlap_samples = int(samples_per_segment * overlap)
        step_size = samples_per_segment - overlap_samples
        
        segments = []
        start_idx = 0
        
        while start_idx < signal.shape[1]:
            end_idx = min(start_idx + samples_per_segment, signal.shape[1])
            segment = signal[:, start_idx:end_idx]
            
            # Pad if last segment is too short
            if segment.shape[1] < samples_per_segment:
                padding = np.zeros((segment.shape[0], samples_per_segment - segment.shape[1]))
                segment = np.hstack([segment, padding])
            
            segments.append(segment)
            start_idx += step_size
        
        metadata = {
            'attack_type': 'segmented_replay',
            'source_label': label,
            'num_segments': len(segments),
            'segment_duration_sec': segment_duration,
            'overlap_ratio': overlap,
            'detection_risk': 'MEDIUM'
        }
        
        return segments, metadata
    
    def hybrid_replay(
        self,
        labels: List[str],
        weights: Optional[List[float]] = None
    ) -> Tuple[np.ndarray, dict]:
        """
        Hybrid replay - combine multiple recorded signals.
        
        Args:
            labels: List of signal labels to combine
            weights: Optional weights for each signal (default: equal)
            
        Returns:
            Tuple of (combined_signal, attack_metadata)
        """
        if len(labels) == 0:
            raise ValueError("At least one label required")
        
        for label in labels:
            if label not in self.recorded_signals:
                raise ValueError(f"Signal '{label}' not found")
        
        # Default to equal weights
        if weights is None:
            weights = [1.0 / len(labels)] * len(labels)
        else:
            # Normalize weights
            total = sum(weights)
            weights = [w / total for w in weights]
        
        # Ensure all signals have same shape
        target_shape = self.recorded_signals[labels[0]].shape
        signals_aligned = []
        
        for label in labels:
            sig = self.recorded_signals[label]
            if sig.shape != target_shape:
                # Truncate or pad to match
                if sig.shape[1] > target_shape[1]:
                    sig = sig[:, :target_shape[1]]
                else:
                    padding = np.zeros((sig.shape[0], target_shape[1] - sig.shape[1]))
                    sig = np.hstack([sig, padding])
            signals_aligned.append(sig)
        
        # Weighted combination
        combined = np.zeros(target_shape)
        for sig, weight in zip(signals_aligned, weights):
            combined += weight * sig
        
        metadata = {
            'attack_type': 'hybrid_replay',
            'source_labels': labels,
            'weights': weights,
            'combined_shape': combined.shape,
            'detection_risk': 'LOW'  # Hybrid signals are harder to detect
        }
        
        return combined, metadata
    
    def add_noise(
        self,
        signal: np.ndarray,
        noise_level: float = 0.01,
        noise_type: str = 'gaussian'
    ) -> np.ndarray:
        """
        Add noise to signal to evade detection.
        
        Args:
            signal: Input signal
            noise_level: Standard deviation of noise relative to signal
            noise_type: Type of noise ('gaussian', 'uniform', 'pink')
            
        Returns:
            Noisy signal
        """
        signal_power = np.std(signal)
        
        if noise_type == 'gaussian':
            noise = np.random.randn(*signal.shape) * noise_level * signal_power
        elif noise_type == 'uniform':
            noise = np.random.uniform(-1, 1, signal.shape) * noise_level * signal_power
        elif noise_type == 'pink':
            # Approximate pink noise (1/f noise)
            white = np.random.randn(*signal.shape)
            noise = np.zeros_like(signal)
            for ch in range(signal.shape[0]):
                # Simple 1/f approximation via cumulative sum
                noise[ch] = np.cumsum(white[ch]) / np.sqrt(signal.shape[1])
            noise *= noise_level * signal_power / (np.std(noise) + 1e-10)
        else:
            raise ValueError(f"Unknown noise type: {noise_type}")
        
        return signal + noise
    
    def evaluate_replay_success(
        self,
        original_signal: np.ndarray,
        replayed_signal: np.ndarray,
        threshold: float = 0.8
    ) -> Dict[str, float]:
        """
        Evaluate similarity between original and replayed signals.
        
        Args:
            original_signal: Original EEG signal
            replayed_signal: Replayed (possibly modified) signal
            threshold: Similarity threshold for "successful" replay
            
        Returns:
            Dictionary of similarity metrics
        """
        # Ensure same shape
        min_len = min(original_signal.shape[1], replayed_signal.shape[1])
        orig = original_signal[:, :min_len]
        repl = replayed_signal[:, :min_len]
        
        # Correlation coefficient (per channel, then average)
        correlations = []
        for ch in range(orig.shape[0]):
            if np.std(orig[ch]) > 1e-10 and np.std(repl[ch]) > 1e-10:
                corr = np.corrcoef(orig[ch], repl[ch])[0, 1]
                correlations.append(corr)
        avg_correlation = np.mean(correlations) if correlations else 0.0
        
        # Mean Squared Error (normalized)
        mse = np.mean((orig - repl) ** 2)
        nmse = mse / (np.var(orig) + 1e-10)
        
        # Signal-to-Noise Ratio
        signal_power = np.mean(orig ** 2)
        noise_power = np.mean((orig - repl) ** 2)
        snr_db = 10 * np.log10(signal_power / (noise_power + 1e-10))
        
        # Overall similarity score
        similarity_score = (avg_correlation + 1) / 2  # Map [-1, 1] to [0, 1]
        success = similarity_score >= threshold
        
        return {
            'correlation': float(avg_correlation),
            'nmse': float(nmse),
            'snr_db': float(snr_db),
            'similarity_score': float(similarity_score),
            'success': bool(success),
            'threshold': threshold
        }


def create_replay_attack(
    recorded_signal: np.ndarray,
    attack_type: str = 'direct',
    sampling_rate: float = 250.0,
    **kwargs
) -> Tuple[np.ndarray, dict]:
    """
    Convenience function to create replay attack.
    
    Args:
        recorded_signal: Recorded EEG signal to replay
        attack_type: Type of replay ('direct', 'stretched', 'segmented', 'hybrid')
        sampling_rate: EEG sampling rate in Hz
        **kwargs: Additional arguments for specific attack types
        
    Returns:
        Tuple of (replayed_signal, attack_metadata)
    """
    attacker = ReplayAttackBCI(sampling_rate=sampling_rate)
    
    # Record the signal
    attacker.record_signal(recorded_signal, label='target_signal')
    
    # Execute attack
    if attack_type == 'direct':
        return attacker.direct_replay('target_signal')
    elif attack_type == 'stretched':
        stretch_factor = kwargs.get('stretch_factor', 1.0)
        return attacker.time_stretched_replay('target_signal', stretch_factor)
    elif attack_type == 'segmented':
        segment_duration = kwargs.get('segment_duration', 1.0)
        overlap = kwargs.get('overlap', 0.0)
        return attacker.segmented_replay('target_signal', segment_duration, overlap)
    elif attack_type == 'hybrid':
        # For hybrid, we need multiple signals
        raise ValueError("Hybrid attack requires multiple signals - use ReplayAttackBCI class directly")
    else:
        raise ValueError(f"Unknown attack type: {attack_type}")


if __name__ == "__main__":
    # Example usage
    print("NeuroRedKit - BCI Replay Attack Module")
    print("=" * 50)
    
    # Create dummy EEG signal (8 channels, 5 seconds at 250Hz)
    sampling_rate = 250.0
    duration_sec = 5.0
    n_channels = 8
    n_samples = int(sampling_rate * duration_sec)
    
    # Simulate EEG with mu rhythm (8-13 Hz) for motor imagery
    t = np.linspace(0, duration_sec, n_samples)
    signal = np.zeros((n_channels, n_samples))
    for ch in range(n_channels):
        mu_rhythm = np.sin(2 * np.pi * 10 * t + ch * 0.1)  # 10 Hz mu rhythm
        noise = 0.1 * np.random.randn(n_samples)
        signal[ch] = mu_rhythm + noise
    
    # Initialize attacker
    attacker = ReplayAttackBCI(sampling_rate=sampling_rate)
    
    # Record signal
    signal_hash = attacker.record_signal(
        signal,
        label='user1_motor_imagery_left',
        user_id='user1',
        task_context='left_hand_motor_imagery'
    )
    print(f"Recorded signal with hash: {signal_hash}")
    
    # Direct replay
    replayed, meta = attacker.direct_replay('user1_motor_imagery_left')
    print(f"\nDirect Replay:")
    print(f"  Duration: {meta['replay_duration']:.2f}s")
    print(f"  Detection Risk: {meta['detection_risk']}")
    
    # Time-stretched replay
    stretched, meta = attacker.time_stretched_replay('user1_motor_imagery_left', stretch_factor=1.2)
    print(f"\nTime-Stretched Replay (1.2x):")
    print(f"  Duration: {meta['replay_duration']:.2f}s")
    print(f"  Detection Risk: {meta['detection_risk']}")
    
    # Evaluate replay success
    metrics = attacker.evaluate_replay_success(signal, replayed)
    print(f"\nReplay Success Metrics:")
    print(f"  Correlation: {metrics['correlation']:.4f}")
    print(f"  SNR: {metrics['snr_db']:.2f} dB")
    print(f"  Similarity: {metrics['similarity_score']:.4f}")
    print(f"  Success: {metrics['success']}")
