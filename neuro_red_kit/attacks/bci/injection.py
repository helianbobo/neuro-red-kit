"""
Wireless Signal Injection Attacks for BCI Systems.

This module implements wireless signal injection attacks targeting BCI communication channels.
BCI systems typically use 2.4GHz wireless (OpenBCI Cyton), Bluetooth (consumer EEG headsets),
or WiFi (some research-grade systems) for data transmission.

Attack Vectors:
1. Jamming: Flood the channel with noise to disrupt communication
2. Spoofing: Transmit fake EEG data that appears legitimate
3. Injection: Inject malicious packets into the data stream
4. Man-in-the-Middle: Intercept and modify packets in transit

References:
- OpenBCI Cyton Protocol: https://docs.openbci.com/docs/06Software/01-OpenBCISoftware/CytonDaisyStreamingProtocol
- Bluetooth Low Energy Security: https://www.bluetooth.com/specifications/specs/core-specification-5-4/
- EEG Signal Spoofing: https://arxiv.org/abs/2106.01896
"""

import numpy as np
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import struct


class WirelessProtocol(Enum):
    """Supported wireless protocols for BCI systems."""
    OPENBCI_24GHZ = "openbci_2.4ghz"  # OpenBCI Cyton proprietary protocol
    BLE = "bluetooth_le"  # Bluetooth Low Energy (e.g., Muse, Emotiv)
    WIFI = "wifi"  # WiFi-based systems
    ZIGBEE = "zigbee"  # Some medical-grade BCI systems


class InjectionMode(Enum):
    """Injection attack modes."""
    JAMMING = "jamming"  # Disrupt communication
    SPOOFING = "spoofing"  # Replace with fake data
    INJECTION = "injection"  # Inject into existing stream
    MITM = "man_in_the_middle"  # Intercept and modify


@dataclass
class InjectionConfig:
    """Configuration for wireless injection attack."""
    protocol: WirelessProtocol = WirelessProtocol.OPENBCI_24GHZ
    mode: InjectionMode = InjectionMode.INJECTION
    channel: int = 0  # Wireless channel (0-10 for 2.4GHz)
    power_dbm: float = -20.0  # Transmission power in dBm
    duration_seconds: float = 10.0  # Attack duration
    target_mac: Optional[str] = None  # Target device MAC address
    spoof_data: Optional[np.ndarray] = None  # Data to inject/spoof
    jamming_pattern: str = "continuous"  # continuous, pulsed, random
    pulse_interval_ms: int = 100  # For pulsed jamming
    noise_level: float = 0.5  # Noise amplitude (0-1)


@dataclass
class InjectionResult:
    """Result of an injection attack simulation."""
    success: bool
    attack_type: str
    protocol: str
    duration_seconds: float
    packets_injected: int = 0
    packets_intercepted: int = 0
    signal_quality: float = 0.0  # SNR or correlation metric
    detection_evasion_score: float = 0.0  # How well attack avoided detection
    metadata: Dict = field(default_factory=dict)


class WirelessInjector:
    """
    Wireless signal injection attack simulator for BCI systems.
    
    This class provides methods to simulate various wireless injection attacks
    against BCI communication channels. Note: This is for research and security
    testing purposes only. Actual wireless transmission requires SDR hardware
    (e.g., HackRF, USRP) and appropriate licenses.
    
    Example:
        >>> injector = WirelessInjector()
        >>> config = InjectionConfig(
        ...     protocol=WirelessProtocol.OPENBCI_24GHZ,
        ...     mode=InjectionMode.SPOOFING,
        ...     spoof_data=eeg_signal
        ... )
        >>> result = injector.execute(config)
        >>> print(f"Packets injected: {result.packets_injected}")
    """
    
    # OpenBCI Cyton protocol constants
    OPENBCI_SAMPLE_RATE = 250  # Hz
    OPENBCI_PACKET_SIZE = 33  # bytes (sync + sample + aux + footer)
    OPENBCI_SYNC_BYTE = 0xA0
    OPENBCI_MAX_CHANNEL = 8
    
    # BLE advertising channel constants
    BLE_CHANNELS = [37, 38, 39]  # Advertising channels
    BLE_DATA_CHANNELS = list(range(0, 37))  # Data channels
    
    def __init__(self, sdr_device: Optional[str] = None):
        """
        Initialize the wireless injector.
        
        Args:
            sdr_device: SDR device identifier (e.g., "hackrf", "usrp").
                       If None, runs in simulation mode only.
        """
        self.sdr_device = sdr_device
        self._packet_counter = 0
        
    def execute(self, config: InjectionConfig) -> InjectionResult:
        """
        Execute a wireless injection attack.
        
        Args:
            config: Attack configuration
            
        Returns:
            InjectionResult with attack metrics
        """
        if config.mode == InjectionMode.JAMMING:
            return self._execute_jamming(config)
        elif config.mode == InjectionMode.SPOOFING:
            return self._execute_spoofing(config)
        elif config.mode == InjectionMode.INJECTION:
            return self._execute_injection(config)
        elif config.mode == InjectionMode.MITM:
            return self._execute_mitm(config)
        else:
            raise ValueError(f"Unknown injection mode: {config.mode}")
    
    def _execute_jamming(self, config: InjectionConfig) -> InjectionResult:
        """Execute jamming attack."""
        sample_count = int(config.duration_seconds * self.OPENBCI_SAMPLE_RATE)
        
        if config.jamming_pattern == "continuous":
            # Continuous white noise jamming
            noise = np.random.normal(0, config.noise_level, sample_count)
            jamming_signal = noise
        elif config.jamming_pattern == "pulsed":
            # Pulsed jamming (more power-efficient, harder to detect)
            pulse_samples = int((config.pulse_interval_ms / 1000) * self.OPENBCI_SAMPLE_RATE)
            jamming_signal = np.zeros(sample_count)
            for i in range(0, sample_count, pulse_samples):
                pulse_end = min(i + pulse_samples // 2, sample_count)
                jamming_signal[i:pulse_end] = np.random.normal(0, config.noise_level, pulse_end - i)
        elif config.jamming_pattern == "random":
            # Random pattern jamming
            jamming_signal = np.random.normal(0, config.noise_level, sample_count) * \
                            (np.random.random(sample_count) > 0.5)
        else:
            raise ValueError(f"Unknown jamming pattern: {config.jamming_pattern}")
        
        # Calculate jamming effectiveness
        snr_reduction = 10 * np.log10(1 + config.noise_level ** 2)
        detection_evasion = 0.3 if config.jamming_pattern == "pulsed" else 0.1
        
        return InjectionResult(
            success=True,
            attack_type="jamming",
            protocol=config.protocol.value,
            duration_seconds=config.duration_seconds,
            packets_injected=sample_count,
            signal_quality=-snr_reduction,
            detection_evasion_score=detection_evasion,
            metadata={
                "jamming_pattern": config.jamming_pattern,
                "noise_level": config.noise_level,
                "estimated_snr_reduction_db": snr_reduction
            }
        )
    
    def _execute_spoofing(self, config: InjectionConfig) -> InjectionResult:
        """Execute spoofing attack - transmit fake EEG data."""
        if config.spoof_data is None:
            # Generate synthetic EEG-like signal if not provided
            config.spoof_data = self._generate_synthetic_eeg(
                duration=config.duration_seconds,
                sample_rate=self.OPENBCI_SAMPLE_RATE
            )
        
        # Encode spoof data according to protocol
        if config.protocol == WirelessProtocol.OPENBCI_24GHZ:
            packets = self._encode_openbci_packets(config.spoof_data)
        elif config.protocol == WirelessProtocol.BLE:
            packets = self._encode_ble_packets(config.spoof_data)
        else:
            packets = [config.spoof_data.tobytes()]
        
        # Calculate spoofing quality metrics
        if config.spoof_data is not None:
            # Correlation with typical EEG patterns
            correlation = self._calculate_eeg_realism(config.spoof_data)
        else:
            correlation = 0.5
        
        return InjectionResult(
            success=True,
            attack_type="spoofing",
            protocol=config.protocol.value,
            duration_seconds=config.duration_seconds,
            packets_injected=len(packets),
            signal_quality=correlation,
            detection_evasion_score=correlation * 0.8,  # Realistic signals evade detection better
            metadata={
                "packets_generated": len(packets),
                "signal_correlation": correlation,
                "protocol_encoding": config.protocol.value
            }
        )
    
    def _execute_injection(self, config: InjectionConfig) -> InjectionResult:
        """Execute injection attack - inject into existing stream."""
        if config.spoof_data is None:
            config.spoof_data = self._generate_synthetic_eeg(
                duration=config.duration_seconds,
                sample_rate=self.OPENBCI_SAMPLE_RATE
            )
        
        # Simulate injection into stream
        injection_points = int(config.duration_seconds * 10)  # 10 injections per second
        packets_injected = 0
        
        for i in range(injection_points):
            # Inject a portion of the spoof data
            start_idx = int(i * len(config.spoof_data) / injection_points)
            end_idx = int((i + 1) * len(config.spoof_data) / injection_points)
            
            if config.protocol == WirelessProtocol.OPENBCI_24GHZ:
                packets = self._encode_openbci_packets(config.spoof_data[start_idx:end_idx])
                packets_injected += len(packets)
            else:
                packets_injected += 1
        
        # Calculate injection stealth metrics
        stealth_score = 1.0 - (packets_injected / (config.duration_seconds * 100))  # Fewer injections = more stealth
        
        return InjectionResult(
            success=True,
            attack_type="injection",
            protocol=config.protocol.value,
            duration_seconds=config.duration_seconds,
            packets_injected=packets_injected,
            signal_quality=0.85,
            detection_evasion_score=stealth_score,
            metadata={
                "injection_points": injection_points,
                "stealth_score": stealth_score,
                "injection_interval_ms": 1000 / 10
            }
        )
    
    def _execute_mitm(self, config: InjectionConfig) -> InjectionResult:
        """Execute man-in-the-middle attack."""
        # Simulate interception and modification
        sample_count = int(config.duration_seconds * self.OPENBCI_SAMPLE_RATE)
        
        # Intercept rate (packets per second)
        intercept_rate = 50  # Hz
        packets_intercepted = int(config.duration_seconds * intercept_rate)
        
        # Modification rate (what fraction of packets we modify)
        modification_rate = 0.3
        packets_modified = int(packets_intercepted * modification_rate)
        
        return InjectionResult(
            success=True,
            attack_type="man_in_the_middle",
            protocol=config.protocol.value,
            duration_seconds=config.duration_seconds,
            packets_injected=packets_modified,
            packets_intercepted=packets_intercepted,
            signal_quality=0.7,
            detection_evasion_score=0.6,
            metadata={
                "intercept_rate_hz": intercept_rate,
                "modification_rate": modification_rate,
                "packets_modified": packets_modified
            }
        )
    
    def _generate_synthetic_eeg(self, duration: float, sample_rate: int) -> np.ndarray:
        """
        Generate synthetic EEG-like signal for testing.
        
        Args:
            duration: Signal duration in seconds
            sample_rate: Sampling rate in Hz
            
        Returns:
            Synthetic EEG signal array
        """
        t = np.linspace(0, duration, int(duration * sample_rate))
        
        # Simulate typical EEG frequency bands
        delta = 0.5 * np.sin(2 * np.pi * 2 * t)  # 0.5-4 Hz
        theta = 0.3 * np.sin(2 * np.pi * 5 * t)  # 4-8 Hz
        alpha = 0.4 * np.sin(2 * np.pi * 10 * t)  # 8-13 Hz
        beta = 0.2 * np.sin(2 * np.pi * 20 * t)  # 13-30 Hz
        gamma = 0.1 * np.sin(2 * np.pi * 40 * t)  # 30-100 Hz
        
        # Add noise
        noise = np.random.normal(0, 0.1, len(t))
        
        signal = delta + theta + alpha + beta + gamma + noise
        return signal
    
    def _encode_openbci_packets(self, signal: np.ndarray) -> List[bytes]:
        """
        Encode signal into OpenBCI Cyton protocol packets.
        
        OpenBCI Cyton packet format (33 bytes):
        - 1 byte: Sync byte (0xA0)
        - 1 byte: Sample number (0-255, wraps around)
        - 24 bytes: Channel data (3 bytes per channel, 8 channels)
        - 6 bytes: Aux data (2 bytes per aux channel, 3 channels)
        - 1 byte: Footer (0xC0)
        
        Args:
            signal: EEG signal array
            
        Returns:
            List of encoded packet bytes
        """
        packets = []
        samples_per_packet = 1  # OpenBCI sends one sample per packet
        
        for i in range(0, len(signal), samples_per_packet):
            packet = bytearray(self.OPENBCI_PACKET_SIZE)
            
            # Sync byte
            packet[0] = self.OPENBCI_SYNC_BYTE
            
            # Sample number (wraps at 255)
            packet[1] = self._packet_counter % 256
            self._packet_counter += 1
            
            # Channel data (24-bit signed integers)
            for ch in range(self.OPENBCI_MAX_CHANNEL):
                # Quantize signal to 24-bit range
                sample_value = int(signal[i] * 2**23) if i < len(signal) else 0
                sample_value = max(-2**23, min(2**23 - 1, sample_value))
                
                # Pack as 3 bytes (24-bit signed)
                packed = struct.pack('>i', sample_value)[1:]  # Remove leading byte
                offset = 2 + ch * 3
                packet[offset:offset+3] = packed
            
            # Aux data (simulated)
            aux_offset = 2 + self.OPENBCI_MAX_CHANNEL * 3
            for aux in range(3):
                aux_value = int(np.random.random() * 2**16)
                packet[aux_offset + aux*2:aux_offset + aux*2+2] = struct.pack('>H', aux_value)
            
            # Footer
            packet[-1] = 0xC0
            
            packets.append(bytes(packet))
        
        return packets
    
    def _encode_ble_packets(self, signal: np.ndarray) -> List[bytes]:
        """
        Encode signal into BLE packets (simplified simulation).
        
        BLE data packets vary by profile. For EEG headsets like Muse,
        data is typically sent via notification characteristics.
        
        Args:
            signal: EEG signal array
            
        Returns:
            List of encoded packet bytes
        """
        packets = []
        samples_per_packet = 4  # BLE can carry more samples per packet
        
        for i in range(0, len(signal), samples_per_packet):
            packet_samples = signal[i:i+samples_per_packet]
            
            # BLE packet structure (simplified):
            # - 2 bytes: Header (length + type)
            # - N bytes: Payload (EEG samples)
            # - 2 bytes: CRC
            
            header = struct.pack('>H', len(packet_samples) * 2 + 2)  # 2 bytes per sample
            payload = b''.join(struct.pack('>h', int(s * 1000)) for s in packet_samples)
            crc = struct.pack('>H', sum(payload) & 0xFFFF)
            
            packet = header + payload + crc
            packets.append(packet)
        
        return packets
    
    def _calculate_eeg_realism(self, signal: np.ndarray) -> float:
        """
        Calculate how realistic an EEG signal appears.
        
        Uses simple heuristics:
        - Power spectral density should match typical EEG bands
        - Amplitude should be in realistic range (10-100 μV)
        - Signal should have appropriate temporal structure
        
        Args:
            signal: EEG signal array
            
        Returns:
            Realism score (0-1)
        """
        if len(signal) < 100:
            return 0.5
        
        # Check amplitude range (typical EEG: 10-100 μV)
        amplitude = np.std(signal)
        amplitude_score = 1.0 if 10 < amplitude * 1e6 < 100 else max(0, 1 - abs(amplitude * 1e6 - 50) / 50)
        
        # Check frequency content (simplified)
        # Real EEG has most power in delta/theta/alpha bands
        fft = np.fft.fft(signal)
        freqs = np.fft.fftfreq(len(signal), 1/self.OPENBCI_SAMPLE_RATE)
        
        # Calculate band power ratios
        delta_power = np.sum(np.abs(fft[(freqs >= 0.5) & (freqs < 4)]) ** 2)
        theta_power = np.sum(np.abs(fft[(freqs >= 4) & (freqs < 8)]) ** 2)
        alpha_power = np.sum(np.abs(fft[(freqs >= 8) & (freqs < 13)]) ** 2)
        beta_power = np.sum(np.abs(fft[(freqs >= 13) & (freqs < 30)]) ** 2)
        total_power = delta_power + theta_power + alpha_power + beta_power
        
        if total_power > 0:
            # Realistic EEG: delta+theta+alpha should dominate
            low_freq_ratio = (delta_power + theta_power + alpha_power) / total_power
            frequency_score = low_freq_ratio if low_freq_ratio > 0.5 else low_freq_ratio * 2
        else:
            frequency_score = 0.5
        
        return (amplitude_score + frequency_score) / 2
    
    def create_injection_attack(
        self,
        protocol: str = "openbci_2.4ghz",
        mode: str = "injection",
        duration: float = 10.0,
        target_channel: int = 0,
        noise_level: float = 0.5,
        **kwargs
    ) -> InjectionResult:
        """
        Convenience method to create and execute an injection attack.
        
        Args:
            protocol: Wireless protocol ("openbci_2.4ghz", "bluetooth_le", "wifi")
            mode: Attack mode ("jamming", "spoofing", "injection", "man_in_the_middle")
            duration: Attack duration in seconds
            target_channel: Wireless channel number
            noise_level: Noise amplitude (0-1)
            **kwargs: Additional configuration options
            
        Returns:
            InjectionResult with attack metrics
            
        Example:
            >>> injector = WirelessInjector()
            >>> result = injector.create_injection_attack(
            ...     protocol="openbci_2.4ghz",
            ...     mode="spoofing",
            ...     duration=5.0,
            ...     noise_level=0.3
            ... )
            >>> print(f"Attack success: {result.success}")
        """
        protocol_map = {
            "openbci_2.4ghz": WirelessProtocol.OPENBCI_24GHZ,
            "bluetooth_le": WirelessProtocol.BLE,
            "wifi": WirelessProtocol.WIFI,
            "zigbee": WirelessProtocol.ZIGBEE
        }
        
        mode_map = {
            "jamming": InjectionMode.JAMMING,
            "spoofing": InjectionMode.SPOOFING,
            "injection": InjectionMode.INJECTION,
            "man_in_the_middle": InjectionMode.MITM
        }
        
        config = InjectionConfig(
            protocol=protocol_map.get(protocol, WirelessProtocol.OPENBCI_24GHZ),
            mode=mode_map.get(mode, InjectionMode.INJECTION),
            channel=target_channel,
            duration_seconds=duration,
            noise_level=noise_level,
            **kwargs
        )
        
        return self.execute(config)


# Convenience functions for quick access

def create_wireless_injection(
    protocol: str = "openbci_2.4ghz",
    mode: str = "injection",
    duration: float = 10.0,
    **kwargs
) -> InjectionResult:
    """
    Create and execute a wireless injection attack.
    
    Args:
        protocol: Wireless protocol
        mode: Attack mode
        duration: Duration in seconds
        **kwargs: Additional configuration
        
    Returns:
        InjectionResult
        
    Example:
        >>> result = create_wireless_injection(
        ...     protocol="openbci_2.4ghz",
        ...     mode="spoofing",
        ...     duration=5.0
        ... )
    """
    injector = WirelessInjector()
    return injector.create_injection_attack(protocol, mode, duration, **kwargs)


def simulate_eeg_spoofing(
    duration: float = 10.0,
    sample_rate: int = 250,
    protocol: str = "openbci_2.4ghz"
) -> Tuple[np.ndarray, InjectionResult]:
    """
    Simulate EEG signal spoofing attack.
    
    Args:
        duration: Signal duration in seconds
        sample_rate: Sampling rate in Hz
        protocol: Wireless protocol
        
    Returns:
        Tuple of (spoofed_signal, attack_result)
    """
    injector = WirelessInjector()
    signal = injector._generate_synthetic_eeg(duration, sample_rate)
    
    result = injector.create_injection_attack(
        protocol=protocol,
        mode="spoofing",
        duration=duration,
        spoof_data=signal
    )
    
    return signal, result
