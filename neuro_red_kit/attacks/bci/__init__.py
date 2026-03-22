"""BCI layer attack modules."""

from .adversarial import AdversarialBCIAttack, create_eeg_adversarial_sample
from .replay import ReplayAttackBCI, create_replay_attack
from .injection import (
    WirelessInjector,
    InjectionConfig,
    InjectionResult,
    WirelessProtocol,
    InjectionMode,
    create_wireless_injection,
    simulate_eeg_spoofing,
)
from .spoofing import (
    SensorSpoofingAttack,
    SpoofingConfig,
    SpoofingResult,
    SpoofingMode,
    create_sensor_spoofing,
)

__all__ = [
    "AdversarialBCIAttack",
    "create_eeg_adversarial_sample",
    "ReplayAttackBCI",
    "create_replay_attack",
    "WirelessInjector",
    "InjectionConfig",
    "InjectionResult",
    "WirelessProtocol",
    "InjectionMode",
    "create_wireless_injection",
    "simulate_eeg_spoofing",
    "SensorSpoofingAttack",
    "SpoofingConfig",
    "SpoofingResult",
    "SpoofingMode",
    "create_sensor_spoofing",
]
