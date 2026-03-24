"""Agent-layer attacks."""

from neuro_red_kit.attacks.agent.prompt_injection import (
    InjectionType,
    InjectionConfig,
    InjectionResult,
    PromptInjectionAttack,
    create_prompt_injection,
    create_batch_injections,
)

from neuro_red_kit.attacks.agent.tool_abuse import (
    ToolAbuseType,
    ToolAbuseConfig,
    ToolAbusePayload,
    ToolAbuseAttack,
    create_tool_abuse_attack,
    create_batch_tool_abuses,
)

from neuro_red_kit.attacks.agent.hijacking import (
    HijackType,
    HijackSeverity,
    HijackConfig,
    HijackPayload,
    AgentHijackingAttack,
    create_agent_hijack,
    create_batch_hijacks,
)

from neuro_red_kit.attacks.agent.privilege_escalation import (
    EscalationType,
    EscalationSeverity,
    EscalationConfig,
    EscalationPayload,
    PrivilegeEscalationAttack,
    create_privilege_escalation,
    create_batch_escalations,
)

__all__ = [
    "InjectionType",
    "InjectionConfig",
    "InjectionResult",
    "PromptInjectionAttack",
    "create_prompt_injection",
    "create_batch_injections",
    "ToolAbuseType",
    "ToolAbuseConfig",
    "ToolAbusePayload",
    "ToolAbuseAttack",
    "create_tool_abuse_attack",
    "create_batch_tool_abuses",
    "HijackType",
    "HijackSeverity",
    "HijackConfig",
    "HijackPayload",
    "AgentHijackingAttack",
    "create_agent_hijack",
    "create_batch_hijacks",
    "EscalationType",
    "EscalationSeverity",
    "EscalationConfig",
    "EscalationPayload",
    "PrivilegeEscalationAttack",
    "create_privilege_escalation",
    "create_batch_escalations",
]
