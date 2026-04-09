"""Rule registry — single import point for all detection rules."""

from pyhunter.rules import BaseRule
from pyhunter.rules.rce_eval import DynamicCodeExecutionRule
from pyhunter.rules.cmd_injection import CommandInjectionRule
from pyhunter.rules.unsafe_deserialization import UnsafeDeserializationRule
from pyhunter.rules.dunder_abuse import DunderAbuseRule
from pyhunter.rules.import_time_exec import ImportTimeExecRule
from pyhunter.rules.build_rce import BuildInstallRCERule
from pyhunter.rules.path_traversal import PathTraversalRule
from pyhunter.rules.dynamic_import import DynamicImportRule
from pyhunter.rules.web_flow import WebInputFlowRule
from pyhunter.rules.decorator_exec import DecoratorExecutionRule


def all_rules() -> list[BaseRule]:
    """Return one instance of every registered rule."""
    return [
        DynamicCodeExecutionRule(),
        CommandInjectionRule(),
        UnsafeDeserializationRule(),
        DunderAbuseRule(),
        ImportTimeExecRule(),
        BuildInstallRCERule(),
        PathTraversalRule(),
        DynamicImportRule(),
        WebInputFlowRule(),
        DecoratorExecutionRule(),
    ]
