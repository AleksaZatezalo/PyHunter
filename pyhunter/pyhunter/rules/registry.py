"""Returns the list of all active detection rules."""
from __future__ import annotations

from pyhunter.rules.rce_eval               import DynamicCodeExecutionRule
from pyhunter.rules.cmd_injection          import CommandInjectionRule
from pyhunter.rules.unsafe_deserialization import UnsafeDeserializationRule
from pyhunter.rules.path_traversal         import PathTraversalRule
from pyhunter.rules.ssti                   import SSTIRule
from pyhunter.rules.unsafe_subprocess      import UnsafeSubprocessRule
from pyhunter.rules.pickle_socket          import PickleOverSocketRule
from pyhunter.rules.dunder_abuse           import DunderAbuseRule
from pyhunter.rules.import_time_exec       import ImportTimeExecRule
from pyhunter.rules.build_rce              import BuildInstallRCERule
from pyhunter.rules.web_flow               import WebInputFlowRule


def all_rules():
    return [
        DynamicCodeExecutionRule(),
        CommandInjectionRule(),
        UnsafeDeserializationRule(),
        PathTraversalRule(),
        SSTIRule(),
        UnsafeSubprocessRule(),
        PickleOverSocketRule(),
        DunderAbuseRule(),
        ImportTimeExecRule(),
        BuildInstallRCERule(),
        WebInputFlowRule(),
    ]
