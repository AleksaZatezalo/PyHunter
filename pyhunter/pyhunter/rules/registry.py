"""Returns the list of all active detection rules."""
from __future__ import annotations

from pyhunter.rules.rce_eval               import DynamicCodeExecutionRule
from pyhunter.rules.cmd_injection          import CommandInjectionRule
from pyhunter.rules.unsafe_deserialization import UnsafeDeserializationRule
from pyhunter.rules.path_traversal         import PathTraversalRule
from pyhunter.rules.ssti                   import SSTIRule
from pyhunter.rules.unsafe_subprocess      import UnsafeSubprocessRule
from pyhunter.rules.pickle_socket          import PickleOverSocketRule


def all_rules():
    return [
        DynamicCodeExecutionRule(),
        CommandInjectionRule(),
        UnsafeDeserializationRule(),
        PathTraversalRule(),
        SSTIRule(),
        UnsafeSubprocessRule(),
        PickleOverSocketRule(),
    ]
