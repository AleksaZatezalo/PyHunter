"""Rule registry — returns the active set of detection rules.

Design pattern: Registry (creational)
  all_rules() is the single point of registration. The Scanner queries it at
  startup and filters out any rules disabled in .pyhunterrc. Adding a new rule
  means adding one import and one constructor call here — nothing else changes.

Current rule set (9 rules across 3 attack phases):

  Initial Access  ─ FLOW-WEB, CMD-INJECT, DESER-RCE, FILE-UPLOAD, PICKLE-NET
  Code Execution  ─ RCE-EVAL, EXEC-DECORATOR
  Supply Chain    ─ RCE-BUILD, RCE-IMPORT
"""
from __future__ import annotations

from pyhunter.rules.rce_eval        import DynamicCodeExecutionRule
from pyhunter.rules.import_time_exec import ImportTimeExecRule
from pyhunter.rules.build_rce       import BuildInstallRCERule
from pyhunter.rules.web_flow        import WebInputFlowRule
from pyhunter.rules.decorator_exec  import DecoratorExecutionRule
from pyhunter.rules.pickle_socket   import PickleOverSocketRule
from pyhunter.rules.cmd_injection   import CommandInjectionRule
from pyhunter.rules.deser_rce       import DeserRCERule
from pyhunter.rules.file_upload_rce import FileUploadRCERule


def all_rules():
    """Return one fresh instance of every active detection rule."""
    return [
        # ── Initial Access ────────────────────────────────────────────────────
        WebInputFlowRule(),       # FLOW-WEB    — web/CLI input → dangerous sink
        CommandInjectionRule(),   # CMD-INJECT  — user input → OS command executor
        DeserRCERule(),           # DESER-RCE   — user input → deserialiser (pickle/yaml/…)
        FileUploadRCERule(),      # FILE-UPLOAD — unvalidated upload → webshell
        PickleOverSocketRule(),   # PICKLE-NET  — pickle over network socket

        # ── Code Execution ────────────────────────────────────────────────────
        DynamicCodeExecutionRule(),  # RCE-EVAL       — eval/exec/compile
        DecoratorExecutionRule(),    # EXEC-DECORATOR — dynamic/dangerous decorator

        # ── Supply Chain ──────────────────────────────────────────────────────
        BuildInstallRCERule(),    # RCE-BUILD  — setup.py cmdclass → build-time RCE
        ImportTimeExecRule(),     # RCE-IMPORT — dangerous call at import time
    ]
