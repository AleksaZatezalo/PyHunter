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

# Injection
from pyhunter.rules.sql_injection          import SQLInjectionRule
from pyhunter.rules.nosql_injection        import NoSQLInjectionRule
from pyhunter.rules.log_injection          import LogInjectionRule
from pyhunter.rules.header_injection       import HeaderInjectionRule

# Cryptography
from pyhunter.rules.weak_crypto            import WeakCryptoRule
from pyhunter.rules.hardcoded_secrets      import HardcodedSecretsRule
from pyhunter.rules.insecure_random        import InsecureRandomRule

# Authentication / Session
from pyhunter.rules.weak_jwt               import WeakJWTRule
from pyhunter.rules.insecure_cookie        import InsecureCookieRule

# Network / SSRF
from pyhunter.rules.ssrf                   import SSRFRule
from pyhunter.rules.xxe                    import XXERule
from pyhunter.rules.insecure_tls           import InsecureTLSRule

# Secrets / Leakage
from pyhunter.rules.debug_enabled          import DebugEnabledRule
from pyhunter.rules.stack_trace_leak       import StackTraceLeakRule

# Race Conditions / Resource
from pyhunter.rules.toctou                 import TOCTOURule
from pyhunter.rules.redos                  import ReDoSRule

# Web-Specific
from pyhunter.rules.open_redirect          import OpenRedirectRule
from pyhunter.rules.mass_assignment        import MassAssignmentRule
from pyhunter.rules.cors_misconfig         import CORSMisconfigRule


def all_rules():
    return [
        # Original rules
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

        # Injection
        SQLInjectionRule(),
        NoSQLInjectionRule(),
        LogInjectionRule(),
        HeaderInjectionRule(),

        # Cryptography
        WeakCryptoRule(),
        HardcodedSecretsRule(),
        InsecureRandomRule(),

        # Authentication / Session
        WeakJWTRule(),
        InsecureCookieRule(),

        # Network / SSRF
        SSRFRule(),
        XXERule(),
        InsecureTLSRule(),

        # Secrets / Leakage
        DebugEnabledRule(),
        StackTraceLeakRule(),

        # Race Conditions / Resource
        TOCTOURule(),
        ReDoSRule(),

        # Web-Specific
        OpenRedirectRule(),
        MassAssignmentRule(),
        CORSMisconfigRule(),
    ]
