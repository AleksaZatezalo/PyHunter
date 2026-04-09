"""Active detection rules — focused on the top-15 web-app-to-root exploit chain.

Each rule targets a specific stage of the chain:
  Initial access  → SSTI, DESER-RCE, CMD-INJECT, DEBUG-EXPOSED, FILE-UPLOAD
  Data / pivoting → SQL-INJECT, SSRF, XXE, PATH-TRAVERSAL
  Credential      → HARDCODED-SECRET
  Auth bypass     → AUTH-BYPASS, MASS-ASSIGN
  Privesc         → SUID-RISK, WRITABLE-PATH, CONTAINER-ESCAPE
"""
from __future__ import annotations

from pyhunter.rules.r01_ssti             import SSTIRule
from pyhunter.rules.r02_deser_rce        import DeserRCERule
from pyhunter.rules.r03_cmd_inject       import CmdInjectRule
from pyhunter.rules.r04_debug_exposed    import DebugExposedRule
from pyhunter.rules.r05_file_upload_rce  import FileUploadRCERule
from pyhunter.rules.r06_sqli             import SQLInjectRule
from pyhunter.rules.r07_ssrf             import SSRFRule
from pyhunter.rules.r08_xxe              import XXERule
from pyhunter.rules.r09_path_traversal   import PathTraversalRule
from pyhunter.rules.r10_hardcoded_secrets import HardcodedSecretsRule
from pyhunter.rules.r11_auth_bypass      import AuthBypassRule
from pyhunter.rules.r12_mass_assign      import MassAssignRule
from pyhunter.rules.r13_suid_risk        import SUIDRiskRule
from pyhunter.rules.r14_writable_path    import WritablePathRule
from pyhunter.rules.r15_container_escape import ContainerEscapeRule


def all_rules():
    return [
        # ── Initial access ────────────────────────────────────────────────────
        SSTIRule(),           # Template injection → RCE
        DeserRCERule(),       # pickle/YAML/jsonpickle → RCE
        CmdInjectRule(),      # OS command injection → RCE
        DebugExposedRule(),   # Debug console / Werkzeug REPL → RCE
        FileUploadRCERule(),  # Webshell upload → RCE

        # ── Data exfiltration & lateral movement ──────────────────────────────
        SQLInjectRule(),      # SQLi → creds dump, file write, DB RCE
        SSRFRule(),           # SSRF → cloud metadata, internal services
        XXERule(),            # XXE → file read, SSRF pivot
        PathTraversalRule(),  # Path traversal → read SSH keys, .env, source

        # ── Credential access ─────────────────────────────────────────────────
        HardcodedSecretsRule(),  # Hardcoded keys → direct DB/cloud/SSH access

        # ── Authentication & authorisation bypass ─────────────────────────────
        AuthBypassRule(),     # JWT bypass, DRF no-auth, FastAPI unprotected routes
        MassAssignRule(),     # Mass assignment → is_admin=True, role=superuser

        # ── Privilege escalation (post-RCE) ───────────────────────────────────
        SUIDRiskRule(),          # SUID binary abuse, chmod +s, ctypes.setuid(0)
        WritablePathRule(),      # Write to cron/sudoers/authorized_keys
        ContainerEscapeRule(),   # Docker socket, privileged container, cap_sys_admin
    ]
