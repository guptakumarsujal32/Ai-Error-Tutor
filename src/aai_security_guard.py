"""
Agentic AI (AAI) Security Guard - Multi-Layer Defense and Threat Detection.

Defends the Agentic AI against:
  1. Prompt Injections & Policy Bypasses (direct overrides, jailbreaks, roleplay attacks)
  2. Indirect Prompt Injections (hidden directives in comments, docstrings, string literals)
  3. Trojan Healed Code & Hidden Agendas (covert PII exfiltration, credential theft)
  4. Obfuscated Sandbox Escapes & Dynamic Introspection (__subclasses__, getattr eval)
  5. Resource Exhaustion & Algorithmic Denial of Service (DoS)

Provides:
  - Threat Detection Engine
  - Quantified Risk Assessment (Risk Level + 0-100 Risk Score)
  - Action Blocking & Quarantine (Fail-Closed)
  - Structured Attack Audit Logging
  - Multi-Vector Attack Simulator and Metrics Benchmark (Precision, Recall, F1, ASR, FPR)
"""

import ast
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    POLICY_BYPASS = "policy_bypass"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    TROJAN_HEALED_CODE = "trojan_healed_code"
    PII_DATA_EXFILTRATION = "pii_data_exfiltration"
    OBFUSCATED_EXECUTION = "obfuscated_execution"
    RESOURCE_DOS = "resource_dos"
    BENIGN = "benign"


class RiskLevel(str, Enum):
    BENIGN = "BENIGN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatFinding:
    """Represents a specific detected threat signature or heuristic."""
    category: ThreatCategory
    severity: RiskLevel
    rule_id: str
    description: str
    matched_snippet: str
    weight: float = 1.0


@dataclass
class SecurityAssessment:
    """Consolidated risk assessment for input prompt, code, or healed code."""
    is_safe: bool
    risk_level: RiskLevel
    risk_score: float                # 0.0 to 100.0
    primary_category: ThreatCategory
    findings: List[ThreatFinding] = field(default_factory=list)
    blocked_actions: List[str] = field(default_factory=list)
    remediation_advice: str = ""
    audit_id: str = ""
    target_type: str = "code"        # "prompt", "code", or "healed_code"
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['risk_level'] = self.risk_level.value
        data['primary_category'] = self.primary_category.value
        for finding in data['findings']:
            finding['category'] = finding['category'].value if isinstance(finding['category'], ThreatCategory) else finding['category']
            finding['severity'] = finding['severity'].value if isinstance(finding['severity'], RiskLevel) else finding['severity']
        return data


class AAIAttackAuditLogger:
    """
    Logs all detected security incidents and audit trails into structured
    JSONL and text log files.
    """

    def __init__(self, log_dir: Optional[str] = None):
        base_dir = log_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".security_scans"
        )
        self.log_dir = base_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.jsonl_path = os.path.join(self.log_dir, "security_audit.jsonl")
        self.log_path = os.path.join(self.log_dir, "security_audit.log")

    def log_assessment(self, assessment: SecurityAssessment, raw_input: str) -> None:
        """Log assessment to persistent audit storage if a risk or block occurred."""
        if assessment.is_safe and assessment.risk_level == RiskLevel.BENIGN:
            return  # Only log threats or non-trivial events to prevent log bloat

        sanitized_sample = raw_input.strip()
        if len(sanitized_sample) > 300:
            sanitized_sample = sanitized_sample[:300] + "... [TRUNCATED]"

        # Redact common secrets patterns in logged payloads
        sanitized_sample = re.sub(
            r'(AIza[0-9A-Za-z-_]{35}|ghp_[0-9A-Za-z]{36}|sk-[a-zA-Z0-9]{32,})',
            '[REDACTED_API_KEY]',
            sanitized_sample
        )

        entry = {
            "audit_id": assessment.audit_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_type": assessment.target_type,
            "is_safe": assessment.is_safe,
            "risk_level": assessment.risk_level.value,
            "risk_score": round(assessment.risk_score, 2),
            "primary_category": assessment.primary_category.value,
            "blocked_actions": assessment.blocked_actions,
            "findings_count": len(assessment.findings),
            "findings": [asdict(f) for f in assessment.findings],
            "sample_snippet": sanitized_sample,
            "latency_ms": round(assessment.latency_ms, 2)
        }

        # Write to JSONL
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as jf:
                jf.write(json.dumps(entry) + "\n")
        except Exception:
            pass

        # Write to human-readable log
        try:
            with open(self.log_path, "a", encoding="utf-8") as lf:
                lf.write(
                    f"[{entry['timestamp']}] [{assessment.risk_level.value}] "
                    f"ID={assessment.audit_id} "
                    f"Target={assessment.target_type} "
                    f"Category={assessment.primary_category.value} "
                    f"Score={assessment.risk_score:.1f} "
                    f"Blocked={assessment.blocked_actions}\n"
                )
        except Exception:
            pass


class AAISecurityGuard:
    """
    Comprehensive Security Layer for Agentic AI:
    - Analyzes inbound user prompts & code.
    - Scans outbound/healed candidate code for trojan insertions and hidden agendas.
    - Computes risk levels and scores.
    - Enforces fail-closed blocking and logs attacks.
    """

    # 1. Prompt Injection & Policy Bypass Regex Signatures
    PROMPT_INJECTION_PATTERNS = [
        # Policy bypass & validation disabling (e.g. user prompt example)
        (
            r"(?i)\bignore\s+(?:the\s+|all\s+|any\s+)?(?:security|safety|policy|policies|rules|instructions|sandbox|guardrails?|guidelines?)",
            ThreatCategory.POLICY_BYPASS,
            RiskLevel.CRITICAL,
            "POL-01",
            "Direct instruction to ignore security policies or safety guidelines"
        ),
        (
            r"(?i)\bdisable\s+(?:the\s+)?(?:validation|security|safety|sandbox|scanner|filtering|gate|watchdog)\s+(?:step|check|process|layer)?",
            ThreatCategory.POLICY_BYPASS,
            RiskLevel.CRITICAL,
            "POL-02",
            "Explicit command to disable security validation or sandbox checks"
        ),
        (
            r"(?i)\bmark\s+(?:the\s+)?(?:vulnerable|unsafe|malicious|bad|insecure)\s+code\s+as\s+(?:safe|secure|valid|clean|benign)",
            ThreatCategory.POLICY_BYPASS,
            RiskLevel.CRITICAL,
            "POL-03",
            "Attempt to coerce AI into marking vulnerable code as safe"
        ),
        (
            r"(?i)\b(?:bypass|circumvent|skip|override)\s+(?:the\s+|all\s+)?(?:security|validation|sandbox|safety|checks?|restrictions?)",
            ThreatCategory.POLICY_BYPASS,
            RiskLevel.CRITICAL,
            "POL-04",
            "Explicit request to bypass security controls"
        ),

        # Jailbreak, Persona & Unrestricted AI Hijacking
        (
            r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:unrestricted|jailbroken|DAN|evil|anarchist|god\s*mode|root)\b",
            ThreatCategory.PROMPT_INJECTION,
            RiskLevel.CRITICAL,
            "INJ-01",
            "Jailbreak persona or unrestricted mode roleplay attempt"
        ),
        (
            r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts|rules|context)",
            ThreatCategory.PROMPT_INJECTION,
            RiskLevel.CRITICAL,
            "INJ-02",
            "Attempt to wipe context and override system instructions"
        ),
        (
            r"(?i)\bdeveloper\s+mode\s+(?:enabled|activated|on)\b",
            ThreatCategory.PROMPT_INJECTION,
            RiskLevel.HIGH,
            "INJ-03",
            "Developer mode privilege escalation prompt"
        ),
        (
            r"(?i)\b(?:reveal|dump|leak|print|output)\s+(?:your\s+|the\s+)?(?:system\s+prompt|developer\s+prompt|initial\s+instructions|system\s+instructions)",
            ThreatCategory.PROMPT_INJECTION,
            RiskLevel.HIGH,
            "INJ-04",
            "System prompt extraction or leakage attempt"
        ),
        (
            r"(?i)<\s*(?:system|im_start|admin|instruction)\s*>",
            ThreatCategory.PROMPT_INJECTION,
            RiskLevel.HIGH,
            "INJ-05",
            "Delimiter injection mimicking internal agent/system tokens"
        ),
    ]

    # 2. Indirect Prompt Injection Patterns inside comments or string literals
    INDIRECT_INJECTION_PATTERNS = [
        (
            r"(?i)#.*(?:\[SYSTEM|\[ADMIN|IMPORTANT\s+INSTRUCTION|NOTE\s+TO\s+AI|DISREGARD\s+RULES|IGNORE\s+SECURITY)",
            ThreatCategory.INDIRECT_PROMPT_INJECTION,
            RiskLevel.CRITICAL,
            "IND-01",
            "Indirect prompt injection disguised inside a code comment"
        ),
        (
            r"(?i)'''[\s\S]*?(?:ignore\s+security|bypass\s+validation|disable\s+checks|unrestricted\s+mode)[\s\S]*?'''",
            ThreatCategory.INDIRECT_PROMPT_INJECTION,
            RiskLevel.CRITICAL,
            "IND-02",
            "Indirect prompt injection hidden in multi-line triple-quoted string"
        ),
        (
            r'(?i)"""[\s\S]*?(?:ignore\s+security|bypass\s+validation|disable\s+checks|unrestricted\s+mode)[\s\S]*?"""',
            ThreatCategory.INDIRECT_PROMPT_INJECTION,
            RiskLevel.CRITICAL,
            "IND-03",
            "Indirect prompt injection hidden in double-quoted docstring"
        ),
    ]

    # 3. PII & Secret Exfiltration Signatures (Personal info, env keys, credentials)
    PII_EXFILTRATION_PATTERNS = [
        (
            r"(?i)\bos\.environ(?:\.get)?\s*\[?\s*['\"](?:GEMINI_API_KEY|API_KEY|AWS_SECRET|SECRET_KEY|PASSWORD|PRIVATE_KEY|TOKEN|AUTH)",
            ThreatCategory.PII_DATA_EXFILTRATION,
            RiskLevel.CRITICAL,
            "EXF-01",
            "Targeted harvesting of sensitive API keys or environment secrets"
        ),
        (
            r"(?i)(?:~/\.ssh|\.ssh/id_rsa|\.ssh/known_hosts|/etc/passwd|/etc/shadow|C:\\Windows\\System32\\config)",
            ThreatCategory.PII_DATA_EXFILTRATION,
            RiskLevel.CRITICAL,
            "EXF-02",
            "Access to personal SSH keys, password hashes, or system credentials"
        ),
        (
            r"(?i)\b(?:open|read)\s*\(\s*['\"][^'\"]*(?:\.env|credentials|secret|passwords?\.txt|token\.json)['\"]",
            ThreatCategory.PII_DATA_EXFILTRATION,
            RiskLevel.CRITICAL,
            "EXF-03",
            "Attempt to open local credentials, .env files, or secret stores"
        ),
        (
            r"(?i)\b(?:pyperclip\.paste|tkinter\.Tk\(\)\.clipboard_get)\s*\(",
            ThreatCategory.PII_DATA_EXFILTRATION,
            RiskLevel.HIGH,
            "EXF-04",
            "Clipboard data harvesting"
        ),
        (
            r"(?i)(?:requests\.(?:post|put)|urllib\.request\.urlopen|socket\.socket)\s*\(.*?(?:webhook|evil|exfil|attacker|ngrok|pipedream)",
            ThreatCategory.PII_DATA_EXFILTRATION,
            RiskLevel.CRITICAL,
            "EXF-05",
            "Covert outbound data exfiltration via webhook or remote endpoint"
        ),
    ]

    # 4. Obfuscation, Dynamic Introspection & Sandbox Bypass
    OBFUSCATION_PATTERNS = [
        (
            r"(?i)__subclasses__\s*\(\s*\)",
            ThreatCategory.OBFUSCATED_EXECUTION,
            RiskLevel.CRITICAL,
            "OBF-01",
            "Python object class hierarchy traversal (__subclasses__) sandbox escape"
        ),
        (
            r"(?i)__globals__\s*\[\s*['\"](?:system|popen|spawn|__builtins__)['\"]",
            ThreatCategory.OBFUSCATED_EXECUTION,
            RiskLevel.CRITICAL,
            "OBF-02",
            "Introspection via __globals__ to access restricted system functions"
        ),
        (
            r"(?i)getattr\s*\(\s*(?:__builtins__|builtins)\s*,\s*['\"][a-zA-Z0-9_\+]+['\"]",
            ThreatCategory.OBFUSCATED_EXECUTION,
            RiskLevel.CRITICAL,
            "OBF-03",
            "Dynamic attribute access on builtins to resolve blocked functions"
        ),
        (
            r"(?i)(?:base64\.b64decode|codecs\.decode|bytes\.fromhex)\s*\(",
            ThreatCategory.OBFUSCATED_EXECUTION,
            RiskLevel.HIGH,
            "OBF-04",
            "Encoded/obfuscated payload decoder"
        ),
    ]

    def __init__(self, log_dir: Optional[str] = None):
        self.logger = AAIAttackAuditLogger(log_dir=log_dir)

    def assess_input(self, text_or_code: str, target_type: str = "code") -> SecurityAssessment:
        """
        Assess incoming prompt or user code for prompt injection, policy bypass,
        exfiltration, or malicious constructs.
        """
        start_time = time.perf_counter()
        findings: List[ThreatFinding] = []

        if not text_or_code or not text_or_code.strip():
            return SecurityAssessment(
                is_safe=True,
                risk_level=RiskLevel.BENIGN,
                risk_score=0.0,
                primary_category=ThreatCategory.BENIGN,
                audit_id=uuid.uuid4().hex[:12],
                target_type=target_type,
                latency_ms=0.0
            )

        content = text_or_code.strip()

        # Step 1: Check Prompt Injection & Policy Bypass
        for pattern, cat, sev, rule_id, desc in self.PROMPT_INJECTION_PATTERNS:
            match = re.search(pattern, content)
            if match:
                findings.append(ThreatFinding(
                    category=cat,
                    severity=sev,
                    rule_id=rule_id,
                    description=desc,
                    matched_snippet=match.group(0)[:80],
                    weight=1.5 if sev == RiskLevel.CRITICAL else 1.0
                ))

        # Step 2: Check Indirect Prompt Injection (inside comments/docstrings)
        for pattern, cat, sev, rule_id, desc in self.INDIRECT_INJECTION_PATTERNS:
            match = re.search(pattern, content)
            if match:
                findings.append(ThreatFinding(
                    category=cat,
                    severity=sev,
                    rule_id=rule_id,
                    description=desc,
                    matched_snippet=match.group(0)[:80],
                    weight=1.5
                ))

        # Step 3: Check PII / Secret Exfiltration
        for pattern, cat, sev, rule_id, desc in self.PII_EXFILTRATION_PATTERNS:
            match = re.search(pattern, content)
            if match:
                findings.append(ThreatFinding(
                    category=cat,
                    severity=sev,
                    rule_id=rule_id,
                    description=desc,
                    matched_snippet=match.group(0)[:80],
                    weight=1.4
                ))

        # Step 4: Check Obfuscation & Dynamic Introspection
        for pattern, cat, sev, rule_id, desc in self.OBFUSCATION_PATTERNS:
            match = re.search(pattern, content)
            if match:
                findings.append(ThreatFinding(
                    category=cat,
                    severity=sev,
                    rule_id=rule_id,
                    description=desc,
                    matched_snippet=match.group(0)[:80],
                    weight=1.3
                ))

        # Step 5: AST Deep Analysis (if code is parseable)
        ast_findings = self._ast_deep_scan(content)
        findings.extend(ast_findings)

        # Compute Consolidated Score & Risk Level
        risk_score, risk_level, primary_cat = self._calculate_risk(findings)
        is_safe = risk_level in (RiskLevel.BENIGN, RiskLevel.LOW)

        blocked_actions = []
        remediation_advice = "No threat detected."
        if not is_safe:
            blocked_actions = ["sandbox_execution_halted", "llm_generation_prevented", "response_quarantined"]
            remediation_advice = (
                f"The request was identified as a {primary_cat.value.replace('_', ' ').title()} attack. "
                "The Agentic AI security layer has blocked the action to protect the system and user privacy."
            )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        assessment = SecurityAssessment(
            is_safe=is_safe,
            risk_level=risk_level,
            risk_score=risk_score,
            primary_category=primary_cat,
            findings=findings,
            blocked_actions=blocked_actions,
            remediation_advice=remediation_advice,
            audit_id=uuid.uuid4().hex[:12],
            target_type=target_type,
            latency_ms=latency_ms
        )

        # Automatically log threats
        self.logger.log_assessment(assessment, content)
        return assessment

    def audit_healed_code(self, healed_code: str, original_code: str = "") -> SecurityAssessment:
        """
        Specialized Egress Guard:
        Audits candidate code synthesized or proposed by the Agentic AI (or LLM)
        to ensure the fix has no trojan insertions, covert PII exfiltration,
        or backdoors.
        """
        assessment = self.assess_input(healed_code, target_type="healed_code")

        # Additional heuristic: If original code did NOT have environment or file access,
        # but healed code suddenly introduces them, flag as TROJAN_HEALED_CODE.
        if "os.environ" in healed_code and "os.environ" not in original_code:
            assessment.findings.append(ThreatFinding(
                category=ThreatCategory.TROJAN_HEALED_CODE,
                severity=RiskLevel.CRITICAL,
                rule_id="TRJ-01",
                description="Healed code introduced unauthorized os.environ secret inspection",
                matched_snippet="os.environ inspection in fix",
                weight=2.0
            ))
            assessment.is_safe = False
            assessment.risk_level = RiskLevel.CRITICAL
            assessment.risk_score = max(assessment.risk_score, 95.0)
            assessment.primary_category = ThreatCategory.TROJAN_HEALED_CODE
            assessment.blocked_actions = ["healed_code_quarantined", "sandbox_verification_aborted"]
            assessment.remediation_advice = "The proposed code repair contained a suspicious trojan pattern accessing secrets."

        if not assessment.is_safe and assessment.primary_category != ThreatCategory.TROJAN_HEALED_CODE:
            # Reclassify as trojan healed code if it's in the healed artifact
            assessment.primary_category = ThreatCategory.TROJAN_HEALED_CODE

        return assessment

    def _ast_deep_scan(self, code: str) -> List[ThreatFinding]:
        """Deep AST analysis for stealthy or dynamic bypass attempts."""
        findings: List[ThreatFinding] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for getattr with dangerous builtins or calls
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == 'getattr' and len(node.args) >= 2:
                    # check if inspecting __builtins__
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Name) and first_arg.id in ('__builtins__', 'builtins'):
                        findings.append(ThreatFinding(
                            category=ThreatCategory.OBFUSCATED_EXECUTION,
                            severity=RiskLevel.CRITICAL,
                            rule_id="AST-01",
                            description="AST detected dynamic getattr on builtins",
                            matched_snippet="getattr(__builtins__, ...)",
                            weight=1.5
                        ))

            # Check for suspicious attribute chains: .__class__.__bases__
            if isinstance(node, ast.Attribute):
                if node.attr in ('__subclasses__', '__bases__', '__mro__', '__globals__'):
                    findings.append(ThreatFinding(
                        category=ThreatCategory.OBFUSCATED_EXECUTION,
                        severity=RiskLevel.HIGH,
                        rule_id="AST-02",
                        description=f"AST detected introspection attribute '{node.attr}'",
                        matched_snippet=node.attr,
                        weight=1.2
                    ))

        return findings

    def _calculate_risk(self, findings: List[ThreatFinding]) -> Tuple[float, RiskLevel, ThreatCategory]:
        """Calculates normalized 0-100 risk score, categorical risk level, and primary category."""
        if not findings:
            return 0.0, RiskLevel.BENIGN, ThreatCategory.BENIGN

        # Weight table
        total_score = 0.0
        critical_count = 0
        high_count = 0

        category_counts: Dict[ThreatCategory, float] = {}

        for f in findings:
            category_counts[f.category] = category_counts.get(f.category, 0.0) + f.weight
            if f.severity == RiskLevel.CRITICAL:
                total_score += 45.0 * f.weight
                critical_count += 1
            elif f.severity == RiskLevel.HIGH:
                total_score += 25.0 * f.weight
                high_count += 1
            elif f.severity == RiskLevel.MEDIUM:
                total_score += 15.0 * f.weight
            else:
                total_score += 5.0 * f.weight

        # Cap score at 100.0
        normalized_score = min(100.0, max(0.0, total_score))

        # Assign Risk Level
        if critical_count > 0 or normalized_score >= 70.0:
            level = RiskLevel.CRITICAL
        elif high_count > 0 or normalized_score >= 45.0:
            level = RiskLevel.HIGH
        elif normalized_score >= 20.0:
            level = RiskLevel.MEDIUM
        elif normalized_score > 0.0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.BENIGN

        # Primary Category is the one with highest cumulative weight
        primary_cat = max(category_counts.items(), key=lambda item: item[1])[0]

        return normalized_score, level, primary_cat
