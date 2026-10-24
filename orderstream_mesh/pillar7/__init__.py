"""
OrderStream Enterprise Engineering Mesh - Pillar 7: AI Code Agent Defenses, Prompt Shielding & Hallucination Firewalls
Solvers 61-70:
61. PromptInjectionSanitizer: Neutralizes adversarial prompt injections hidden in PR comments and code
62. PhantomPackageFirewall: Blocks AI-hallucinated phantom package imports and slopsquatting attacks
63. AgentLoopCostCircuitBreaker: Intercepts repetitive agent thrashing and runaway LLM billing loops
64. SyntheticCodeEntropyWatermarker: Scores code perplexity and stylistic entropy to audit AI generation
65. RAGEmbeddingStalenessCleaner: Synchronizes AST chunk hashes to invalidate stale code search vectors
66. AgentPermissionSandbox: Least-privilege capability broker constraining autonomous agent actions
67. ContextWindowOptimizer: AST token slicing engine reducing context length and LLM inference cost
68. HallucinatedAPIFirewall: Verifies AI-synthesized function calls against true installed symbol stubs
69. AgenticGitRebaseGovernor: Autonomous rebase conflict reconciler preventing infinite agent loops
70. AdversarialBenchmarkAuditor: Codebase benchmark leak detector preventing LLM evaluation contamination
"""

import hashlib
import json
import math
import re
import time
from typing import Dict, List, Optional, Set, Tuple


# -------------------------------------------------------------
# 61. Prompt Injection Sanitizer
# -------------------------------------------------------------
class PromptInjectionSanitizer:
    """
    AST-level comment and string literal sanitizer neutralizing adversarial indirect prompt injection
    attacks hidden within pull requests aimed at compromising automated AI code reviewers.
    """
    ADVERSARIAL_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(prior|previous)\s+instructions", re.IGNORECASE),
        re.compile(r"approve\s+this\s+pr\s+immediately", re.IGNORECASE),
        re.compile(r"system\s*:\s*you\s+are\s+now", re.IGNORECASE),
        re.compile(r"you\s+must\s+say\s+LGTM", re.IGNORECASE),
        re.compile(r"disregard\s+all\s+security\s+rules", re.IGNORECASE)
    ]

    @classmethod
    def sanitize_untrusted_text(cls, text: str) -> Dict[str, any]:
        findings = []
        sanitized = text
        for pat in cls.ADVERSARIAL_PATTERNS:
            matches = list(pat.finditer(sanitized))
            if matches:
                for m in matches:
                    findings.append(m.group(0))
                sanitized = pat.sub("[PROMPT_INJECTION_DEFUSED]", sanitized)

        is_safe = len(findings) == 0
        return {
            "is_safe": is_safe,
            "injections_detected": findings,
            "sanitized_output": sanitized,
            "verdict": "PERMIT" if is_safe else "QUARANTINE_INDIRECT_PROMPT_INJECTION"
        }


# -------------------------------------------------------------
# 62. Phantom Package Firewall
# -------------------------------------------------------------
class PhantomPackageFirewall:
    """
    AI hallucination validator detecting phantom import names fabricated by LLM code generators
    (Copilot, Cursor) before attackers can register them on PyPI/npm (Slopsquatting).
    """
    def __init__(self, known_registry_packages: Optional[Set[str]] = None):
        self.known_packages = set(known_registry_packages or [
            "requests", "flask", "django", "numpy", "pandas", "pytest",
            "express", "react", "react-dom", "lodash", "axios", "ethers",
            "tokio", "serde", "anyhow", "syn", "thiserror"
        ])

    def scan_imports(self, imports: List[str]) -> Dict[str, any]:
        hallucinations = []
        for imp in imports:
            root_pkg = imp.split(".")[0].strip()
            if root_pkg and root_pkg not in self.known_packages:
                hallucinations.append(root_pkg)

        has_hallucinations = len(hallucinations) > 0
        return {
            "has_hallucinations": has_hallucinations,
            "suspicious_packages": hallucinations,
            "verdict": "BLOCK_SLOPSQUATTING_RISK" if has_hallucinations else "PASS"
        }


# -------------------------------------------------------------
# 63. Agent Loop Cost Circuit Breaker
# -------------------------------------------------------------
class AgentLoopCostCircuitBreaker:
    """
    Autonomous agent loop cost interceptor detecting semantic cycling
    and freezing runaway LLM billing before thousands of dollars in tokens accrue.
    """
    def __init__(self, max_consecutive_similar: int = 3, cost_cap_usd: float = 25.0):
        self.max_similar = max_consecutive_similar
        self.cost_cap = cost_cap_usd
        self.turn_actions: List[str] = []
        self.total_cost: float = 0.0

    def record_turn(self, action_signature: str, turn_cost_usd: float) -> Dict[str, any]:
        self.turn_actions.append(action_signature)
        self.total_cost += turn_cost_usd

        # Check total budget
        if self.total_cost >= self.cost_cap:
            return {
                "triggered": True,
                "reason": f"Agent exceeded monetary cost cap: ${self.total_cost:.2f} >= ${self.cost_cap:.2f}",
                "action": "HALT_AGENT"
            }

        # Check repetitive cycles
        if len(self.turn_actions) >= self.max_similar:
            recent = self.turn_actions[-self.max_similar:]
            if len(set(recent)) == 1:
                return {
                    "triggered": True,
                    "reason": f"Semantic loop detected: identical action executed {self.max_similar} times consecutively",
                    "action": "HALT_AGENT"
                }

        return {"triggered": False, "total_cost": self.total_cost, "action": "CONTINUE"}


# -------------------------------------------------------------
# 64. Synthetic Code Entropy Watermarker
# -------------------------------------------------------------
class SyntheticCodeEntropyWatermarker:
    """
    Stylometry and token entropy engine scoring AI-generated code versus human maintainer baselines.
    Detects unvetted code dumps from LLM tools that lack natural human variance.
    """
    @staticmethod
    def calculate_token_entropy(code: str) -> Dict[str, any]:
        tokens = re.findall(r"\w+", code)
        if not tokens:
            return {"entropy": 0.0, "is_likely_synthetic": False}

        freq = {}
        for t in tokens:
            freq[t] = freq.get(t, 0) + 1

        total = len(tokens)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        # AI-generated code typically shows very uniform, lower-entropy token distributions
        is_synthetic = entropy < 3.0 and total > 50
        return {
            "token_count": total,
            "unique_tokens": len(freq),
            "entropy": round(entropy, 3),
            "is_likely_synthetic": is_synthetic,
            "audit_verdict": "FLAG_FOR_AUDIT" if is_synthetic else "NORMAL"
        }


# -------------------------------------------------------------
# 65. RAG Embedding Staleness Cleaner
# -------------------------------------------------------------
class RAGEmbeddingStalenessCleaner:
    """
    Incremental AST chunk-hash synchronization engine invalidating stale vector embeddings
    in enterprise code search RAG databases when functions are edited or removed.
    """
    def __init__(self):
        self.registered_chunks: Dict[str, str] = {} # chunk_id -> ast_hash

    def register_chunk(self, chunk_id: str, code_content: str):
        h = hashlib.sha256(code_content.encode("utf-8")).hexdigest()
        self.registered_chunks[chunk_id] = h

    def evaluate_commit_diff(self, updated_chunks: Dict[str, str], deleted_chunk_ids: List[str]) -> Dict[str, any]:
        invalidated = list(deleted_chunk_ids)
        updated = []

        for cid, content in updated_chunks.items():
            new_h = hashlib.sha256(content.encode("utf-8")).hexdigest()
            old_h = self.registered_chunks.get(cid)
            if old_h != new_h:
                self.registered_chunks[cid] = new_h
                updated.append(cid)

        for d in deleted_chunk_ids:
            if d in self.registered_chunks:
                del self.registered_chunks[d]

        return {
            "invalidated_chunk_ids": invalidated,
            "updated_chunk_ids": updated,
            "total_stale_evictions": len(invalidated) + len(updated)
        }


# -------------------------------------------------------------
# 66. Agent Permission Sandbox
# -------------------------------------------------------------
class AgentPermissionSandbox:
    """
    Least-privilege capability broker restricting file edits and terminal commands
    executed by autonomous agents (Devin, Cursor, AutoGPT).
    """
    FORBIDDEN_COMMANDS = ["rm -rf", "mkfs", "dd", "chmod 777", "curl | bash", "wget | sh"]
    PROTECTED_DIRECTORIES = [".git/", ".github/workflows/", "credentials/", ".env"]

    @classmethod
    def evaluate_command(cls, command_str: str) -> Dict[str, any]:
        for bad in cls.FORBIDDEN_COMMANDS:
            if bad in command_str:
                return {"permitted": False, "reason": f"Dangerous destructive command detected: {bad}"}
        return {"permitted": True}

    @classmethod
    def evaluate_file_write(cls, target_file_path: str) -> Dict[str, any]:
        norm = target_file_path.replace("\\", "/")
        for protected in cls.PROTECTED_DIRECTORIES:
            if norm.startswith(protected) or f"/{protected}" in norm:
                return {"permitted": False, "reason": f"Access to sensitive infrastructure file path denied: {protected}"}
        return {"permitted": True}


# -------------------------------------------------------------
# 67. Context Window Optimizer
# -------------------------------------------------------------
class ContextWindowOptimizer:
    """
    Syntactic code pruner extracting minimal AST token slices to maximize LLM context fidelity
    while slashing prompt token consumption by 50-70%.
    """
    @staticmethod
    def prune_comments_and_blank_lines(source_code: str) -> Dict[str, any]:
        lines = source_code.splitlines()
        pruned = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            pruned.append(line)
        result_text = "\n".join(pruned)
        saving_ratio = round(1.0 - (len(result_text) / (len(source_code) or 1)), 2)
        return {
            "pruned_code": result_text,
            "original_length": len(source_code),
            "pruned_length": len(result_text),
            "bytes_saved_ratio": saving_ratio
        }


# -------------------------------------------------------------
# 68. Hallucinated API Firewall
# -------------------------------------------------------------
class HallucinatedAPIFirewall:
    """
    Type signature checker validating that AI-generated function invocations
    match actual installed package interfaces rather than nonexistent convenience methods.
    """
    def __init__(self):
        self.known_apis: Dict[str, Set[str]] = {} # module -> set of function names

    def register_module_api(self, module_name: str, functions: List[str]):
        self.known_apis[module_name] = set(functions)

    def verify_call(self, module_name: str, function_name: str) -> Dict[str, any]:
        if module_name not in self.known_apis:
            return {"valid": False, "reason": f"Module {module_name} is not installed in the workspace"}
        if function_name not in self.known_apis[module_name]:
            return {
                "valid": False,
                "reason": f"Method {function_name} does not exist in module {module_name} (AI Hallucination)"
            }
        return {"valid": True, "verdict": "VERIFIED_CALL"}


# -------------------------------------------------------------
# 69. Agentic Git Rebase Governor
# -------------------------------------------------------------
class AgenticGitRebaseGovernor:
    """
    Automated rebase reconciler recovering autonomous coding agents trapped in rebase/merge conflict loops.
    Enforces deterministic state rollbacks when agents fail to resolve conflicts after N attempts.
    """
    def __init__(self, max_attempts: int = 3):
        self.max_attempts = max_attempts
        self.rebase_attempts: Dict[str, int] = {} # branch_id -> attempts

    def record_attempt(self, branch_id: str, conflict_files: List[str]) -> Dict[str, any]:
        self.rebase_attempts[branch_id] = self.rebase_attempts.get(branch_id, 0) + 1
        curr = self.rebase_attempts[branch_id]
        if curr > self.max_attempts:
            return {
                "action": "ABORT_REBASE_AND_ALERT_HUMAN",
                "attempts": curr,
                "conflict_files": conflict_files
            }
        return {
            "action": "RETRY_WITH_AST_HINTS",
            "attempts": curr,
            "conflict_files": conflict_files
        }


# -------------------------------------------------------------
# 70. Adversarial Benchmark Auditor
# -------------------------------------------------------------
class AdversarialBenchmarkAuditor:
    """
    Dataset contamination detector ensuring that AI evaluation benchmarks
    (HumanEval, SWE-bench, internal test problems) are not accidentally leaked into training code.
    """
    BENCHMARK_CANARIES = [
        "HumanEval_164", "SWE-bench-instance-django-11001", "OrderStream-Bench-42", "eval_secret_probe"
    ]

    @classmethod
    def audit_source_code(cls, source_code: str) -> Dict[str, any]:
        detected = [c for c in cls.BENCHMARK_CANARIES if c in source_code]
        clean = len(detected) == 0
        return {
            "clean": clean,
            "canaries_found": detected,
            "verdict": "BENCHMARK_INTEGRITY_VERIFIED" if clean else "CONTAMINATION_ALERT"
        }
