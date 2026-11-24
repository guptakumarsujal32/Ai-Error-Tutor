"""Defensive Red-Team Attacker Agent for AI Error Tutor.

Generates and manages test attack programs to rigorously validate
the Ingress Security Gate and Execution Sandbox.
Designed to work safely with small local models (qwen2.5-coder:3b).
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional

import config
from llm.ollama_client import ask_llm, wrap_code, LLMError

logger = logging.getLogger("AttackerAgent")


class AttackerAgent:
    """Defensive red-team agent that supplies seed attacks and mutations."""

    def __init__(self, seeds_file: Optional[str] = None):
        self.model_name = config.MODELS.get("attacker", "qwen2.5-coder:3b")
        self.seeds_path = seeds_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "attacks",
            "seed_attacks.json"
        )
        self.seeds = self.load_seeds()

    def load_seeds(self, path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load curated seed attacks from JSON library."""
        target_path = path or self.seeds_path
        if not os.path.exists(target_path):
            logger.warning(f"Seed attacks file not found at {target_path}")
            return []
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"Failed to read seed attacks: {e}")
            return []

    def get_categories(self) -> List[str]:
        """Return list of distinct attack categories in the seed catalog."""
        cats = [s.get("category", "unknown") for s in self.seeds]
        return sorted(list(set(cats)))

    def generate_variants(self, seed: Dict[str, Any], n: int = 1) -> List[Dict[str, Any]]:
        """
        Generate n mutated variations of a seed attack using the local LLM.
        Clamped to a maximum of 3 variants (default 1).
        Fail-safe: skips failed/timed-out variants silently without crashing.

        Args:
            seed: Base attack seed dictionary
            n: Number of mutations to attempt (1 to 3)

        Returns:
            List of successfully generated attack variants.
        """
        # Clamp n between 1 and 3
        count = max(1, min(int(n or 1), 3))
        variants: List[Dict[str, Any]] = []

        system_prompt = (
            "You are a defensive security testing tool. "
            "Generate a subtle mutation of the following Python snippet by renaming variables, "
            "splitting strings with concatenation, or changing syntax layout. "
            "Respond ONLY with a JSON object.\n"
            "Example JSON schema:\n"
            '{"variant_code": "a = \'o\'\\nb = \'s\'\\nprint(a + b)"}'
        )

        for i in range(1, count + 1):
            try:
                user_content = f"Mutate this snippet (Variant {i}):\n{wrap_code(seed.get('code', ''))}"
                response = ask_llm(
                    role="attacker",
                    system_prompt=system_prompt,
                    user_content=user_content,
                    temperature=0.2,
                    force_provider="ollama",
                    use_cache=False,
                )

                variant_code = response.get("variant_code") or response.get("code")
                if not variant_code or not str(variant_code).strip():
                    logger.warning(f"Empty code in variant {i} for {seed.get('id')}; skipping.")
                    continue

                variants.append({
                    "id": f"{seed.get('id')}-VAR{i}",
                    "parent_id": seed.get("id"),
                    "category": seed.get("category", "general"),
                    "title": f"{seed.get('title', 'Attack')} (Variant {i})",
                    "code": str(variant_code).strip(),
                    "should_be_blocked": True,
                    "is_variant": True,
                    "description": f"Mutated variant {i} of {seed.get('id')}."
                })
            except (LLMError, Exception) as e:
                # Never crash the round on LLM parsing or timeout error
                print(f"[WARN] Attacker LLM variant generation skipped for {seed.get('id')} (Var {i}): {e}")
                logger.warning(f"Variant generation failed for {seed.get('id')}: {e}")
                continue

        return variants

    def prepare_attack_set(
        self,
        include_variants: bool = False,
        n_variants: int = 1,
        progress_callback=None
    ) -> List[Dict[str, Any]]:
        """
        Prepare attack test suite consisting of all seed attacks and optional LLM variants.

        Args:
            include_variants: If False (fast mode), only seed attacks are returned.
            n_variants: Number of variants to generate per seed (1 to 3).
            progress_callback: Optional callable(step, total, msg) for UI progress tracking.

        Returns:
            List of attack test objects ready for execution.
        """
        all_attacks: List[Dict[str, Any]] = list(self.seeds)
        if not include_variants:
            return all_attacks

        total_seeds = len(self.seeds)
        for idx, seed in enumerate(self.seeds):
            if progress_callback:
                progress_callback(
                    idx + 1,
                    total_seeds,
                    f"Generating variants with {self.model_name} for '{seed.get('id')}'..."
                )
            vars_list = self.generate_variants(seed, n=n_variants)
            all_attacks.extend(vars_list)

        return all_attacks
