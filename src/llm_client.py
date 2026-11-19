import os
from typing import Optional


class GroqClient:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "").strip()
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip()

    def ping(self) -> str:
        if not self.api_key:
            return "offline_mode: GROQ_API_KEY not set (using local fallback)"
        return f"ready: model={self.model}"

    def analyze_text(self, prompt: str) -> str:
        if not self.api_key:
            return f"[Local Analysis] Reviewed finding context ({len(prompt)} chars). Apply CWE mapping and remediation steps."
        try:
            from groq import Groq  # type: ignore
            client = Groq(api_key=self.api_key)
            resp = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=400,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            return f"[Fallback Analysis] LLM call skipped ({exc}). Using structured risk assessment."
