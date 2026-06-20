import os
from abc import ABC, abstractmethod

class Provider(ABC):
    @abstractmethod
    def complete(self, prompt: str, max_tokens: int = 512):
        """Return a dict like {'result': '...'}"""
        pass

class OpenAIProvider(Provider):
    def __init__(self):
        try:
            import openai
            self.openai = openai
        except Exception:
            self.openai = None
        self.api_key = os.getenv("OPENAI_API_KEY")

    def complete(self, prompt: str, max_tokens: int = 512):
        if not self.openai or not self.api_key:
            return {"result": f"[stubbed OpenAI response for prompt length {len(prompt)}]"}
        try:
            self.openai.api_key = self.api_key
            # adapt to the installed openai SDK; prefer ChatCompletion but keep fallback
            if hasattr(self.openai, "ChatCompletion"):
                resp = self.openai.ChatCompletion.create(model="gpt-4o-mini", messages=[{"role":"user","content":prompt}], max_tokens=max_tokens)
                # different SDK versions return different shapes
                content = ""
                if hasattr(resp, "choices") and len(resp.choices) > 0:
                    ch = resp.choices[0]
                    if hasattr(ch, "message"):
                        content = ch.message.get("content") if isinstance(ch.message, dict) else ch.message.content
                    else:
                        content = getattr(ch, "text", "")
                else:
                    content = getattr(resp, "text", str(resp))
                return {"result": content}
            else:
                # legacy completion
                resp = self.openai.Completion.create(engine="text-davinci-003", prompt=prompt, max_tokens=max_tokens)
                return {"result": resp.choices[0].text}
        except Exception as e:
            return {"result": f"[openai provider error: {e}]"}

class ClaudeProvider(Provider):
    def __init__(self):
        try:
            import anthropic
            self.anthropic = anthropic
        except Exception:
            self.anthropic = None
        self.api_key = os.getenv("ANTHROPIC_API_KEY")

    def complete(self, prompt: str, max_tokens: int = 512):
        if not self.anthropic or not self.api_key:
            return {"result": f"[stubbed Claude response for prompt length {len(prompt)}]"}
        try:
            client = self.anthropic.Client(api_key=self.api_key)
            # The exact call depends on the anthropic SDK version; try common patterns
            try:
                resp = client.completions.create(model="claude-2.1", prompt=prompt, max_tokens_to_sample=max_tokens)
                text = getattr(resp, "completion", resp.get("completion", str(resp)))
            except Exception:
                resp = client.create_completion(prompt=prompt, model="claude-2.1", max_tokens_to_sample=max_tokens)
                text = resp.get("completion", str(resp))
            return {"result": text}
        except Exception as e:
            return {"result": f"[claude provider error: {e}]"}

class GeminiProvider(Provider):
    def __init__(self):
        # google generative ai client (google-generativeai)
        try:
            import google.generativeai as genai
            self.genai = genai
        except Exception:
            self.genai = None
        self.api_key = os.getenv("GEMINI_API_KEY")

    def complete(self, prompt: str, max_tokens: int = 512):
        if not self.genai or not self.api_key:
            return {"result": f"[stubbed Gemini response for prompt length {len(prompt)}]"}
        try:
            self.genai.configure(api_key=self.api_key)
            # example using chat.completions (API can vary)
            resp = self.genai.chat.completions.create(model="gemini-pro", messages=[{"role":"user","content":prompt}], max_output_tokens=max_tokens)
            # parse response
            content = ""
            if isinstance(resp, dict):
                choices = resp.get("candidates") or resp.get("choices") or []
                if choices:
                    content = choices[0].get("content", "")
                else:
                    content = str(resp)
            else:
                try:
                    content = resp.candidates[0].content
                except Exception:
                    content = str(resp)
            return {"result": content}
        except Exception as e:
            return {"result": f"[gemini provider error: {e}]"}

class LocalLLMProvider(Provider):
    def complete(self, prompt: str, max_tokens: int = 512):
        return {"result": f"[local-llm-stub response for prompt len {len(prompt)}]"}

class ProviderFactory:
    def __init__(self):
        self.providers = {
            "openai": OpenAIProvider(),
            "claude": ClaudeProvider(),
            "gemini": GeminiProvider(),
            "local": LocalLLMProvider()
        }
    def get(self, name="openai"):
        return self.providers.get(name, self.providers["local"])
