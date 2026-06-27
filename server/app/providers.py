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

# server/app/providers.py
# ...keep the earlier parts of the file unchanged up to GeminiProvider...(editado: atualiza para google-genai)

class GeminiProvider(Provider):
    def __init__(self):
        # Try new google.genai first, then fallback to google.generativeai
        try:
            import google.genai as genai  # type: ignore
            self.genai = genai
            self.genai_variant = "genai"
        except Exception:
            try:
                import google.generativeai as genai  # type: ignore
                self.genai = genai
                self.genai_variant = "generativeai"
            except Exception:
                self.genai = None
                self.genai_variant = None
        self.api_key = os.getenv("GEMINI_API_KEY")

    def complete(self, prompt: str, max_tokens: int = 512):
        if not self.genai or not self.api_key:
            return {"result": f"[stubbed Gemini response for prompt length {len(prompt)}]"}

        try:
            # Older package: configure()
            if self.genai_variant == "generativeai":
                if hasattr(self.genai, "configure"):
                    self.genai.configure(api_key=self.api_key)
                # try chat completions path
                if hasattr(self.genai, "chat") and hasattr(self.genai.chat, "completions"):
                    resp = self.genai.chat.completions.create(model="gemini-pro", messages=[{"role":"user","content":prompt}], max_output_tokens=max_tokens)
                elif hasattr(self.genai, "GenerativeModel"):
                    model = self.genai.GenerativeModel("gemini-pro")
                    resp = model.generate_content(prompt)
                else:
                    resp = self.genai.generate(prompt) if hasattr(self.genai, "generate") else {"result": str(self.genai)}
            # New package: try multiple call shapes
            elif self.genai_variant == "genai":
                # try chat completions style first
                if hasattr(self.genai, "chat") and hasattr(self.genai.chat, "completions"):
                    resp = self.genai.chat.completions.create(model="gemini-pro", messages=[{"role":"user","content":prompt}], max_output_tokens=max_tokens)
                elif hasattr(self.genai, "generate_text"):
                    resp = self.genai.generate_text(model="gemini-pro", text=prompt, max_output_tokens=max_tokens)
                elif hasattr(self.genai, "GenerativeModel"):
                    client = self.genai.GenerativeModel("gemini-pro")
                    if hasattr(client, "generate_content"):
                        resp = client.generate_content(prompt)
                    elif hasattr(client, "generate_text"):
                        resp = client.generate_text(prompt)
                    else:
                        resp = {"result": str(client)}
                elif hasattr(self.genai, "generate"):
                    resp = self.genai.generate(model="gemini-pro", prompt=prompt, max_output_tokens=max_tokens)
                else:
                    resp = {"result": str(self.genai)}
            else:
                return {"result": "[gemini provider error: no supported SDK]"}

            # parse response generically
            content = ""
            if isinstance(resp, dict):
                choices = resp.get("candidates") or resp.get("choices") or []
                if choices:
                    # choose first candidate/content if present
                    first = choices[0]
                    if isinstance(first, dict):
                        content = first.get("content") or first.get("text") or str(first)
                    else:
                        content = str(first)
                else:
                    # maybe direct keys
                    content = resp.get("result") or resp.get("output") or str(resp)
            else:
                # try attribute-based parsing
                try:
                    if hasattr(resp, "candidates") and resp.candidates:
                        content = resp.candidates[0].content
                    elif hasattr(resp, "choices") and len(resp.choices) > 0:
                        ch = resp.choices[0]
                        if hasattr(ch, "message"):
                            msg = ch.message
                            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", str(msg))
                        else:
                            content = getattr(ch, "text", str(ch))
                    else:
                        content = str(resp)
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
