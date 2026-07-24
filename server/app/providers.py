import os
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

class Provider(ABC):
    @abstractmethod
    def complete(self, prompt: str, max_tokens: int = 2048):
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

    def complete(self, prompt: str, max_tokens: int = 2048):
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

    def complete(self, prompt: str, max_tokens: int = 2048):
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
        self.genai = None
        try:
            # Explicitly import the stable library to avoid conflicts
            import google.generativeai as genai
            self.genai = genai
            logger.info("Successfully imported google.generativeai SDK.")
        except ImportError:
            logger.error("Failed to import google.generativeai. Make sure 'google-generativeai' is installed.")
        
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("GEMINI_API_KEY environment variable not found.")
        else:
            logger.info("GEMINI_API_KEY loaded.")
            
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-pro-latest")

    def complete(self, prompt: str, max_tokens: int = 4096):
        if not self.genai or not self.api_key:
            return {"result": f"[stubbed Gemini response: Gemini SDK or API key not configured]"}

        try:
            # Use the configure() and GenerativeModel() pattern for the google.generativeai library
            self.genai.configure(api_key=self.api_key)
            
            generation_config = self.genai.types.GenerationConfig(
                max_output_tokens=max_tokens
            )
            model = self.genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=generation_config
            )
            
            response = model.generate_content(prompt)
            result_text = response.text
            return {"result": result_text}
        except Exception as e:
            return {"result": f"[gemini provider error: {e}]"}

class LocalLLMProvider(Provider):
    def complete(self, prompt: str, max_tokens: int = 2048):
        return {"result": f"[local-llm-stub response for prompt len {len(prompt)}]"}

class ProviderFactory:
    def __init__(self):
        self.provider_classes = {
            "openai": OpenAIProvider,
            "claude": ClaudeProvider,
            "gemini": GeminiProvider,
            "local": LocalLLMProvider
        }
        self.providers_cache = {}

    def get(self, name=None):
        if name is None:
            name = os.getenv("BURP_THINKER_PROVIDER", "gemini")
        
        if name in self.providers_cache:
            return self.providers_cache[name]

        provider_class = self.provider_classes.get(name)
        if provider_class:
            instance = provider_class()
            self.providers_cache[name] = instance
            return instance
        
        # Fallback to gemini if the name is invalid
        logger.warning(f"Provider '{name}' not found, falling back to 'gemini'.")
        return self.get("gemini")
