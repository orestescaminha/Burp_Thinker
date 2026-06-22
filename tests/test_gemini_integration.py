import os
from server.app.gemini_integration import GeminiResponseParser, GeminiClient

def test_try_extract_json_plain():
    text = '{"a":1, "b":"x"}'
    parsed = GeminiResponseParser.try_extract_json(text)
    assert isinstance(parsed, dict)
    assert parsed["a"] == 1

def test_try_extract_json_markdown_block():
    text = "```json\n{\"a\":2}\n```"
    parsed = GeminiResponseParser.try_extract_json(text)
    assert isinstance(parsed, dict)
    assert parsed["a"] == 2

def test_try_extract_json_invalid():
    text = "not json at all"
    parsed = GeminiResponseParser.try_extract_json(text)
    assert parsed is None

def test_gemini_client_stub_behavior(monkeypatch):
    # Ensure GEMINI not available path: unset env key
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    client = GeminiClient()
    out = client.generate("Hello world", max_tokens=10)
    assert isinstance(out, dict)
    assert out.get("status") == "stub"
    assert "Gemini stub" in out.get("result", "")
