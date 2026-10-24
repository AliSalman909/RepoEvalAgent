"""Gemini client: transcript conversion, response parsing and error mapping (offline, no API calls)."""

import pytest
from google.genai import errors, types

from auditor.llm import GeminiClient, LLMConfigError, LLMError, _map_api_error
from tools import INSPECTION_TOOL_SCHEMAS

TEST_MODEL = "test-model-from-env"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("GEMINI_MODEL", TEST_MODEL)
    monkeypatch.delenv("GEMINI_THINKING_LEVEL", raising=False)
    return GeminiClient()


def _response(parts, finish="STOP"):
    return types.GenerateContentResponse(
        candidates=[types.Candidate(content=types.Content(role="model", parts=parts), finish_reason=finish)],
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=100, candidates_token_count=20, thoughts_token_count=7),
    )


def test_model_and_thinking_come_from_env(monkeypatch, client):
    assert client.model == TEST_MODEL and client.thinking_level is None  # nothing hardcoded
    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "High")
    assert GeminiClient().thinking_level == "high"
    assert GeminiClient(model="cli-model").model == "cli-model"  # --model overrides the env


def test_missing_key(monkeypatch, client):
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(LLMConfigError, match="GEMINI_API_KEY"):
        GeminiClient()


@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_model_is_a_config_error(monkeypatch, value):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    if value is None:
        monkeypatch.delenv("GEMINI_MODEL", raising=False)
    else:
        monkeypatch.setenv("GEMINI_MODEL", value)
    with pytest.raises(LLMConfigError, match="GEMINI_MODEL is not set"):
        GeminiClient()


def test_tool_schemas_convert_to_function_declarations(client):
    from auditor.findings import RECORD_VIOLATION_SCHEMA
    tools = client._tools(INSPECTION_TOOL_SCHEMAS + [RECORD_VIOLATION_SCHEMA])
    names = [d.name for d in tools[0].function_declarations]
    assert names[:4] == ["list_files", "read_file", "search_code", "git_log"] and "record_violation" in names
    # the nullable file/line fields survive as plain JSON schema
    rec = tools[0].function_declarations[-1].parameters_json_schema
    assert rec["properties"]["file"]["type"] == ["string", "null"]


def test_function_calls_parsed_and_model_content_kept_verbatim(client):
    call = types.Part(function_call=types.FunctionCall(id="c1", name="read_file", args={"path": "a.py"}),
                      thought_signature=b"sig-123")
    resp = client.parse_response(_response([types.Part(text="Let me look."), call]))
    assert resp.stop_reason == "tool_use"
    assert [(c.id, c.name, c.input) for c in resp.tool_calls] == [("c1", "read_file", {"path": "a.py"})]
    assert resp.text == "Let me look."
    assert resp.usage == {"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 0, "thinking_tokens": 7}
    # re-sending the transcript gives back the identical Content, thought signature included
    contents = client.to_contents([{"role": "user", "content": "go"}, {"role": "assistant", "raw": resp.raw_content}])
    assert contents[1] is resp.raw_content and contents[1].parts[1].thought_signature == b"sig-123"


def test_missing_call_id_gets_generated(client):
    resp = client.parse_response(_response([types.Part(function_call=types.FunctionCall(name="list_files", args={}))]))
    assert resp.tool_calls[0].id.startswith("call_")


def test_thought_parts_are_not_reported_as_text(client):
    resp = client.parse_response(_response([types.Part(text="secret reasoning", thought=True), types.Part(text="Done.")]))
    assert resp.text == "Done." and resp.stop_reason == "end_turn"


def test_tool_results_become_function_responses_with_id_and_name(client):
    contents = client.to_contents([{"role": "tool", "note": "[turn 1/5]", "results": [
        {"id": "c1", "name": "read_file", "content": "file text", "is_error": False},
        {"id": "c2", "name": "search_code", "content": "bad regex", "is_error": True},
    ]}])
    parts = contents[0].parts
    assert contents[0].role == "user"
    assert (parts[0].function_response.id, parts[0].function_response.name) == ("c1", "read_file")
    assert parts[0].function_response.response == {"output": "file text"}
    assert parts[1].function_response.response == {"error": "bad regex"}
    assert parts[2].text == "[turn 1/5]"


@pytest.mark.parametrize("finish, expected", [
    ("SAFETY", "refusal"), ("PROHIBITED_CONTENT", "refusal"), ("MAX_TOKENS", "max_tokens"),
    ("MALFORMED_FUNCTION_CALL", "malformed_tool_call"), ("STOP", "end_turn"),
])
def test_finish_reasons_normalised(client, finish, expected):
    assert client.parse_response(_response([types.Part(text="x")], finish)).stop_reason == expected


def test_blocked_prompt_is_a_refusal(client):
    resp = types.GenerateContentResponse(
        candidates=[], prompt_feedback=types.GenerateContentResponsePromptFeedback(block_reason="SAFETY"))
    assert client.parse_response(resp).stop_reason == "refusal"


def test_empty_content_keeps_transcript_valid(client):
    resp = client.parse_response(types.GenerateContentResponse(
        candidates=[types.Candidate(content=None, finish_reason="STOP")]))
    assert resp.raw_content.parts and resp.stop_reason == "end_turn"


@pytest.mark.parametrize("code, message, cls, text", [
    (400, "API key not valid. Please pass a valid API key.", LLMConfigError, "credentials"),
    (403, "Permission denied", LLMConfigError, "credentials"),
    (404, "models/gemini-x is not found", LLMConfigError, "not found"),
    (429, "Resource exhausted", LLMError, "rate limited"),
    (400, "Invalid argument", LLMError, "rejected the request"),
    (503, "Unavailable", LLMError, "503"),
])
def test_api_errors_mapped(code, message, cls, text):
    exc = errors.APIError(code, {"error": {"code": code, "message": message, "status": "X"}})
    mapped = _map_api_error(exc, "gemini-x")
    assert type(mapped) is cls and text in str(mapped)


def test_complete_maps_sdk_errors(client, monkeypatch):
    def boom(**kwargs):
        raise errors.ClientError(404, {"error": {"code": 404, "message": "model not found", "status": "NOT_FOUND"}})
    monkeypatch.setattr(client._client.models, "generate_content", boom)
    with pytest.raises(LLMConfigError, match="not found"):
        client.complete("sys", [{"role": "user", "content": "hi"}], INSPECTION_TOOL_SCHEMAS)


def test_complete_sends_expected_request(client, monkeypatch):
    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        return _response([types.Part(text="ok")])
    monkeypatch.setattr(client._client.models, "generate_content", fake)
    client.complete("system prompt", [{"role": "user", "content": "hi"}], INSPECTION_TOOL_SCHEMAS)
    cfg = seen["config"]
    assert seen["model"] == TEST_MODEL
    assert cfg.system_instruction == "system prompt"
    assert cfg.automatic_function_calling.disable is True   # we own the loop
    assert cfg.thinking_config is None                      # not sent unless GEMINI_THINKING_LEVEL is set


def test_thinking_level_sent_when_configured(monkeypatch, client):
    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "low")
    c = GeminiClient()
    seen = {}
    monkeypatch.setattr(c._client.models, "generate_content",
                        lambda **kw: seen.update(kw) or _response([types.Part(text="ok")]))
    c.complete("s", [{"role": "user", "content": "hi"}], INSPECTION_TOOL_SCHEMAS)
    assert str(seen["config"].thinking_config.thinking_level).upper().endswith("LOW")
