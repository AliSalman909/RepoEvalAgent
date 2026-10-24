import pytest

from auditor.redact import contains_unredacted_secret, redact


@pytest.mark.parametrize("text, secret", [
    ('API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"', "abcdefghijklmnopqrstuvwxyz123456"),
    ("aws_access_key_id = AKIAZZZZZZZZZZZZZZZZ", "AKIAZZZZZZZZZZZZZZZZ"),
    ('password = "hunter2xyz"', "hunter2xyz"),
    ("db_password: hunter2", "hunter2"),
    ("DATABASE_URL=postgres://admin:S3cretPass@db:5432/app", "S3cretPass"),
    ("GITHUB_TOKEN=ghp_" + "x1" * 18, "ghp_" + "x1" * 18),
    ('{"client_secret": "abcd1234efgh5678"}', "abcd1234efgh5678"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "MIIEpAIBAAKCAQEA"),
])
def test_secrets_are_masked(text, secret):
    out = redact(text)
    assert secret not in out
    assert "REDACTED" in out
    assert contains_unredacted_secret(text)


@pytest.mark.parametrize("text", [
    'password = os.environ["DB_PASSWORD"]',
    "token: ${{ secrets.GITHUB_TOKEN }}",
    'SECRET_KEY = "changeme"',
    "api_key = settings.API_KEY",
    "def get_token(token): return token",
    'API_KEY="your-api-key-here"',
    "password = None",
])
def test_references_and_placeholders_are_kept(text):
    assert redact(text) == text


@pytest.mark.parametrize("text", [
    # provider token formats (caught anywhere, regardless of variable name)
    "x = gho_" + "a" * 36, "GITLAB=glpat-" + "A1b2" * 5, "NPM_TOKEN=npm_" + "a1B2" * 9, "HF=hf_" + "Ab1" * 12,
    "GROQ=gsk_" + "a1" * 22, 'x = "GOCSPX-' + "a1B2" * 7 + '"', "dop_v1_" + "a1" * 32,
    "SG." + "a" * 22 + "." + "b" * 43, "SK" + "a1" * 16, "key-" + "a1B2" * 8, "a1" * 16 + "-us14",
    "123456789:AA" + "b" * 33, "shpat_" + "a1" * 16, "r8_" + "a" * 37, "dapi" + "a1" * 16,
    "sk-svcacct-" + "a1B2" * 6,
    # context-dependent secrets
    "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + "Ab1+" * 22 + "==;",
    "Authorization: Bearer abc123DEF456ghi789JKL",
    'curl -H "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw=="',
    "/".join(("https:", "", "hooks.slack.com", "services", "T0123ABCD", "B0123ABCD",
              "abcdefghijklmnopqrstuvwx")),
    "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123",
    # bare / suffixed `key` names with token-like values
    'key = "a1b2c3d4e5f6g7h8i9j0"', '"key": "9f8e7d6c5b4a39281706f5e4d3c2b1a0"', 'hmac_key = "Zx9Yw8Vu7Ts6Rq5Po4Nm"',
    "signingKey: q8W3e7R1t5Y9u2I6o4P0",
    # names followed by a closing quote/bracket before `=`
    'cfg["api_key"] = "abcd1234efgh5678"', 'cfg["key"] = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"',
])
def test_extended_secret_formats_are_masked(text):
    assert "REDACTED" in redact(text)


@pytest.mark.parametrize("text", [
    'cache_key = "user_profile_settings_v2"', 'cacheKey = "a1b2c3d4e5f6g7h8i9"',
    'public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"', 'primary_key = "customer_id_2024_main"',
    'sort_key = "created_at_2024_desc"', 'key = "user_profile_settings_v2"', 'key = "short1"',
    "key = settings.API_KEY", "key: ${{ secrets.DEPLOY_KEY }}", 'key = os.environ["KEY"]',
    'monkey = "abc123def456ghi789jkl"',
    # DevOps evidence the agent must still be able to read
    "uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
    "FROM python@sha256:3a1f9e0b7c6d5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a09",
    "Basic configuration_management is described below", "Use a Bearer token from the environment",
])
def test_harmless_values_are_not_masked(text):
    assert redact(text) == text


def test_redaction_is_idempotent():
    once = redact('token = "abcdef1234567890"')
    assert redact(once) == once
