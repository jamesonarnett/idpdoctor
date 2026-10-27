#!/bin/sh
# Fake `claude` for tests. Records argv, stdin and whether any banned env
# var reached it, then prints a canned envelope chosen by FAKE_CLAUDE_MODE.
# Never contacts anything.
set -u
out="${FAKE_CLAUDE_RECORD:-/dev/null}"
{
  printf 'ARGS:'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'
  printf 'KEY:%s\n' "${ANTHROPIC_API_KEY:-unset}"
  printf 'TOKEN:%s\n' "${ANTHROPIC_AUTH_TOKEN:-unset}"
  printf 'CWD:%s\n' "$(pwd)"
  printf 'STDIN:'; cat; printf '\n'
} > "$out"
case "${FAKE_CLAUDE_MODE:-success}" in
  success)
    cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"duration_ms":1234,"duration_api_ms":1000,"num_turns":3,"result":"done","session_id":"fake","total_cost_usd":0.0123,"usage":{"input_tokens":100,"cache_creation_input_tokens":200,"cache_read_input_tokens":300,"output_tokens":40},"modelUsage":{"claude-sonnet-4-5":{"inputTokens":100,"outputTokens":40,"cacheReadInputTokens":300,"cacheCreationInputTokens":200,"costUSD":0.0123,"costBasis":"list"}},"permission_denials":[],"stop_reason":"end_turn","structured_output":{"root_cause_code":"SAML_AUDIENCE_MISMATCH","confidence":0.9,"evidence":[{"path":"/Response/Assertion/Conditions/AudienceRestriction/Audience","actual":"https://sp.example.com/saml/metadata/","expected":"https://sp.example.com/saml/metadata","note":"trailing slash"},{"path":"/Response/Made/Up","actual":"x"}],"fix":"Set the Audience URI in the IdP app to the SP entity ID exactly.","alternatives":[{"code":"SAML_ISSUER_MISMATCH","why_not":"issuer check passed"}],"questions":[]}}
JSON
    ;;
  checkname)
    cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"duration_ms":1234,"duration_api_ms":1000,"num_turns":3,"result":"done","session_id":"fake","total_cost_usd":0.0123,"usage":{"input_tokens":100,"cache_creation_input_tokens":200,"cache_read_input_tokens":300,"output_tokens":40},"modelUsage":{"claude-sonnet-4-5":{"inputTokens":100,"outputTokens":40,"cacheReadInputTokens":300,"cacheCreationInputTokens":200,"costUSD":0.0123,"costBasis":"list"}},"permission_denials":[],"stop_reason":"end_turn","structured_output":{"root_cause_code":"SAML_AUDIENCE_MISMATCH","confidence":0.9,"evidence":[{"path":"/Response/Assertion/Conditions/AudienceRestriction/Audience","actual":"https://sp.example.com/saml/metadata/","expected":"https://sp.example.com/saml/metadata"},{"path":"checks/audience","actual":"fail"},{"path":"issuer","actual":"pass"},{"path":"/Response/Made/Up","actual":"x"}],"fix":"Set the Audience URI in the IdP app to the SP entity ID exactly.","alternatives":[],"questions":[]}}
JSON
    ;;
  healthy)
    cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"duration_ms":900,"num_turns":2,"result":"ok","total_cost_usd":0.005,"usage":{"input_tokens":50,"output_tokens":20},"permission_denials":[],"structured_output":{"root_cause_code":"HEALTHY","confidence":0.95,"evidence":[],"fix":"No change needed.","posture_codes":["POSTURE_EMBEDDED_KEY_TRUST"]}}
JSON
    ;;
  malformed)
    printf 'Please run /login first\n'
    exit 1
    ;;
  denial)
    cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"duration_ms":10,"num_turns":2,"result":"","total_cost_usd":0.001,"usage":{"input_tokens":1,"output_tokens":1},"permission_denials":[{"tool_name":"Bash","tool_input":{"command":"ls"}}],"structured_output":{"root_cause_code":"UNKNOWN","confidence":0.1,"evidence":[],"fix":""}}
JSON
    ;;
  error)
    cat <<'JSON'
{"type":"result","subtype":"error_max_turns","is_error":true,"duration_ms":10,"num_turns":9,"result":"Reached max turns","total_cost_usd":0.2,"usage":{"input_tokens":1,"output_tokens":1},"permission_denials":[]}
JSON
    ;;
  nostructured)
    cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"duration_ms":10,"num_turns":2,"result":"prose only","total_cost_usd":0.001,"usage":{"input_tokens":1,"output_tokens":1},"permission_denials":[]}
JSON
    ;;
  timeout)
    sleep 30
    ;;
  judge)
    cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"duration_ms":800,"num_turns":2,"result":"","total_cost_usd":0.02,"usage":{"input_tokens":400,"output_tokens":60},"modelUsage":{"claude-opus-4-1":{"inputTokens":400,"outputTokens":60,"costUSD":0.02,"costBasis":"list"}},"permission_denials":[],"structured_output":{"evidence_correct":true,"fix_score":4,"fix_is_security_regression":false,"rationale":"cites the audience path; fix names the exact entity ID"}}
JSON
    ;;
  *)
    echo "unknown FAKE_CLAUDE_MODE" >&2; exit 2;;
esac
