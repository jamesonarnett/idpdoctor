#!/bin/zsh
# One short command per WALKTHROUGH.md step: ./scripts/walkthrough.sh <step>
# Steps: 1 decode | 2 diagnose | 2b diagnose+cert | 3 mint | 3b diagnose-minted | 4 jwt-oidc-oauth
#        6 explain-on | 6b explain-off | 7 web | 10 bundle
set -e
cd "$(dirname "$0")/.."
B=./bin/idpdoctor
AUD=testdata/saml/audience_mismatch
SP=https://sp.example.com/saml/metadata
NOW=2026-01-15T12:00:00Z
json() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
case "${1:-}" in
  1)  $B saml decode -f testdata/saml/healthy_okta/response.xml ;;
  2)  $B diagnose -f $AUD/response.xml --sp-entity-id $SP --now $NOW; echo "exit=$?" ;;
  2b) json $AUD/params.json idp_cert_pem > /tmp/idp.pem
      $B diagnose -f $AUD/response.xml --sp-entity-id $SP --now $NOW --idp-cert /tmp/idp.pem; echo "exit=$?" ;;
  3)  $B eval gen --seed 7 --per-class 1 --controls 2 --out /tmp/mini; ls /tmp/mini/cases ;;
  3b) C=/tmp/mini/cases/${2:-saml_time_window_invalid-00}; echo "--- label (the truth) ---"; cat $C/label.json; echo
      echo "--- symptom the user would report ---"; cat $C/symptom.txt; echo; echo "--- diagnose with the case's expected values ---"
      ART=$(ls $C | grep -vE 'json$|txt$' | head -1); [ -z "$ART" ] && ART=artifact.txt
      python3 - "$C" "$B" "$ART" <<'PY'
import json, subprocess, sys, tempfile, os
c, b, art = sys.argv[1:4]; e = json.load(open(f"{c}/expected.json"))
args = [b, "diagnose", "-f", f"{c}/{art}"]
for k, f in [("sp_entity_id","--sp-entity-id"),("acs_url","--acs-url"),("idp_entity_id","--idp-entity-id"),("now","--now"),
             ("issuer","--issuer"),("client_id","--client-id"),("redirect_uri","--redirect-uri"),("nonce","--nonce"),("request_id","--request-id")]:
    if e.get(k): args += [f, str(e[k])]
if e.get("idp_cert_pem"):
    t = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False); t.write(e["idp_cert_pem"]); t.close(); args += ["--idp-cert", t.name]
if e.get("jwks"):
    t = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(e["jwks"], t); t.close(); args += ["--jwks", t.name]
r = subprocess.run(args); print(f"exit={r.returncode}")
PY
      ;;
  4)  $B jwt validate -f testdata/jwt/jwt_expired/token.txt --issuer https://login.example.com/tenant-1/v2.0 --client-id client-abc123 --now $NOW || true
      echo; echo "--- oidc case dirs ---"; ls testdata/oidc; echo "--- oauth case dirs ---"; ls testdata/oauth ;;
  6)  $B diagnose -f $AUD/response.xml --sp-entity-id $SP --now $NOW --symptom "Okta login works but our SP says Invalid audience" --explain --explain-mode tools-on ;;
  6b) $B diagnose -f $AUD/response.xml --sp-entity-id $SP --now $NOW --symptom "Okta login works but our SP says Invalid audience" --explain --explain-mode tools-off ;;
  7)  echo "open http://127.0.0.1:7777  (Ctrl-C to stop)"; $B web --addr 127.0.0.1:7777 ;;
  10) $B bundle --redacted -f $AUD/response.xml --sp-entity-id $SP --out /tmp/ticket.zip && unzip -l /tmp/ticket.zip ;;
  *)  sed -n '2,4p' "$0" ;;
esac
