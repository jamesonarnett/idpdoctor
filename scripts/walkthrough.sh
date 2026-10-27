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
  3b) C=/tmp/mini/cases/${2:-saml_time_window_invalid-00}; echo "--- label ---"; cat $C/label.json; echo; echo "--- diagnose ---"
      ART=$(ls $C | grep -vE 'json$' | head -1)
      $B diagnose -f $C/$ART --sp-entity-id "$(json $C/params.json sp_entity_id)" --now "$(json $C/params.json now)" || true ;;
  4)  $B jwt validate -f testdata/jwt/jwt_expired/token.txt --issuer https://login.example.com/tenant-1/v2.0 --client-id client-abc123 --now $NOW || true
      echo; echo "--- oidc case dirs ---"; ls testdata/oidc; echo "--- oauth case dirs ---"; ls testdata/oauth ;;
  6)  $B diagnose -f $AUD/response.xml --sp-entity-id $SP --now $NOW --symptom "Okta login works but our SP says Invalid audience" --explain --explain-mode tools-on ;;
  6b) $B diagnose -f $AUD/response.xml --sp-entity-id $SP --now $NOW --symptom "Okta login works but our SP says Invalid audience" --explain --explain-mode tools-off ;;
  7)  echo "open http://127.0.0.1:7777  (Ctrl-C to stop)"; $B web --addr 127.0.0.1:7777 ;;
  10) $B bundle --redacted -f $AUD/response.xml --sp-entity-id $SP --out /tmp/ticket.zip && unzip -l /tmp/ticket.zip ;;
  *)  sed -n '2,4p' "$0" ;;
esac
