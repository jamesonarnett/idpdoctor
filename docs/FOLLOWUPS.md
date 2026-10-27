# Follow-ups noticed during the v1 walkthrough (2026-10-27)

- Symptom templates are chosen per class, so an `expired` (NotOnOrAfter) mutation can carry a NotBefore symptom
  ("Current time is earlier than NotBefore condition"). Realistic as user misreporting, but the generator should
  prefer a template matching the sub-mutator when one exists and tag the case `symptom_match: exact|class|misleading`
  so the report can split accuracy by symptom quality. (v2)
- JWT/OIDC/OAuth classes have no symptom templates (symptom.txt is empty for `jwt_expired_or_not_yet_valid`), so the
  LLM arms see SAML cases with a ticket-like symptom and token cases without one. Add vendor strings for the token
  classes (Entra AADSTS700024 "token expired", Auth0 "jwt expired", Okta "The token has expired", Google "Token used
  too late") to `evals/symptom_templates/vendor_strings.json`. (v1.1, before the full benchmark)
