# Symptom templates

`idpdoctor eval gen` reads every `*.json` file in this directory. Each file
is a map from catalog code to a list of symptom strings; a case drawn for
that code gets one of them as its `symptom.txt` about 70% of the time (the
rest get no symptom, like many real tickets). `meta.json` records which
file the symptom came from, so results can be split by source.

- `vendor_strings.json`: the public vendor error strings from BUILD_PLAN
  section 3 (Okta, Entra AADSTS, Google, Snowflake, GitLab, GitHub, Auth0,
  WorkOS, Scalekit), lightly paraphrased into ticket form.
- `realworld.json`: not written yet. 3-5 anonymized
  symptom templates from real support tickets, each filed under an existing
  catalog code, no tenant names, no user identifiers, no hostnames other
  than example.com. The file does not exist yet; `eval gen` works without it
  and will pick the templates up on the next regeneration.

Format:

```json
{
  "SAML_AUDIENCE_MISMATCH": [
    "Okta shows the user as signed in but our app says Invalid audience."
  ]
}
```
