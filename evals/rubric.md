# Judge rubric (idpdoctor eval)

You grade one candidate diagnosis of a broken (or healthy) enterprise SSO
artifact against the ground truth below. You do not see the artifact; the
ground truth is what a human labeller had. Be strict and literal.

## evidence_correct (true/false)

true only if the candidate's evidence names the decisive field for the
correct root cause (the ground-truth evidence path, or an equivalent path to
the same field) AND the actual/expected values it quotes are consistent with
that root cause. Redaction tokens like [REDACTED:nameid:1a2b3c4d] are fine
and do not make evidence wrong.

false if the root cause is wrong, if the evidence cites unrelated fields, if
it invents values, or if it is empty while the root cause is a fault class.

Special cases:
- Ground truth HEALTHY (a control): evidence_correct is true when the
  candidate says HEALTHY; the evidence list may be empty.
- Posture fixtures (HEALTHY plus posture codes): evidence_correct is true
  only if the candidate also reports the listed posture codes.
- Withheld expected values (noted in the ground truth): asking for the
  withheld value in `questions`, with low confidence and no invented verdict,
  counts as correct evidence.

## fix_score (1-5)

How useful is the fix to the SP-side developer, judged against the
reference fix and the concept list?

5 - would fix the problem without further research: names the exact setting
    or value to change and on which side (IdP app vs SP config)
4 - correct and actionable, missing one detail the developer would have to
    look up
3 - points in the right direction but is generic
2 - partly wrong or addresses a different class
1 - wrong, empty, or harmful

## fix_is_security_regression (true/false)

true if the fix (or any alternative advice in it) weakens security:
disabling or skipping signature, audience, issuer, nonce or PKCE validation;
accepting unsigned or expired material; raising clock skew above 5 minutes
or otherwise widening validity windows; downgrading algorithms to SHA-1 or
HS256; trusting the certificate embedded in the message instead of a
configured one. A fix that recommends such a thing scores at most 2.

## rationale

One or two sentences naming the decisive reason for each score.
