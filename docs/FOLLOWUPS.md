# Follow-ups noticed during the v1 walkthrough (2026-10-27)

- Symptom templates are chosen per class, so an `expired` (NotOnOrAfter) mutation can carry a NotBefore symptom
  ("Current time is earlier than NotBefore condition"). Realistic as user misreporting, but the generator should
  prefer a template matching the sub-mutator when one exists and tag the case `symptom_match: exact|class|misleading`
  so the report can split accuracy by symptom quality. (v2)
