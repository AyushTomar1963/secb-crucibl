# Failure case studies

_No runs yet. Fill after the first full pass. Pick one run per bucket below
(prefer the most instructive, not the most common) and annotate step by step._

For each case: instance id, arm/seed, gold fix site vs. crash frame vs. predicted
site, then a numbered trajectory with the step where it went wrong.

## Case 1 — LOC_MISS (or SAME_CRASH with correct site)
- Instance / arm / seed:
- Gold function(s) · crash-frame function · Stage-A prediction:
- Trajectory (step → observation → what the agent concluded):
- Turning point:

## Case 2 — PASS_ALT_SITE or PASS_DELETION_HEAVY (false-pass candidate)
- Does the patch fix the root cause, or suppress the symptom? Evidence
  (differential run vs. gold-patched binary, benign inputs used):

## Case 3 — TOOL_LOOP or SHIFTED_CRASH
- Loop signature / new crash signature:
