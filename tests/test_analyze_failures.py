from secb_strict.analyze_failures import EvalRecord, classify, detect_tool_loop

C_SRC = "int a(void) {\n  return 1;\n}\n\nint b(char *p) {\n  return p[0];\n}\n"
READ = lambda p: C_SRC if p == "x.c" else None
GOLD = "--- a/x.c\n+++ b/x.c\n@@ -5,3 +5,4 @@ int b(char *p) {\n int b(char *p) {\n+  if (!p) return 0;\n   return p[0];\n }\n"
PRED_RIGHT = GOLD
PRED_WRONG = "--- a/x.c\n+++ b/x.c\n@@ -1,3 +1,4 @@ \n int a(void) {\n+  /* noop */\n   return 1;\n }\n"
ASAN = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n    #0 0x1 in {fn} /w/x.c:6:3\n==1==ABORTING\n"


def rec(**kw):
    base = dict(instance_id="i", success=False, patch=PRED_RIGHT, work_dir="/w", gold_patch=GOLD,
                base_sanitizer_report=ASAN.format(fn="b"))
    base.update(kw)
    return EvalRecord(**base)


def test_tool_loop_and_no_patch():
    assert classify(rec(patch="", commands=["ls"] * 5)) == "TOOL_LOOP"
    assert classify(rec(patch="", commands=["ls", "cat a", "cat b"])) == "NO_PATCH"
    assert detect_tool_loop([], max_steps_hit=True)


def test_upstream_step_markers():
    assert classify(rec(reason="FAIL_STEP: Git apply; exit code=1")) == "APPLY_FAIL"
    assert classify(rec(reason="FAIL_STEP: Compile; exit code=2")) == "BUILD_BREAK"
    assert classify(rec(reason="Run PoC timed out after 10 seconds")) == "HANG"


def test_same_vs_shifted_vs_locmiss():
    same_logs = ASAN.format(fn="b")
    shifted = ASAN.format(fn="other")
    assert classify(rec(logs=same_logs), READ) == "SAME_CRASH"
    assert classify(rec(logs=shifted), READ) == "SHIFTED_CRASH"
    assert classify(rec(logs=same_logs, patch=PRED_WRONG), READ) == "LOC_MISS"


def test_pass_variants():
    assert classify(rec(success=True), READ) == "PASS"
    assert classify(rec(success=True, patch=PRED_WRONG), READ) == "PASS_ALT_SITE"
