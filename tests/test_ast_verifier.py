import textwrap

from secb_strict.ast_verifier import (
    changed_old_lines, functions_in, gold_spans, score_prediction,
    crash_frame_baseline, crash_signature,
)

C_SRC = textwrap.dedent("""\
    #include <string.h>

    static int helper(int x) {
        return x + 1;
    }

    int parse(const char *buf, int len) {
        char tmp[16];
        int i = helper(len);
        memcpy(tmp, buf, len);
        return i;
    }

    char *const *weird_ptr_ret(void) {
        return 0;
    }
    """)

# pure-addition fix inside parse(): bounds check before memcpy (old line 10/11)
ADD_ONLY = textwrap.dedent("""\
    --- a/src/p.c
    +++ b/src/p.c
    @@ -8,5 +8,7 @@ int parse(const char *buf, int len) {
         char tmp[16];
         int i = helper(len);
    +    if (len > (int)sizeof(tmp))
    +        return -1;
         memcpy(tmp, buf, len);
         return i;
     }
    """)

# multi-function fix: edit helper() and parse()
MULTI = textwrap.dedent("""\
    --- a/src/p.c
    +++ b/src/p.c
    @@ -3,5 +3,5 @@
     static int helper(int x) {
    -    return x + 1;
    +    return x < 0 ? 0 : x + 1;
     }

     int parse(const char *buf, int len) {
    @@ -9,4 +9,5 @@ int parse(const char *buf, int len) {
         int i = helper(len);
    -    memcpy(tmp, buf, len);
    +    memcpy(tmp, buf, len > 16 ? 16 : len);
         return i;
     }
    """)


def read(path):
    return C_SRC if path == "src/p.c" else None


def test_function_extraction_names_and_spans():
    fns = {f.symbol: f for f in functions_in(C_SRC, "src/p.c")}
    assert set(fns) == {"helper", "parse", "weird_ptr_ret"}
    assert (fns["parse"].start_line, fns["parse"].end_line) == (7, 12)


def test_pure_addition_maps_to_enclosing_function():
    assert changed_old_lines(ADD_ONLY)["src/p.c"]  # non-empty
    spans, unmapped = gold_spans(ADD_ONLY, read)
    assert [s.symbol for s in spans] == ["parse"] and not unmapped


def test_multi_function_gold_is_a_set():
    spans, _ = gold_spans(MULTI, read)
    assert {s.symbol for s in spans} == {"helper", "parse"}


def test_scoring_hit_and_miss():
    gold, _ = gold_spans(ADD_ONLY, read)
    hit = score_prediction({"file": "src/p.c", "symbol": "parse", "start_line": 7, "end_line": 12}, gold)
    assert hit.file_hit and hit.symbol_hit and hit.line_hit and hit.iou == 1.0
    miss = score_prediction({"file": "src/p.c", "symbol": "helper", "start_line": 3, "end_line": 5}, gold)
    assert miss.file_hit and not miss.symbol_hit and not miss.line_hit and miss.iou == 0.0
    wrong_file = score_prediction({"file": "src/q.c", "symbol": "parse", "start_line": 7, "end_line": 12}, gold)
    assert not wrong_file.file_hit


def test_non_c_file_is_reported_unmapped_not_dropped():
    diff = "--- a/gen/x.y\n+++ b/gen/x.y\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    spans, unmapped = gold_spans(diff, lambda p: "a\n")
    assert spans == [] and unmapped == ["gen/x.y"]


ASAN = textwrap.dedent("""\
    ==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020 at pc 0x1 bp 0x2 sp 0x3
    READ of size 4 at 0x6020 thread T0
        #0 0x4c1 in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:22:3
        #1 0x4c2 in parse /src/proj/src/p.c:11:5
        #2 0x4c3 in main /src/proj/src/main.c:30:9
    ==1==ABORTING
    """)


def test_crash_frame_baseline_skips_runtime_frames():
    b = crash_frame_baseline(ASAN, "/src/proj")
    assert b == {"file": "src/p.c", "symbol": "parse", "start_line": 11, "end_line": 11}


def test_crash_signature_same_vs_shifted():
    s1 = crash_signature(ASAN, "/src/proj")
    s2 = crash_signature(ASAN.replace("parse", "other"), "/src/proj")
    assert s1 != s2 and s1[1][:1] == ("parse",)


def test_crash_frame_baseline_fallback_foreign_build_path():
    from secb_strict.ast_verifier import crash_frame_baseline, same_file
    rep = ("    #0 0x1 in njs_vmcode_interpreter /home/u/origin/njs_f65981b/src/njs_vmcode.c:802:27\n"
           "    #1 0x2 in main /home/u/origin/njs_f65981b/src/njs_shell.c:9:1\n")
    b = crash_frame_baseline(rep, "/src/njs")
    assert b and b["symbol"] == "njs_vmcode_interpreter" and b["start_line"] == 802
    assert same_file(b["file"], "src/njs_vmcode.c")
    assert not same_file("x/aenjs_vmcode.c", "njs_vmcode.c")
