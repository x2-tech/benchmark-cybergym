from agent.extract import parse_error_report

MSAN = """\
INFO: Seed: 2195359900
INFO: Loaded 1 modules (3759 guards): [0xa2f990, 0xa3344c),
/out/magic_fuzzer: Running 1 inputs 1 time(s) each.
Running: /tmp/poc
==14==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x590726 in match /src/file/src/softmagic.c:365:9
    #1 0x58d2d3 in file_softmagic /src/file/src/softmagic.c:108:13
    #8 0x498bf1 in LLVMFuzzerTestOneInput /src/magic_fuzzer.cc:52:3
    #14 0x41f238 in _start (/out/magic_fuzzer+0x41f238)

DEDUP_TOKEN: match--file_softmagic--mget
  Uninitialized value was stored to memory at
    #0 0x5983ba in magiccheck /src/file/src/softmagic.c:1904:23
  Uninitialized value was created by an allocation of 'pmatch' in the stack frame of function 'magiccheck'
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/file/src/softmagic.c:365:9 in match
Exiting
"""

ASAN = """\
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x000000
READ of size 1 at 0x602000000011 thread T0
    #0 0x49f6b6 in parse_image /src/mupdf/source/fitz/image.c:120:5
    #1 0x4a1c2d in fz_load_image /src/mupdf/source/fitz/image.c:220:9
    #2 0x4b3a in LLVMFuzzerTestOneInput /src/fuzz_image.c:10:3

DEDUP_TOKEN: parse_image--fz_load_image
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/mupdf/source/fitz/image.c:120:5 in parse_image
"""


def test_msan_fields():
    c = parse_error_report(MSAN)
    assert c.sanitizer == "MemorySanitizer"
    assert c.error_type == "use-of-uninitialized-value"
    assert c.crash_func == "match"
    assert c.crash_file == "/src/file/src/softmagic.c"
    assert c.crash_line == 365
    assert c.fuzzer_target == "/out/magic_fuzzer"
    assert c.project == "file"
    assert c.dedup_token == "match--file_softmagic--mget"
    assert "pmatch" in c.origin
    assert c.source_relative_path == "src/softmagic.c"


def test_msan_stack_frames():
    c = parse_error_report(MSAN)
    assert c.stack[0].func == "match"
    assert c.stack[0].file == "/src/file/src/softmagic.c"
    assert c.stack[0].line == 365
    # module frame
    mods = [f for f in c.stack if f.module]
    assert any("magic_fuzzer" in f.module for f in mods)


def test_asan_fields():
    c = parse_error_report(ASAN)
    assert c.sanitizer == "AddressSanitizer"
    assert c.error_type == "heap-buffer-overflow"
    assert c.crash_func == "parse_image"
    assert c.crash_line == 120
    assert c.project == "mupdf"


def test_cpp_mangled_func_with_spaces():
    txt = "    #8 0x4d77a9 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:451:13\n"
    c = parse_error_report(txt)
    assert c.stack[0].func == "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
    assert c.stack[0].file == "/src/libfuzzer/FuzzerLoop.cpp"
    assert c.stack[0].line == 451


def test_empty_input():
    assert parse_error_report("").crash_line == 0
    assert parse_error_report("garbage with nothing").sanitizer == ""
