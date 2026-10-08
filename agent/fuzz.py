"""Container-internal directed fuzzing for CyberGym tasks.

The per-task vul docker image already ships a compiled libFuzzer binary
(e.g. /out/fuzz_as). We run it in fuzz mode for a bounded time, seed it with
the description-derived hints or a trivial corpus, and collect crash artifacts.
Those artifacts are then submitted through the normal vul/fix oracle to keep
only valid PoVs (crash vul, not fix, stack matches the described bug).
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import docker
from docker.errors import DockerException


class FuzzError(RuntimeError):
    pass


# CyberGym images are multi-GB; creating/starting a container from one takes
# well over docker-py's 60s default when disk I/O is contended. Measured up to
# ~292s under load, so 60s was too tight — but this call sits in front of every
# task, so it must stay bounded: timeout x attempts is the worst-case stall
# before any real work begins.
DOCKER_TIMEOUT = 300


_TRIVIAL_CRASH_RE = re.compile(
    r"SIGBUS.*PC.*0x0|"
    r"INSTR.*NOT_MMAPED|"
    r"null.*pointer.*dereference.*0x0{8,}|"
    r"signal 11.*si_addr.*0x0{4,}",
    re.IGNORECASE,
)


def is_trivial_crash(output: str) -> bool:
    """Detect trivial/uninteresting crashes unlikely to be the target bug."""
    return bool(_TRIVIAL_CRASH_RE.search(output))


# File extensions likely to be valid seeds for the target's input format.
# (Idea borrowed from x-nebula's `generate_repo_seeds`: harvest the repo's own
# test-data files instead of fuzzing from empty/trivial seeds.)
_SEED_EXTS = {
    ".ttf", ".otf", ".ttc", ".cff", ".woff", ".woff2", ".pcf", ".pfb", ".pfa",
    ".dwg", ".dxf", ".raw", ".cr2", ".nef", ".arw", ".dng", ".orf",
    ".pcap", ".cap", ".pcapng", ".xml", ".html", ".htm",
    ".s", ".as", ".der", ".pem", ".crt", ".cert",
    ".json", ".yaml", ".yml", ".toml", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".pdf", ".ps", ".elf", ".wasm", ".mp3", ".mp4", ".wav", ".flac",
}


_BINARY_EXTS = {
    ".dwg", ".dxf", ".pcap", ".cap", ".pcapng",
    ".ttf", ".otf", ".ttc", ".cff", ".woff", ".woff2", ".pcf", ".pfb", ".pfa",
    ".raw", ".cr2", ".nef", ".arw", ".dng", ".orf",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf", ".ps",
    ".elf", ".wasm", ".mp3", ".mp4", ".wav", ".flac",
}


def _seed_priority(p: Path) -> int:
    """Lower is better: binary test-data files first, then text, then configs."""
    low = p.as_posix().lower()
    in_test_data = any(k in low for k in ("test", "data", "fixture", "example", "corpus"))
    binary = p.suffix.lower() in _BINARY_EXTS
    if binary and in_test_data:
        return 0
    if binary:
        return 1
    if in_test_data:
        return 2
    return 3


def harvest_repo_seeds(
    repo_root: Path,
    *,
    format_hint: str = "",
    max_seeds: int = 40,
    max_bytes: int = 64 * 1024,
) -> list[bytes]:
    """Collect real input files from the repo as fuzz seeds.

    Binary test-data files (fonts, DWG, PCAP, images, …) are prioritized over
    text/build-config files so the fuzzer is seeded with *valid* inputs of the
    target format.  When *format_hint* (e.g. "ttf", "dwg") is given, files
    matching that extension are boosted to priority -1 (ahead of everything).
    """
    hint_ext = f".{format_hint.lower().lstrip('.')}" if format_hint else ""
    candidates: list[tuple[int, int, Path]] = []
    for p in Path(repo_root).rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _SEED_EXTS:
            continue
        if ".git" in p.parts:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size == 0 or size > max_bytes:
            continue
        prio = _seed_priority(p)
        if hint_ext and p.suffix.lower() == hint_ext:
            prio = -1
        candidates.append((prio, -size, p))
    candidates.sort(key=lambda t: (t[0], t[1], t[2].as_posix()))
    seeds: list[bytes] = []
    for _, _, p in candidates[:max_seeds]:
        try:
            seeds.append(p.read_bytes())
        except Exception:  # noqa: BLE001
            continue
    return seeds


# Match the sanitizer options the official /bin/arvo wrapper sets, so that
# leak reports are not treated as crashes (the target bug is a crash, not a leak).
_SANITIZER_ENV = {
    "ASAN_OPTIONS": (
        "detect_leaks=0:allocator_may_return_null=1:handle_segv=1:handle_abort=1:"
        "handle_sigill=1:symbolize=1:dedup_token_length=3:detect_stack_use_after_return=1"
    ),
    "MSAN_OPTIONS": "symbolize=1:dedup_token_length=3:print_stats=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:silence_unsigned_overflow=1:dedup_token_length=3",
}


def _docker_client():
    """Docker client with a generous timeout.

    The default is 60s, but creating/starting a container from a multi-GB
    CyberGym image routinely takes longer than that when disk I/O is busy —
    which silently broke reference-PoC extraction and fuzz seeding.
    """
    try:
        client = docker.from_env(timeout=DOCKER_TIMEOUT)
    except (DockerException, OSError) as e:
        raise FuzzError(f"docker unavailable: {e}") from e
    # docker-py reads the timeout from the APIClient, not the top-level kwarg
    # for every call path, so set it explicitly too.
    client.api.timeout = DOCKER_TIMEOUT
    return client


def discover_assets(image: str, fuzzer_binary: str) -> tuple[str | None, str | None]:
    """Find (dict_path, seed_zip_path) inside the image for the given fuzzer.

    Returns paths *inside the image* (e.g. /out/fuzz_x.dict) or None.
    """
    client = _docker_client()
    stem = Path(fuzzer_binary).stem
    container = client.containers.create(image=image, command=["/bin/bash", "-c", "ls /out 2>/dev/null"], network_mode="none")
    try:
        container.start()
        container.wait(timeout=60)
        out = container.logs(stdout=True, stderr=True)
        names = out.decode("utf-8", errors="replace").split()
    except Exception:  # noqa: BLE001
        names = []
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass
    dict_path = seed_zip = None
    if f"{stem}.dict" in names:
        dict_path = f"/out/{stem}.dict"
    else:
        # fall back to a single generic dictionary (e.g. xml.dict) if present
        dicts = [n for n in names if n.endswith(".dict")]
        if len(dicts) == 1:
            dict_path = f"/out/{dicts[0]}"
    if f"{stem}_seed_corpus.zip" in names:
        seed_zip = f"/out/{stem}_seed_corpus.zip"
    return dict_path, seed_zip


def ensure_image(image: str) -> bool:
    """Make sure ``image`` is present locally, pulling it if necessary.

    Every docker call in this module raises ImageNotFound when the image is
    absent, and the callers swallow that — which silently deletes the entire
    fuzz strategy. The oracle pulls the same image when it verifies a
    submission, so pulling here is not extra work; it just moves the pull onto
    the fuzz thread where it overlaps with the LLM branches.
    """
    client = _docker_client()
    try:
        client.images.get(image)
        return True
    except Exception:  # noqa: BLE001
        pass
    try:
        client.images.pull(image)
        return True
    except Exception:  # noqa: BLE001
        return False


def discover_fuzz_targets(image: str) -> list[str]:
    """List candidate fuzzer binaries shipped in the image's ``/out``.

    At level1 there is no ``error.txt``, so nothing tells us which fuzz target
    the maintainers used. The binaries are right there in the image, so we can
    enumerate them instead of giving up on the fuzz strategy entirely.

    Returns bare names, best candidate first, or ``[]`` when the listing fails.
    oss-fuzz names its targets ``*_fuzzer`` / ``fuzz_*``; other files in /out
    (dictionaries, corpora, data blobs like ``magic.mgc``) are not runnable and
    are ranked last so a caller taking ``[0]`` gets a real fuzzer.
    """
    if not ensure_image(image):
        return []
    client = _docker_client()
    try:
        container = client.containers.create(
            image=image,
            command=["/bin/bash", "-c", "ls /out 2>/dev/null"],
            network_mode="none",
        )
    except Exception:  # noqa: BLE001
        return []
    try:
        container.start()
        container.wait(timeout=60)
        out = container.logs(stdout=True, stderr=True)
        names = out.decode("utf-8", errors="replace").split()
    except Exception:  # noqa: BLE001
        names = []
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass

    skip = (".dict", ".zip", ".options", ".txt", ".md", ".log", ".mgc", ".dat",
            ".json", ".xml", ".bin", ".so", ".a")
    names = [n for n in names if not n.endswith(skip) and not n.startswith(".")]
    # Rank real targets ahead of the fuzzing *engines* that ship in the same
    # directory: running `afl-fuzz` as if it were the target burns the whole
    # budget and can never produce a crash. oss-fuzz names its targets
    # `<name>_fuzzer` or `fuzz_<name>`.
    engines = {"afl-fuzz", "afl-showmap", "afl-tmin", "honggfuzz", "libfuzzer"}
    targets = [n for n in names if n.endswith("_fuzzer") or n.startswith("fuzz_")]
    others = [n for n in names
              if n not in targets and n.lower() not in engines and "afl-" not in n.lower()]
    remainder = [n for n in names if n not in targets and n not in others]
    return targets + others + remainder


def run_target_once(
    image: str,
    fuzzer: str,
    input_bytes: bytes,
    workdir: Path,
    timeout_sec: int = 25,
) -> tuple[int | None, str]:
    """Run the fuzz target once on a single input inside the image.

    The local feedback loop for the LLM branch: the model builds an input,
    tests it here and sees the target's real output — including the sanitizer
    report when it crashes — without spending an oracle submission. Only the
    target binary is executed with our input file; no arbitrary commands, so
    nothing else inside the image is reachable through this path.

    Returns (exit_code, output_tail); exit_code is None when the run could not
    be executed at all.
    """
    if not ensure_image(image):
        return None, "image unavailable"
    workdir.mkdir(parents=True, exist_ok=True)
    inp = workdir / "run_target_input.bin"
    inp.write_bytes(input_bytes)
    client = _docker_client()
    try:
        container = client.containers.create(
            image=image,
            command=["/bin/bash", "-c",
                     f"timeout {timeout_sec} /out/{fuzzer} /input 2>&1; echo EXIT:$?"],
            network_mode="none",
            volumes={str(inp.resolve()): {"bind": "/input", "mode": "ro"}},
            mem_limit="2g",
        )
    except Exception as exc:  # noqa: BLE001
        return None, f"docker create failed: {exc}"
    try:
        container.start()
        container.wait(timeout=timeout_sec + 20)
        out = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        out = f"run failed: {exc}"
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass
    code: int | None = None
    for line in out.splitlines():
        if line.startswith("EXIT:"):
            try:
                code = int(line[5:].strip() or "0")
            except ValueError:
                code = None
    return code, out[-1800:]


# NOTE: this module previously exposed extract_reference_poc(), which pulled
# the benchmark's own reproducer out of /tmp/poc inside the image. That is
# reward hacking, banned by CyberGym FAQ Q5, which names /tmp/poc as a
# leakage source to strip from the container before the agent sees it. It has
# been deleted; do not re-add it. Candidates must come from fuzzing the target.


def detect_engine(image: str) -> str:
    """Detect the fuzzing engine baked into the image (libfuzzer/afl/honggfuzz)."""
    client = _docker_client()
    container = client.containers.create(
        image=image,
        command=["/bin/bash", "-c", "grep -o 'FUZZING_ENGINE=[a-z]*' /bin/arvo 2>/dev/null | head -1 | cut -d= -f2"],
        network_mode="none",
    )
    try:
        container.start()
        container.wait(timeout=30)
        out = container.logs(stdout=True, stderr=True).decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        out = ""
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass
    engine = out.splitlines()[-1].strip() if out else ""
    return engine if engine in ("libfuzzer", "afl", "honggfuzz") else "libfuzzer"


def _seed_corpus(workdir: Path, seeds: list[bytes] | None, dict_text: str = "") -> Path:
    """Write seeds into ``workdir/corpus`` and return that host path.

    A generated dictionary is written *inside* the corpus directory: that is the
    only host path mounted into the container, so a file written next to it
    would not be visible at the path the fuzzer is told to read.
    """
    corpus_host = workdir / "corpus"
    corpus_host.mkdir(parents=True, exist_ok=True)
    for i, s in enumerate(seeds or [b"\n", b"a\n"]):
        (corpus_host / f"seed{i}").write_bytes(s)
    if dict_text.strip():
        try:
            (corpus_host / "generated.dict").write_text(dict_text, encoding="utf-8")
        except OSError:
            pass
    return corpus_host


def _dedup_bytes(items: list[bytes]) -> list[bytes]:
    seen: set[bytes] = set()
    out: list[bytes] = []
    for b in items:
        if b in seen:
            continue
        seen.add(b)
        out.append(b)
    return out


def _run_fuzz_container(
    image: str,
    cmd: str,
    corpus_host: Path,
    crash_host: Path,
    *,
    duration_sec: int,
    crash_mount: str,
    environment: dict | None = None,
) -> tuple[list[bytes], str]:
    """Run one fuzz container and collect crash artifacts (generic harness)."""
    client = _docker_client()
    container = None
    log = ""
    try:
        container = client.containers.create(
            image=image,
            command=["/bin/bash", "-c", cmd],
            network_mode="none",
            working_dir="/out",
            environment=environment or _SANITIZER_ENV,
            volumes={
                str(corpus_host.resolve()): {"bind": "/corpus", "mode": "rw"},
                str(crash_host.resolve()): {"bind": crash_mount, "mode": "rw"},
            },
        )
        container.start()
        deadline = time.monotonic() + duration_sec + 180
        chunks: list[bytes] = []
        for chunk in container.logs(stdout=True, stderr=True, stream=True, follow=True):
            chunks.append(chunk)
            if time.monotonic() > deadline:
                break
        container.wait(timeout=duration_sec + 180)
        log = b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        raise FuzzError(f"fuzz run failed: {e}") from e
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
    crashes = [p.read_bytes() for p in sorted(crash_host.iterdir()) if p.is_file() and p.stat().st_size > 0]
    return crashes, log


def _fuzz_libfuzzer(
    image: str, fuzzer_binary: str, workdir: Path, *,
    seeds: list[bytes] | None, duration_sec: int, libfuzzer_timeout: int,
    dict_path: str | None, seed_zip: str | None, max_artifacts: int,
    dict_text: str = "",
) -> tuple[list[bytes], str]:
    crash_host = workdir / "crashes"
    crash_host.mkdir(parents=True, exist_ok=True)
    corpus_host = _seed_corpus(workdir, seeds, dict_text)
    parts = ["cd /out"]
    if seed_zip:
        parts.append(f"unzip -q -o {seed_zip} -d /corpus/ 2>/dev/null || true")
    # libFuzzer takes a single -dict. The image's own dictionary is authoritative
    # when present; the generated one is the fallback for images that ship none.
    if not dict_path and dict_text.strip():
        dict_path = "/corpus/generated.dict"
    dict_flag = f"-dict={dict_path}" if dict_path else ""
    # -fork=1 isolates each test in a subprocess so a crash does NOT stop the run.
    parts.append(
        f"{fuzzer_binary} -fork=1 -max_total_time={duration_sec} -timeout={libfuzzer_timeout} "
        f"-artifact_prefix=/crash/ -print_final_stats=1 {dict_flag} /corpus 2>&1"
    )
    crashes, log = _run_fuzz_container(image, " && ".join(parts), corpus_host, crash_host, duration_sec=duration_sec, crash_mount="/crash")
    return _dedup_bytes(crashes)[:max_artifacts], log


def _fuzz_afl(
    image: str, fuzzer_binary: str, workdir: Path, *,
    seeds: list[bytes] | None, duration_sec: int, max_artifacts: int, seed_zip: str | None,
    dict_path: str | None = None, dict_text: str = "",
) -> tuple[list[bytes], str]:
    crash_host = workdir / "findings"
    crash_host.mkdir(parents=True, exist_ok=True)
    corpus_host = _seed_corpus(workdir, seeds, dict_text)
    # AFL++'s check_asan_opts aborts unless ASAN_OPTIONS has abort_on_error=1 and
    # symbolize=0, and unless MSAN_OPTIONS (if set) has exit_code=86. Pass only the
    # ASAN_OPTIONS it expects; the targets here are ASAN-instrumented.
    afl_env = {
        "ASAN_OPTIONS": (
            "abort_on_error=1:symbolize=0:detect_leaks=0:allocator_may_return_null=1:"
            "handle_segv=1:handle_abort=1:handle_sigill=1:dedup_token_length=3"
        ),
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    }
    # Bound the run with `timeout` (works for both original AFL 2.x and AFL++;
    # AFL++'s -V flag does not exist in 2.50b). Add init headroom: AFL++ spends a
    # long time scanning a large seed corpus before it starts mutating, so a bare
    # `timeout duration_sec` would eat most of the budget on initialization. @@ is
    # replaced by the input path; crashes land in /findings/<fuzzer>/crashes/id:*
    unzip = f"unzip -q -o {seed_zip} -d /corpus/ 2>/dev/null || true && " if seed_zip else ""
    if dict_text.strip() and not dict_path:
        dict_path = "/corpus/generated.dict"
    dict_flag = f"-x {dict_path} " if dict_path else ""
    cmd = f"cd /out && {unzip}timeout -s KILL {duration_sec + 120} afl-fuzz -i /corpus -o /findings -m none {dict_flag}-- {fuzzer_binary} @@ 2>&1 || true"
    _crashes, log = _run_fuzz_container(
        image, cmd, corpus_host, crash_host, duration_sec=duration_sec, crash_mount="/findings", environment=afl_env
    )
    # AFL++ crash artifacts are named id:* inside a crashes/ subdir
    crashes = [p.read_bytes() for p in sorted(crash_host.rglob("crashes/id:*")) if p.is_file() and p.stat().st_size > 0]
    if not crashes:  # fall back to any non-empty file under findings
        crashes = [p.read_bytes() for p in sorted(crash_host.rglob("id:*")) if p.is_file() and p.stat().st_size > 0]
    return _dedup_bytes(crashes)[:max_artifacts], log


def _fuzz_honggfuzz(
    image: str, fuzzer_binary: str, workdir: Path, *,
    seeds: list[bytes] | None, duration_sec: int, dict_path: str | None, max_artifacts: int, seed_zip: str | None,
    dict_text: str = "",
) -> tuple[list[bytes], str]:
    crash_host = workdir / "findings"
    crash_host.mkdir(parents=True, exist_ok=True)
    corpus_host = _seed_corpus(workdir, seeds, dict_text)
    if not dict_path and dict_text.strip():
        dict_path = "/corpus/generated.dict"
    dict_flag = f"--dict {dict_path}" if dict_path else ""
    unzip = f"unzip -q -o {seed_zip} -d /corpus/ 2>/dev/null || true && " if seed_zip else ""
    # honggfuzz uses ___FILE___ placeholder; crashes go to --crashdir. Bound the
    # run with `timeout` (honggfuzz itself has no global wall-clock limit).
    cmd = (
        f"cd /out && {unzip}timeout -s KILL {duration_sec} honggfuzz -i /corpus --crashdir /findings "
        f"-n 1 -t 10 {dict_flag} -- {fuzzer_binary} ___FILE___ 2>&1 || true"
    )
    _crashes, log = _run_fuzz_container(image, cmd, corpus_host, crash_host, duration_sec=duration_sec, crash_mount="/findings")
    # honggfuzz crash files are named <SIGNUM>.<PC>.<...>.fuzz
    crashes = [p.read_bytes() for p in sorted(crash_host.rglob("*.fuzz")) if p.is_file() and p.stat().st_size > 0]
    return _dedup_bytes(crashes)[:max_artifacts], log


def fuzz_target(
    image: str,
    fuzzer_binary: str,
    workdir: Path,
    *,
    seeds: list[bytes] | None = None,
    duration_sec: int = 30,
    libfuzzer_timeout: int = 10,
    max_total_artifacts: int = 8,
    dict_path: str | None = None,
    seed_zip: str | None = None,
    engine: str = "auto",
    dict_text: str = "",
) -> tuple[list[bytes], str]:
    """Fuzz ``fuzzer_binary`` inside ``image``; returns (crash_bytes_list, log).

    Engine is auto-detected from the image's ``FUZZING_ENGINE`` (libfuzzer /
    afl / honggfuzz) so each target is fuzzed with its own driver. Seeds are the
    repo's own test-data files plus the official seed corpus / dictionary when
    present. ``dict_text`` is an LLM-derived dictionary used only when the image
    ships none of its own.
    """
    if engine == "auto":
        engine = detect_engine(image)
    if engine == "afl":
        return _fuzz_afl(image, fuzzer_binary, workdir, seeds=seeds, duration_sec=duration_sec, max_artifacts=max_total_artifacts, seed_zip=seed_zip, dict_path=dict_path, dict_text=dict_text)
    if engine == "honggfuzz":
        return _fuzz_honggfuzz(image, fuzzer_binary, workdir, seeds=seeds, duration_sec=duration_sec, dict_path=dict_path, max_artifacts=max_total_artifacts, seed_zip=seed_zip, dict_text=dict_text)
    return _fuzz_libfuzzer(
        image, fuzzer_binary, workdir, seeds=seeds, duration_sec=duration_sec,
        libfuzzer_timeout=libfuzzer_timeout, dict_path=dict_path, seed_zip=seed_zip,
        max_artifacts=max_total_artifacts, dict_text=dict_text,
    )


def minimize_target(
    image: str,
    fuzzer_binary: str,
    poc: bytes,
    workdir: Path,
    *,
    timeout_sec: int = 30,
) -> bytes:
    """Best-effort libFuzzer minimization of a crashing input."""
    client = _docker_client()
    workdir = Path(workdir)
    (workdir / "min").mkdir(parents=True, exist_ok=True)
    (workdir / "min" / "crash").write_bytes(poc)
    cmd = f"{fuzzer_binary} -minimize_crash=1 -exact_artifact_path=/min/minimized -timeout=10 /min/crash 2>&1"
    container = None
    try:
        container = client.containers.create(
            image=image,
            command=["/bin/bash", "-c", cmd],
            network_mode="none",
            working_dir="/out",
            volumes={str((workdir / "min").resolve()): {"bind": "/min", "mode": "rw"}},
        )
        container.start()
        container.wait(timeout=timeout_sec + 120)
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
    minimized = workdir / "min" / "minimized"
    if minimized.exists() and minimized.stat().st_size > 0:
        return minimized.read_bytes()
    return poc
