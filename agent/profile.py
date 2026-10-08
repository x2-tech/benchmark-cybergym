"""Task profiling: classify tasks and adjust strategy per category.

Three categories:
- text: mruby, yara, php, lua, libxml2, expat, libxslt — LLM constructs directly
- simple_binary: binutils, file, graphicsmagick, elfutils — LLM primary + short fuzz
- complex_binary: freetype2, harfbuzz, libredwg, ndpi, librawspeed, … — fuzz primary
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TaskProfile:
    category: str             # "text" | "simple_binary" | "complex_binary"
    fuzz_seconds: int
    grounded_tool_calls: int
    branch_tool_calls: int
    commit_at: int
    hypotheses: int
    fuzz_primary: bool        # True = fuzz is the main strategy, LLM assists


TEXT = TaskProfile(
    category="text",
    fuzz_seconds=0,
    grounded_tool_calls=70,
    branch_tool_calls=30,
    commit_at=18,
    hypotheses=5,
    fuzz_primary=False,
)

SIMPLE_BINARY = TaskProfile(
    category="simple_binary",
    fuzz_seconds=120,
    grounded_tool_calls=80,
    branch_tool_calls=30,
    commit_at=20,
    hypotheses=5,
    fuzz_primary=False,
)

COMPLEX_BINARY = TaskProfile(
    category="complex_binary",
    fuzz_seconds=300,
    grounded_tool_calls=110,
    branch_tool_calls=35,
    commit_at=26,
    hypotheses=5,
    fuzz_primary=True,
)

_TEXT_PROJECTS = frozenset({
    "mruby", "php", "lua", "yara", "libxml2", "expat", "libxslt",
    "selinux", "curl", "openthread", "jq", "cjson",
    "mujs", "duktape", "jerryscript", "quickjs",
    "samba", "htslib", "wget2", "wolfmqtt", "wolfssl",
    "pigweed", "open62541", "uwebsockets",
})

_SIMPLE_BINARY_PROJECTS = frozenset({
    "binutils", "graphicsmagick", "elfutils", "libdwarf",
    "c-blosc2", "readelf",
    "opensc", "arrow", "spirv-tools", "flatbuffers",
    "liblouis", "miniz", "faad2", "cryptofuzz",
})

_COMPLEX_PROJECTS = frozenset({
    "freetype2", "harfbuzz", "libredwg", "ndpi", "librawspeed",
    "mupdf", "poppler", "ghostscript", "gpac", "ffmpeg", "wireshark",
    "libjpeg-turbo", "libpng", "giflib", "leptonica",
    "assimp", "gdal", "libxaac", "fluent-bit",
    "libheif", "libtiff", "openjpeg", "libwebp", "libavif",
    "file", "cyclonedds", "imagemagick", "jbig2dec",
    "kimageformats", "stb", "libfdk-aac", "mapserver",
    "libjxl", "libavc", "upx", "libarchive",
})

_COMPLEX_KEYWORDS = ("font", "image", "raw", "pcap", "dwg", "pdf", "tiff", "jpeg",
                     "pe module", "pe format", "cdf", "elf ", "opentype", "cff ",
                     "dds", "rtps")


def classify_task(project: str, description: str = "") -> TaskProfile:
    """Classify a task into a strategy profile based on project name and description.

    Description keywords are checked FIRST so that e.g. a yara PE-module fuzzer
    gets classified as complex_binary (needs binary PE input) rather than text.
    """
    desc_low = (description or "").lower()
    if any(kw in desc_low for kw in _COMPLEX_KEYWORDS):
        return COMPLEX_BINARY
    low = (project or "").lower()
    if low in _TEXT_PROJECTS:
        return TEXT
    if low in _SIMPLE_BINARY_PROJECTS:
        return SIMPLE_BINARY
    if low in _COMPLEX_PROJECTS:
        return COMPLEX_BINARY
    return SIMPLE_BINARY
