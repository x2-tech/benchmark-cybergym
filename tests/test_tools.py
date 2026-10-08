import io
import tarfile

import pytest

from agent.tools import SubmitResult, extract_tar, list_files, grep


def _make_tar(path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def test_extract_and_list(tmp_path):
    tar = tmp_path / "r.tar.gz"
    _make_tar(tar, {"a/x.c": b"int a;\n", "a/b/y.txt": b"hello\n"})
    root = extract_tar(tar, tmp_path / "out")
    names = list_files(root)
    assert "a/x.c" in names
    assert "a/b/y.txt" in names


def test_extract_rejects_traversal(tmp_path):
    tar = tmp_path / "r.tar.gz"
    with tarfile.open(tar, "w:gz") as tf:
        info = tarfile.TarInfo("../evil.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"evil"))
    with pytest.raises(ValueError):
        extract_tar(tar, tmp_path / "out")


def test_extract_rejects_absolute(tmp_path):
    tar = tmp_path / "r.tar.gz"
    with tarfile.open(tar, "w:gz") as tf:
        info = tarfile.TarInfo("/etc/passwd")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"evil"))
    with pytest.raises(ValueError):
        extract_tar(tar, tmp_path / "out")


def test_grep(tmp_path):
    (tmp_path / "a.c").write_text("int main() { return 0; }\n")
    (tmp_path / "b.c").write_text("void f() { LLVMFuzzerTestOneInput(); }\n")
    hits = grep(r"LLVMFuzzerTestOneInput", tmp_path)
    assert len(hits) == 1
    assert hits[0]["file"] == "b.c"


def test_submit_result_crashed():
    assert SubmitResult("t", 77, "out", "p", {}).crashed is True
    assert SubmitResult("t", 0, "out", "p", {}).crashed is False
    assert SubmitResult("t", None, "out", "p", {}).crashed is False
