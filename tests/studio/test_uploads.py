"""Uploads remain bounded data, with exact identity when copied into a task."""

import base64
import hashlib
import json
from pathlib import Path
import stat

import pytest

from studio.uploads import MAX_BASE64_CHARS, MAX_FILE_BYTES, TestInputStore


def encoded(value):
    return base64.b64encode(value).decode("ascii")


@pytest.fixture
def uploads(tmp_path):
    return TestInputStore(tmp_path / "studio")


def test_binary_poc_round_trip_and_private_file(uploads, tmp_path):
    content = b"\x00\xff\x80\r\nTIFF\x00"
    info = uploads.create("poc", "poc.tiff", encoded(content))
    assert set(info) == {"id", "filename", "size", "sha256", "kind"}
    assert len(info["id"]) == 32
    assert info["size"] == len(content)
    assert info["sha256"] == hashlib.sha256(content).hexdigest()
    assert uploads.metadata(info["id"], "poc") == info
    disk = uploads.directory / info["id"] / "content.bin"
    assert disk.read_bytes() == content
    assert stat.S_IMODE(disk.stat().st_mode) == 0o600
    case = tmp_path / "task/input/CVE-fixture"
    case.mkdir(parents=True)
    staged = uploads.copy_to_case(info["id"], case, "poc")
    assert staged["relative_path"] == f".kea-test-inputs/{info['id']}/input.tiff"
    assert (case / staged["relative_path"]).read_bytes() == content
    assert uploads.copy_to_case(info["id"], case, "poc") == staged


def test_units_are_stored_without_execution(uploads, tmp_path):
    marker = tmp_path / "executed"
    script = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
    info = uploads.create("unit", "my tests.PY", encoded(script))
    case = tmp_path / "case"
    case.mkdir()
    staged = uploads.copy_to_case(info["id"], case, "unit")
    assert staged["relative_path"].endswith("/input.py")
    assert not marker.exists()
    assert not (case / staged["relative_path"]).stat().st_mode & 0o111
    assert uploads.create("unit", "test.sh", encoded(b"exit 0\n"))["kind"] == "unit"


def test_empty_poc_is_valid_input_but_empty_unit_is_not(uploads):
    info = uploads.create("poc", "empty.dat", "")
    assert uploads.metadata(info["id"])["size"] == 0
    with pytest.raises(ValueError, match="must not be empty"):
        uploads.create("unit", "test.py", "")


@pytest.mark.parametrize("kind,filename,value", [
    ("arbitrary", "poc.bin", "YQ=="),
    ("poc", "../poc.bin", "YQ=="), ("poc", "/tmp/poc.bin", "YQ=="),
    ("poc", "C:\\temp\\poc.bin", "YQ=="), ("poc", "bad\nname.bin", "YQ=="),
    ("poc", "", "YQ=="), ("poc", ".", "YQ=="), ("poc", "a" * 256, "YQ=="),
    ("unit", "tests.zip", "YQ=="), ("unit", "tests.py.exe", "YQ=="),
    ("unit", "test", "YQ=="), ("poc", "poc.bin", "invalid!"),
    ("poc", "poc.bin", "data:application/octet-stream;base64,YQ=="),
    ("poc", "poc.bin", "YQ==\n"), ("poc", "poc.bin", "中文"),
    ("poc", "poc.bin", None),
])
def test_invalid_upload_input_rejected_without_writing(uploads, kind, filename, value):
    with pytest.raises(ValueError):
        uploads.create(kind, filename, value)
    assert list(uploads.directory.iterdir()) == []


def test_file_size_limit_checks_encoded_and_decoded_length(uploads):
    with pytest.raises(ValueError, match="10 MiB"):
        uploads.create("poc", "large.bin", "a" * (MAX_BASE64_CHARS + 1))
    # A base64 quartet can encode up to three bytes, so also check after decode.
    value = b"a" * (MAX_FILE_BYTES + 1)
    assert len(encoded(value)) == MAX_BASE64_CHARS
    with pytest.raises(ValueError, match="10 MiB"):
        uploads.create("poc", "large.bin", encoded(value))
    accepted = uploads.create("poc", "boundary.bin", encoded(value[:-1]))
    assert uploads.metadata(accepted["id"])["size"] == MAX_FILE_BYTES


@pytest.mark.parametrize("identity", ["missing", "../other", "a" * 32, None, "A" * 32])
def test_unknown_or_invalid_id_rejected(uploads, identity):
    with pytest.raises(ValueError):
        uploads.metadata(identity)


def test_kind_cannot_be_swapped(uploads, tmp_path):
    info = uploads.create("poc", "input.py", encoded(b"assert True\n"))
    with pytest.raises(ValueError, match="uploaded unit"):
        uploads.metadata(info["id"], "unit")
    with pytest.raises(ValueError, match="uploaded unit"):
        uploads.copy_to_case(info["id"], tmp_path, "unit")


@pytest.mark.parametrize("tamper", ["content", "size", "hash", "id", "filename", "json"])
def test_saved_content_and_metadata_tampering_rejected(uploads, tamper):
    info = uploads.create("unit", "test.py", encoded(b"assert True\n"))
    directory = uploads.directory / info["id"]
    metadata = directory / "metadata.json"
    if tamper == "content":
        (directory / "content.bin").write_bytes(b"assert False")
    elif tamper == "json":
        metadata.write_text("broken-json")
    else:
        value = json.loads(metadata.read_text())
        field = {"hash": "sha256"}.get(tamper, tamper)
        value[field] = {"size": 999, "hash": "0" * 64, "id": "0" * 32, "filename": "../test.py"}[tamper]
        metadata.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        uploads.metadata(info["id"])


@pytest.mark.parametrize("name", ["content.bin", "metadata.json"])
def test_stored_symlinks_are_not_followed(uploads, tmp_path, name):
    info = uploads.create("unit", "test.py", encoded(b"assert True\n"))
    source = uploads.directory / info["id"] / name
    other = tmp_path / "outside"
    source.rename(other)
    source.symlink_to(other)
    with pytest.raises(ValueError):
        uploads.metadata(info["id"])


def test_staging_refuses_symlink_or_conflicting_content(uploads, tmp_path):
    info = uploads.create("poc", "poc.bin", encoded(b"original"))
    case = tmp_path / "case"
    case.mkdir()
    (case / ".kea-test-inputs").symlink_to(uploads.directory, target_is_directory=True)
    with pytest.raises(ValueError):
        uploads.copy_to_case(info["id"], case, "poc")
    (case / ".kea-test-inputs").unlink()
    staged = uploads.copy_to_case(info["id"], case, "poc")
    (case / staged["relative_path"]).write_bytes(b"other")
    with pytest.raises(ValueError, match="does not match"):
        uploads.copy_to_case(info["id"], case, "poc")


def test_filename_never_controls_host_storage_path(uploads, tmp_path):
    name = "input.$(touch owned)"
    info = uploads.create("poc", name, encoded(b"data"))
    staged = uploads.copy_to_case(info["id"], tmp_path, "poc")
    assert staged["filename"] == name
    assert staged["relative_path"].endswith("/input.bin")
    assert not (tmp_path / "owned").exists()


def test_reopening_store_preserves_input_identity(uploads):
    info = uploads.create("unit", "test.sh", encoded(b"exit 0\n"))
    again = TestInputStore(uploads.root)
    assert again.metadata(info["id"], "unit") == info
