from pathlib import Path

import pytest

from huc.blocklist import BlockList, BlockRule


def make_exe(tmp_path: Path, name: str = "demo.exe", data: bytes = b"huc-test") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_blocklist_persists_path_and_hash(tmp_path: Path) -> None:
    db = tmp_path / "blocklist.json"
    exe = make_exe(tmp_path)
    blocks = BlockList(db)

    rule = blocks.add_path(exe)

    reloaded = BlockList(db)
    assert reloaded.path_blocked(str(exe))
    assert reloaded.match(str(exe)) == rule
    assert len(reloaded.rules()) == 1


def test_hash_match_survives_copy_to_new_path(tmp_path: Path) -> None:
    db = tmp_path / "blocklist.json"
    source = make_exe(tmp_path, "one.exe", b"same-binary")
    blocks = BlockList(db)
    rule = blocks.add_path(source)

    copied = make_exe(tmp_path, "renamed.exe", b"same-binary")

    assert blocks.match(str(copied), check_hash=False) is None
    assert blocks.match(str(copied), check_hash=True) == rule


def test_remove_rule(tmp_path: Path) -> None:
    db = tmp_path / "blocklist.json"
    exe = make_exe(tmp_path)
    blocks = BlockList(db)
    blocks.add_path(exe)

    assert blocks.remove(path=str(exe)) == 1
    assert not blocks.rules()


def test_protected_windows_process_name_refused(tmp_path: Path) -> None:
    exe = make_exe(tmp_path, "svchost.exe")

    with pytest.raises(ValueError):
        BlockRule.from_path(exe)
