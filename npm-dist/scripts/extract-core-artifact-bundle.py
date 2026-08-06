#!/usr/bin/env python3
"""Extract an untrusted Core handoff bundle without archive path traversal."""

from __future__ import annotations

import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


MAX_MEMBERS = 100
MAX_UNCOMPRESSED_BYTES = 3 * 1024 * 1024 * 1024


def safe_name(raw: str) -> PurePosixPath:
    if not raw or "\\" in raw or "\x00" in raw:
        raise ValueError(f"unsafe archive member name: {raw!r}")
    name = PurePosixPath(raw)
    if name.is_absolute() or ".." in name.parts or not name.parts:
        raise ValueError(f"unsafe archive member name: {raw!r}")
    return name


def destination(root: Path, raw: str) -> Path:
    name = safe_name(raw)
    output = root.joinpath(*name.parts).resolve()
    output.relative_to(root.resolve())
    return output


def check_limits(count: int, total: int) -> None:
    if count > MAX_MEMBERS:
        raise ValueError(f"artifact bundle has more than {MAX_MEMBERS} members")
    if total > MAX_UNCOMPRESSED_BYTES:
        raise ValueError("artifact bundle exceeds the uncompressed size limit")


def extract_tar(bundle: Path, root: Path) -> None:
    with tarfile.open(bundle, "r:*") as archive:
        members = archive.getmembers()
        check_limits(len(members), sum(item.size for item in members))
        for member in members:
            if member.name in (".", "./") and member.isdir():
                continue
            output = destination(root, member.name)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(f"artifact bundle member must be a regular file: {member.name}")
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"cannot read artifact bundle member: {member.name}")
            with source, output.open("xb") as target:
                shutil.copyfileobj(source, target)


def extract_zip(bundle: Path, root: Path) -> None:
    with zipfile.ZipFile(bundle) as archive:
        members = archive.infolist()
        check_limits(len(members), sum(item.file_size for item in members))
        for member in members:
            output = destination(root, member.filename)
            mode = (member.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError(f"artifact bundle must not contain symlinks: {member.filename}")
            if member.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, output.open("xb") as target:
                shutil.copyfileobj(source, target)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract-core-artifact-bundle.py <bundle> <empty-output-dir>")
    bundle = Path(sys.argv[1]).resolve()
    root = Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise SystemExit(f"output directory must be empty: {root}")
    if tarfile.is_tarfile(bundle):
        extract_tar(bundle, root)
    elif zipfile.is_zipfile(bundle):
        extract_zip(bundle, root)
    else:
        raise SystemExit("public/starter Core artifact bundle must be tar or zip")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
