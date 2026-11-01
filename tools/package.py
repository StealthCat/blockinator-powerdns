#!/usr/bin/env python3
"""Package the PowerDNS Recursor Lua hook and Python bridge for Linux hosts."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile


def package_version():
    match = re.search(r"^## (\d+\.\d+\.\d+)\b", Path("CHANGELOG.md").read_text(), re.M)
    if not match:
        raise SystemExit("No release version found in CHANGELOG.md")
    version = match.group(1)
    tag = os.environ.get("RELEASE_TAG", "")
    if tag:
        version = tag.removeprefix("v")
        if version not in {match.group(1), match.group(1).removesuffix(".0")}:
            raise SystemExit(f"Release tag {tag!r} does not match changelog version {match.group(1)}")
    return version


def write_package(name, files, build_info):
    output = Path("dist")
    output.mkdir(exist_ok=True)
    archive_path = output / f"{name}.tar.gz"
    for source in files.values():
        if not source.is_file() or source.stat().st_size == 0:
            raise SystemExit(f"Required package file is missing or empty: {source}")
    with tarfile.open(archive_path, "w:gz") as archive:
        for target, source in files.items():
            archive.add(source, arcname=f"{name}/{target}", recursive=False)
        data = build_info.encode()
        entry = tarfile.TarInfo(f"{name}/BUILD-INFO.txt")
        entry.size = len(data)
        entry.mode = 0o644
        archive.addfile(entry, io.BytesIO(data))
    with tarfile.open(archive_path, "r:gz") as archive:
        expected = {f"{name}/{target}" for target in files} | {f"{name}/BUILD-INFO.txt"}
        if set(archive.getnames()) != expected or len(archive.getmembers()) != len(expected):
            raise SystemExit("Unexpected package layout")
        for member in archive.getmembers():
            if not member.isfile() or not member.size:
                raise SystemExit(f"Invalid package member: {member.name}")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    archive_path.with_suffix(archive_path.suffix + ".sha256").write_text(
        f"{digest}  {archive_path.name}\n"
    )
    print(f"Created and validated {archive_path}")


def revision():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()

if __name__ == "__main__":
    version = package_version()
    name = f"blockinator-powerdns_v{version}"
    files = {path: Path(path) for path in [
        "bridge.py", "blockinator.lua", "requirements.txt", "bridge.env.example",
        "blockinator-powerdns.service", "README.md", "CHANGELOG.md", "LICENSE",
    ]}
    info = (f"Blockinator: {version}\nPlugin commit: {revision()}\n"
            "Target: PowerDNS Recursor on Linux with systemd; Python 3.10+\n"
            "Install Python dependencies from requirements.txt before starting the bridge.\n"
            "PowerDNS Recursor and Python dependencies are not bundled.\n")
    write_package(name, files, info)
