#!/usr/bin/env python3
"""Generate a coverage matrix and run positive inventory checks on Linux AMD64."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
CATALOGERS = ROOT.parent.parent / "syft/pkg/cataloger"
STOCK_COMMIT = "1a72047fd46c72e0a12ee77e24b23d2316753d08"
ENV = {**os.environ, "SYFT_EXP_CAPABILITIES": "true", "SYFT_CHECK_FOR_APP_UPDATE": "false"}


def read(path):
    return json.loads(path.read_text())


def write(path, data):
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def command_json(binary, *args):
    return json.loads(subprocess.check_output([binary, *args], env=ENV))


def build_matrix(stock, cataloger_list, capabilities, fixtures):
    names = {entry["name"] for entry in cataloger_list["catalogers"]}
    matrix = {}
    for entry in capabilities["catalogers"]:
        ecosystem = entry["ecosystem"]
        if "language" not in entry["selectors"] and ecosystem not in fixtures:
            continue
        if entry["name"] not in names:
            raise ValueError(f"Capability describes a missing cataloger: {entry['name']}")
        for pattern in entry.get("patterns", []):
            matrix.setdefault(ecosystem, []).append({
                "cataloger": entry["name"],
                **pattern,
                "identity_evidence_status": "unverified",
            })
    if set(matrix) != set(fixtures):
        raise ValueError(f"Inventory fixtures differ from stock ecosystem scope: {set(matrix) ^ set(fixtures)}")
    return {
        "stock": stock,
        "ecosystems": {
            ecosystem: {
                "input_paths": paths,
                "inventory_fixture": fixtures[ecosystem],
                "inventory_results": {},
            }
            for ecosystem, paths in sorted(matrix.items())
        },
    }


def scan(binary, source, cataloger, output):
    output.mkdir(parents=True)
    syft_json = output / "syft.json"
    cdx_json = output / "cyclonedx.json"
    with (output / "stderr.log").open("w") as log:
        subprocess.run([
            binary, "scan", f"dir:{source}", "--override-default-catalogers", cataloger,
            "-o", f"syft-json={syft_json}", "-o", f"cyclonedx-json={cdx_json}",
        ], env=ENV, stderr=log, check=True)
    packages = [entry for entry in read(syft_json)["artifacts"] if entry["foundBy"] == cataloger]
    components = {entry["bom-ref"]: entry for entry in read(cdx_json).get("components", [])}
    if not packages:
        raise ValueError("the selected cataloger returned no packages")
    if len({pkg["id"] for pkg in packages}) != len(packages):
        raise ValueError("duplicate Syft package IDs")
    for pkg in packages:
        matches = [
            component for ref, component in components.items()
            if ref == pkg["id"] or parse_qs(urlsplit(ref).query).get("package-id") == [pkg["id"]]
        ]
        if len(matches) != 1:
            raise ValueError(f"expected one CycloneDX reference for {pkg['id']}")
        component = matches[0]
        if pkg.get("purl") and pkg["purl"] != component.get("purl"):
            raise ValueError(f"package URL changed in CycloneDX for {pkg['id']}")
    return {"status": "pass", "packages": len(packages)}


def binary_identity(binary):
    version = command_json(binary, "version", "-o", "json")
    if version["platform"] != "linux/amd64":
        raise ValueError(f"Expected Linux AMD64 binary, got {version['platform']}")
    with open(binary, "rb") as stream:
        return {**version, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--candidate", type=Path)
    args = parser.parse_args()
    stock = args.stock.resolve()
    stock_version = binary_identity(stock)
    if stock_version["gitCommit"] != STOCK_COMMIT or stock_version["version"] != "1.57.2":
        raise ValueError("Expected the stock Syft v1.57.2 release")
    args.output.mkdir(parents=True)
    cataloger_list = command_json(stock, "cataloger", "list", "-o", "json")
    capabilities = command_json(stock, "cataloger", "info", "-o", "json")
    write(args.output / "cataloger-list.json", cataloger_list)
    write(args.output / "cataloger-info.json", capabilities)
    fixtures = read(ROOT / "inventory-fixtures.json")
    matrix = build_matrix(stock_version, cataloger_list, capabilities, fixtures)
    binaries = {"stock": stock}
    if args.candidate:
        binaries["candidate"] = args.candidate.resolve()
        matrix["candidate"] = binary_identity(binaries["candidate"])
    for ecosystem, row in matrix["ecosystems"].items():
        cataloger, location, *renamed = row["inventory_fixture"]
        directory, path = location.split("/", 1)
        fixture = ROOT / path if directory == "." else CATALOGERS / directory / "testdata" / path
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            if fixture.is_file():
                shutil.copy2(fixture, source / (renamed[0] if renamed else fixture.name))
            else:
                shutil.copytree(fixture, source, dirs_exist_ok=True)
            for lane, binary in binaries.items():
                output = args.output / lane / ecosystem
                try:
                    result = scan(binary, source, cataloger, output)
                except (OSError, ValueError, subprocess.CalledProcessError) as error:
                    result = {"status": "fail", "error": str(error)}
                row["inventory_results"][lane] = result
    write(args.output / "matrix.json", matrix)
    return any(
        result["status"] != "pass"
        for row in matrix["ecosystems"].values()
        for result in row["inventory_results"].values()
    )


if __name__ == "__main__":
    raise SystemExit(main())
