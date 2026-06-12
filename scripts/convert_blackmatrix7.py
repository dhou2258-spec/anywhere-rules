#!/usr/bin/env python3
"""Convert blackmatrix7 Surge rule lists into Anywhere routing rule sets."""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import shutil
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


SUPPORTED_TYPES = {
    "DOMAIN": 2,
    "DOMAIN-SUFFIX": 2,
    "DOMAIN-KEYWORD": 3,
    "IP-CIDR": 0,
    "IP-CIDR6": 1,
}

SKIPPED_TYPES = {
    "AND",
    "DEST-PORT",
    "DOMAIN-REGEX",
    "GEOIP",
    "HOST",
    "HOST-KEYWORD",
    "HOST-SUFFIX",
    "HOST-WILDCARD",
    "IP-ASN",
    "IP6-CIDR",
    "IP-CIDR6-COMPACT",
    "IP-CIDR-COMPACT",
    "IP-CIDR-COMPACT6",
    "IP-CIDR6-COMPACT",
    "NOT",
    "OR",
    "PROCESS-NAME",
    "RULE-SET",
    "SCRIPT",
    "URL-REGEX",
    "USER-AGENT",
}

MAX_RULES_PER_SET = 100000


@dataclass
class ConvertedRuleSet:
    name: str
    source_path: str
    output_path: str
    rule_count: int
    skipped_count: int
    unsupported_types: dict[str, int] = field(default_factory=dict)
    upstream_updated: str | None = None


def request_headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "anywhere-rules-converter",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_bytes(url: str, token: str | None = None, retries: int = 4) -> bytes:
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            req = Request(url, headers=request_headers(token))
            with urlopen(req, timeout=60) as response:
                return response.read()
        except (HTTPError, URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_error = exc
            if attempt == retries - 1:
                break
            time.sleep(2**attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error


def fetch_json(url: str, token: str | None = None) -> object:
    return json.loads(fetch_bytes(url, token).decode("utf-8"))


def discover_source_paths(
    repo: str,
    branch: str,
    source_family: str,
    token: str | None,
) -> tuple[list[str], str | None]:
    url = f"https://api.github.com/repos/{repo}/git/trees/{quote(branch)}?recursive=1"
    payload = fetch_json(url, token)
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected GitHub tree response.")
    if payload.get("truncated"):
        raise RuntimeError("GitHub tree response was truncated; use a narrower source family.")

    prefix = f"rule/{source_family}/"
    paths: list[str] = []
    for entry in payload.get("tree", []):
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if (
            entry.get("type") == "blob"
            and isinstance(path, str)
            and path.startswith(prefix)
            and path.endswith(".list")
        ):
            paths.append(path)
    tree_sha = payload.get("sha")
    return sorted(paths), tree_sha if isinstance(tree_sha, str) else None


def parse_comment_metadata(lines: Iterable[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line.startswith("#"):
            continue
        body = line[1:].strip()
        if ":" not in body:
            continue
        key, value = body.split(":", 1)
        metadata[key.strip().upper()] = value.strip()
    return metadata


def split_rule_line(line: str) -> list[str]:
    try:
        return [part.strip() for part in next(csv.reader([line], skipinitialspace=True))]
    except csv.Error:
        return []


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("+."):
        domain = domain[2:]
    if domain.startswith("*."):
        domain = domain[2:]
    elif domain.startswith("."):
        domain = domain[1:]
    if not domain or "*" in domain or "?" in domain or "/" in domain:
        return None
    return domain


def normalize_keyword(value: str) -> str | None:
    keyword = value.strip().lower()
    if not keyword or "*" in keyword or "?" in keyword or "/" in keyword:
        return None
    return keyword


def convert_domain_wildcard(value: str) -> tuple[int, str] | None:
    domain = normalize_domain(value)
    if domain is None:
        return None
    return 2, domain


def convert_line(line: str) -> tuple[tuple[int, str] | None, str | None]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("//"):
        return None, None

    fields = split_rule_line(stripped)
    if len(fields) < 2:
        return None, "UNKNOWN"

    rule_type = fields[0].upper()
    value = fields[1]

    if rule_type == "DOMAIN-WILDCARD":
        converted = convert_domain_wildcard(value)
        return converted, None if converted else rule_type

    anywhere_type = SUPPORTED_TYPES.get(rule_type)
    if anywhere_type is None:
        return None, rule_type if rule_type in SKIPPED_TYPES or rule_type else "UNKNOWN"

    if anywhere_type == 2:
        normalized = normalize_domain(value)
        if normalized is None:
            return None, rule_type
        return (anywhere_type, normalized), None
    if anywhere_type == 3:
        normalized = normalize_keyword(value)
        if normalized is None:
            return None, rule_type
        return (anywhere_type, normalized), None

    cidr = value.strip()
    if not cidr:
        return None, rule_type
    return (anywhere_type, cidr), None


def output_path_for(source_path: str, source_family: str, dist: Path) -> Path:
    prefix = f"rule/{source_family}/"
    relative = source_path.removeprefix(prefix)
    return dist / "all" / Path(relative).with_suffix(".arrs")


def raw_url(repo: str, branch: str, source_path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{quote(branch)}/{quote(source_path, safe='/')}"


def write_rule_set_file(
    destination: Path,
    name: str,
    repo: str,
    branch: str,
    source_path: str,
    rules: list[tuple[int, str]],
    skipped_count: int,
    unsupported: dict[str, int],
    upstream_updated: str | None,
    total_rules: int | None = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    body = [
        f"# NAME: {name}",
        "# AUTHOR: blackmatrix7",
        f"# SOURCE: https://github.com/{repo}/blob/{branch}/{source_path}",
        "# GENERATED-FOR: Anywhere Routing Rule Set",
        "# NOTE: DOMAIN rules are mapped to Anywhere domain suffix rules.",
        f"# RULES: {len(rules)}",
        f"# SKIPPED: {skipped_count}",
    ]
    if total_rules is not None and total_rules != len(rules):
        body.append(f"# SOURCE-RULES: {total_rules}")
    if upstream_updated:
        body.append(f"# UPSTREAM-UPDATED: {upstream_updated}")
    if unsupported:
        summary = ", ".join(f"{key}={unsupported[key]}" for key in sorted(unsupported))
        body.append(f"# SKIPPED-TYPES: {summary}")
    body.extend(["", f"name = {name}"])
    body.extend(f"{rule_type}, {value}" for rule_type, value in rules)
    destination.write_text("\n".join(body) + "\n", encoding="utf-8")


def split_destination(destination: Path, index: int) -> Path:
    return destination.with_name(f"{destination.stem}_{index:02d}{destination.suffix}")


def build_converted_outputs(
    name: str,
    repo: str,
    branch: str,
    source_path: str,
    destination: Path,
    dist: Path,
    rules: list[tuple[int, str]],
    unsupported: dict[str, int],
    upstream_updated: str | None,
) -> list[ConvertedRuleSet]:
    skipped_count = sum(unsupported.values())
    if len(rules) <= MAX_RULES_PER_SET:
        write_rule_set_file(
            destination,
            name,
            repo,
            branch,
            source_path,
            rules,
            skipped_count,
            unsupported,
            upstream_updated,
        )
        return [
            ConvertedRuleSet(
                name=name,
                source_path=source_path,
                output_path=destination.relative_to(dist).as_posix(),
                rule_count=len(rules),
                skipped_count=skipped_count,
                unsupported_types=unsupported,
                upstream_updated=upstream_updated,
            )
        ]

    chunks = [
        rules[index:index + MAX_RULES_PER_SET]
        for index in range(0, len(rules), MAX_RULES_PER_SET)
    ]
    converted: list[ConvertedRuleSet] = []
    for index, chunk in enumerate(chunks, start=1):
        part_name = f"{name}_{index:02d}"
        part_destination = split_destination(destination, index)
        part_unsupported = unsupported if index == 1 else {}
        part_skipped_count = skipped_count if index == 1 else 0
        write_rule_set_file(
            part_destination,
            part_name,
            repo,
            branch,
            source_path,
            chunk,
            part_skipped_count,
            part_unsupported,
            upstream_updated,
            total_rules=len(rules),
        )
        converted.append(
            ConvertedRuleSet(
                name=part_name,
                source_path=source_path,
                output_path=part_destination.relative_to(dist).as_posix(),
                rule_count=len(chunk),
                skipped_count=part_skipped_count,
                unsupported_types=part_unsupported,
                upstream_updated=upstream_updated,
            )
        )
    return converted


def convert_source(
    repo: str,
    branch: str,
    source_family: str,
    dist: Path,
    source_path: str,
    token: str | None,
) -> list[ConvertedRuleSet]:
    text = fetch_bytes(raw_url(repo, branch, source_path), token=None).decode("utf-8-sig")
    lines = text.splitlines()
    metadata = parse_comment_metadata(lines)

    default_name = Path(source_path).stem
    name = metadata.get("NAME") or default_name
    seen: set[tuple[int, str]] = set()
    rules: list[tuple[int, str]] = []
    unsupported: dict[str, int] = {}

    for line in lines:
        converted, skipped_type = convert_line(line)
        if converted is not None and converted not in seen:
            seen.add(converted)
            rules.append(converted)
        elif skipped_type:
            unsupported[skipped_type] = unsupported.get(skipped_type, 0) + 1

    destination = output_path_for(source_path, source_family, dist)
    return build_converted_outputs(
        name=name,
        repo=repo,
        branch=branch,
        source_path=source_path,
        destination=destination,
        dist=dist,
        rules=rules,
        unsupported=unsupported,
        upstream_updated=metadata.get("UPDATED"),
    )


def matches_include(path: str, includes: list[str]) -> bool:
    if not includes:
        return True
    name = Path(path).stem
    relative = path.removeprefix("rule/")
    return any(
        fnmatch.fnmatch(path, pattern)
        or fnmatch.fnmatch(relative, pattern)
        or fnmatch.fnmatch(name, pattern)
        for pattern in includes
    )


def write_catalog(dist: Path, index: dict[str, object]) -> None:
    files = index.get("files", [])
    upstream = index.get("upstream", {})
    upstream_label = ""
    if isinstance(upstream, dict):
        upstream_label = (
            f"{upstream.get('repo', '')}@{upstream.get('branch', '')}"
            f" ({upstream.get('tree_sha', 'unknown tree')})"
        )
    lines = [
        "# Anywhere Rules Catalog",
        "",
        f"Generated from upstream: `{upstream_label}`",
        "",
        "| Name | Rules | Skipped | File |",
        "| --- | ---: | ---: | --- |",
    ]
    if isinstance(files, list):
        for item in files:
            if not isinstance(item, dict):
                continue
            name = str(item["name"]).replace("|", "\\|")
            output = str(item["output_path"])
            lines.append(
                f"| {name} | {item['rule_count']} | {item['skipped_count']} | "
                f"[{output}](./{output}) |"
            )
    (dist / "catalog.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="blackmatrix7/ios_rule_script")
    parser.add_argument("--branch", default="master")
    parser.add_argument("--source-family", default="Surge")
    parser.add_argument("--dist", default="rules")
    parser.add_argument("--include", action="append", default=[], help="Glob filter for testing.")
    parser.add_argument("--limit", type=positive_int, help="Maximum source files to convert.")
    parser.add_argument("--workers", type=positive_int, default=8)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    dist = Path(args.dist)
    rules_dir = dist / "all"
    if rules_dir.exists():
        shutil.rmtree(rules_dir)
    dist.mkdir(parents=True, exist_ok=True)

    paths, tree_sha = discover_source_paths(args.repo, args.branch, args.source_family, token)
    paths = [path for path in paths if matches_include(path, args.include)]
    if args.limit:
        paths = paths[: args.limit]
    if not paths:
        raise RuntimeError("No source files matched.")

    converted: list[ConvertedRuleSet] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(
                convert_source,
                args.repo,
                args.branch,
                args.source_family,
                dist,
                source_path,
                token,
            )
            for source_path in paths
        ]
        for future in as_completed(futures):
            converted.extend(future.result())

    converted.sort(key=lambda item: item.output_path.lower())
    index = {
        "upstream": {
            "repo": args.repo,
            "branch": args.branch,
            "source_family": args.source_family,
            "tree_sha": tree_sha,
        },
        "total_files": len(converted),
        "total_rules": sum(item.rule_count for item in converted),
        "total_skipped": sum(item.skipped_count for item in converted),
        "files": [
            {
                "name": item.name,
                "source_path": item.source_path,
                "output_path": item.output_path,
                "rule_count": item.rule_count,
                "skipped_count": item.skipped_count,
                "unsupported_types": item.unsupported_types,
                "upstream_updated": item.upstream_updated,
            }
            for item in converted
        ],
    }
    (dist / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_catalog(dist, index)

    print(
        f"Converted {index['total_files']} files, "
        f"{index['total_rules']} rules, skipped {index['total_skipped']} entries.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
