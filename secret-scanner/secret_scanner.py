#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


@dataclass
class SecretFinding:
    filename: str
    line_number: int
    matched_text: str
    pattern_name: str


SECRET_PATTERNS = [
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}")
    ),
    (
        "AWS Secret Key",
        re.compile(r"(?i)aws(.{0,20})?(secret|secretaccesskey)(.{0,20})?[=:\s]?[0-9a-zA-Z/+=]{40}")
    ),
    (
        "Generic API Key",
        re.compile(r'''(?i)(api[_-]?key|apikey|secret|token|access[_-]?token|client[_-]?secret)["'`\s:=]{1,5}[A-Za-z0-9\-_=]{16,100}''')
    ),
    (
        "Generic Password",
        re.compile(r'''(?i)(password|pass|pwd|passwd|secret)["'`\s:=]{1,5}[^\"]{6,100}''')
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")
    ),
    (
        "Private Key File Reference",
        re.compile(r"(?i)(-----BEGIN CERTIFICATE-----|ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)")
    ),
]


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def is_text_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(4096)
            if b"\x00" in chunk:
                return False
    except OSError as exc:
        logging.debug("Unable to read file %s: %s", path, exc)
        return False
    return True


def count_files_in_directory(path: Path) -> int:
    total = 0
    for _, _, files in os.walk(path):
        total += len(files)
    return total


def find_secrets_in_lines(filename: str, lines: Iterable[str]) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        for pattern_name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                matched_text = match.group(0)
                findings.append(
                    SecretFinding(
                        filename=filename,
                        line_number=line_number,
                        matched_text=matched_text,
                        pattern_name=pattern_name,
                    )
                )
    return findings


def scan_file(path: Path) -> List[SecretFinding]:
    if not path.exists():
        logging.warning("Skipping missing file: %s", path)
        return []

    if not path.is_file():
        logging.debug("Skipping non-file path: %s", path)
        return []

    if not is_text_file(path):
        logging.debug("Skipping likely binary file: %s", path)
        return []

    logging.debug("Scanning file: %s", path)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file_handle:
            return find_secrets_in_lines(str(path), file_handle)
    except OSError as exc:
        logging.warning("Unable to open file %s: %s", path, exc)
        return []


def scan_path(path: Path, progress: bool = False) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    if path.is_dir():
        total_files = count_files_in_directory(path) if progress else None
        if progress:
            logging.info("Scanning %s files in directory: %s", total_files, path)
        else:
            logging.info("Recursively scanning directory: %s", path)

        scanned = 0
        for root, _, files in os.walk(path):
            for name in files:
                scanned += 1
                file_path = Path(root) / name
                if progress and total_files is not None:
                    print(f"Scanning file {scanned}/{total_files}: {file_path}", end="\r", flush=True)
                findings.extend(scan_file(file_path))
        if progress:
            print()
    else:
        logging.info("Scanning file: %s", path)
        findings.extend(scan_file(path))
    return findings


def format_findings(findings: List[SecretFinding]) -> str:
    if not findings:
        return "No likely hardcoded secrets detected."

    lines = [
        "Detected potential hardcoded secrets:",
        "filename,line,pattern,match",
    ]
    for finding in findings:
        lines.append(
            f"{finding.filename},{finding.line_number},{finding.pattern_name},{finding.matched_text}"
        )
    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan files or directories for common hardcoded secret patterns."
    )
    parser.add_argument(
        "path",
        help="Path to a file or directory to scan.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write findings to a report file instead of stdout.",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose logging output.",
        action="store_true",
    )
    parser.add_argument(
        "-p",
        "--progress",
        help="Show scanning progress for directories.",
        action="store_true",
    )
    return parser.parse_args()


def write_report(report: str, output_path: Path) -> None:
    try:
        with output_path.open("w", encoding="utf-8") as output_file:
            output_file.write(report)
        logging.info("Report written to %s", output_path)
    except OSError as exc:
        logging.error("Unable to write report file %s: %s", output_path, exc)


def main() -> int:
    args = parse_arguments()
    configure_logging(args.verbose)

    path = Path(args.path).expanduser().resolve()
    if not path.exists():
        logging.error("Path does not exist: %s", path)
        return 1

    findings = scan_path(path, progress=args.progress)
    report = format_findings(findings)

    if args.output:
        write_report(report, Path(args.output))
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
