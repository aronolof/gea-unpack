from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .errors import GeaError
from .unpack import DEFAULT_MAX_OUTPUT, extract_archive, inspect_archive, report_to_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract and verify Gentee GEA members.")
    parser.add_argument(
        "input", type=Path, help="Main GEA volume, archive directory or PE installer"
    )
    parser.add_argument("-d", "--out-dir", type=Path)
    parser.add_argument(
        "--member", help="Exact member path to extract (solid prerequisites are decoded)"
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--list", action="store_true", help="Inspect without decoding or writing")
    actions.add_argument("--test", action="store_true", help="Decode and verify without writing")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--force", action="store_true", help="Replace existing output files")
    parser.add_argument(
        "--max-output",
        type=int,
        default=DEFAULT_MAX_OUTPUT,
        help="Total decoded bytes, including solid prerequisites; 0: unlimited",
    )
    args = parser.parse_args(argv)
    if args.max_output < 0:
        parser.error("--max-output must be non-negative")
    if (args.list or args.test) and (args.out_dir or args.force):
        parser.error("Inspection/validation cannot be combined with output options")
    if args.list and args.member:
        parser.error("--member is for extraction or --test")
    try:
        if args.list:
            report = inspect_archive(args.input)
        else:
            report = extract_archive(
                args.input,
                args.out_dir,
                member=args.member,
                test=args.test,
                force=args.force,
                max_output=args.max_output or None,
            )
        if args.json:
            print(report_to_json(report))
        else:
            for member in report.members:
                print(
                    f"{member['member_name']}\t{member['bytes']}\t"
                    f"{'verified' if member.get('verified') else 'listed'}"
                )
        return 0
    except (GeaError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
