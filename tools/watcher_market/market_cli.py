"""The marketplace registry commands, shared by ``watcher market`` and a vendored copy (``python -m watcher_market``,
see ``market.vendor``). Only the standard library at import time: ``watcher``'s parser builds it for free, and
``market`` (pydantic) loads when a command runs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

# market.KINDS, written out: the parser is built without importing market (a test pins them).
KINDS_CHOICES = (
    "extension", "skill_pack", "bot_template", "mcp_preset", "sticker_pack",
    "lens_suite", "avatar_pack", "persona_pack", "check_pack", "voice_model",
)


def add_commands(cmd: Any, fn: Callable[[argparse.Namespace], int] | None = None) -> None:
    """Add the registry commands to ``cmd`` (an ``add_subparsers`` result); each runs ``fn`` when it is given."""
    parsers = []
    keygen = cmd.add_parser("keygen", help="write a new signing key (mode 0600) and print its did:key")
    keygen.add_argument("--name", required=True, help="the key's name, e.g. official or my-publisher")
    keygen.add_argument("--out", help="the key file (default ~/.config/watcher-market/<name>.key)")
    parsers.append(keygen)
    did = cmd.add_parser("did", help="print a key file's did:key, never the key")
    did.add_argument("--key", required=True)
    parsers.append(did)
    new = cmd.add_parser("new", help="start an item: item.json and a working 1.0.0/ of its kind")
    new.add_argument("source")
    new.add_argument("item_id", metavar="ITEM_ID", help="publisher/name")
    new.add_argument("--kind", required=True, choices=KINDS_CHOICES)
    new.add_argument("--title", required=True)
    new.add_argument("--summary", required=True)
    new.add_argument("--url", help="an MCP preset's https address")
    new.add_argument("--domain", default="general", help="a skill pack's domain tag")
    new.add_argument("--key", help="your publisher key (writes publishers/<publisher>.json when it is missing)")
    new.add_argument("--publisher-name", help="your name in a new publishers/<publisher>.json")
    parsers.append(new)
    version = cmd.add_parser("version", help="add a version: a copy of the newest (or --from) version folder")
    version.add_argument("source")
    version.add_argument("item_id", metavar="ITEM_ID")
    version.add_argument("version", metavar="VERSION")
    version.add_argument("--from", dest="base", metavar="BASE", help="the version folder to copy")
    parsers.append(version)
    revoke = cmd.add_parser("revoke", help="withdraw a version (or * for all) in revoked.json")
    revoke.add_argument("source")
    revoke.add_argument("item_id", metavar="ITEM_ID")
    revoke.add_argument("version", metavar="VERSION")
    revoke.add_argument("--reason", required=True)
    parsers.append(revoke)
    rotate = cmd.add_parser("rotate", help="move a publisher to a new key; the old key signs the handover")
    rotate.add_argument("source")
    rotate.add_argument("--publisher", required=True)
    rotate.add_argument("--key", required=True, help="the publisher's current key")
    rotate.add_argument("--new-key", required=True, help="the new key (watcher market keygen)")
    parsers.append(rotate)
    retire = cmd.add_parser("retire", help="retire a publisher key: versions it signed after --until (or all, with "
                            "--compromised) count as withdrawn")
    retire.add_argument("source")
    retire.add_argument("--publisher", required=True)
    retire.add_argument("--reason", required=True)
    retire.add_argument("--did", help="the key to retire (default the current key)")
    retire.add_argument("--new-key", help="the publisher's new key, needed when the current key retires")
    retire.add_argument("--until", help="YYYY-MM-DDTHH:MM:SSZ (default now); only moves earlier")
    retire.add_argument("--compromised", action="store_true", help="every version the key signed is distrusted")
    parsers.append(retire)
    sign = cmd.add_parser("sign", help="sign a publisher's unsigned or changed bundles in a registry source")
    sign.add_argument("source")
    sign.add_argument("--publisher", required=True)
    sign.add_argument("--key", required=True)
    parsers.append(sign)
    lint = cmd.add_parser("lint", help="check a registry source (screenshots and requirements too) without any key; "
                          "with --site, also that the built site (index, bundles, screenshots, pages) matches it")
    lint.add_argument("source")
    lint.add_argument("--site", help="the built site (build's --out)")
    parsers.append(lint)
    build = cmd.add_parser("build", help="pack the bundles and write the signed site (index.json, bundles/, catalog "
                           "pages)")
    build.add_argument("source")
    build.add_argument("--out", required=True)
    build.add_argument("--key", required=True, help="the registry's key")
    build.add_argument("--previous-key", help="while moving the registry's key: the old key endorses the index")
    parsers.append(build)
    check = cmd.add_parser("check", help="verify a built site as wctl does")
    check.add_argument("dir")
    check.add_argument("--did", required=True, help="the registry's did:key")
    parsers.append(check)
    export = cmd.add_parser("export", help="write a signed item file an admin imports without a registry (#/market "
                            "→ Import a file)")
    export.add_argument("source")
    export.add_argument("item_id", metavar="ITEM_ID")
    export.add_argument("--key", required=True, help="the publisher's key")
    export.add_argument("--version", help="a signed version (default the newest)")
    export.add_argument("--out", help="the file (default <publisher>-<name>-<version>.market.json)")
    parsers.append(export)
    trial = cmd.add_parser("try", help="a throwaway-signed item file for a test stack (RWCTL_MARKET_TRY=1); signs "
                           "nothing in the source")
    trial.add_argument("source")
    trial.add_argument("item_id", metavar="ITEM_ID")
    trial.add_argument("--version", help="a version folder (default the newest)")
    trial.add_argument("--out", help="the file (default try-<publisher>-<name>-<version>.market.json)")
    trial.add_argument("--key", help="the throwaway key (default ~/.config/watcher-market/try.key, made when missing)")
    parsers.append(trial)
    check_item = cmd.add_parser("check-item", help="verify an item file as wctl's import does")
    check_item.add_argument("file")
    parsers.append(check_item)
    diff = cmd.add_parser("diff", help="what version B changes against A (a registry source or built site), as the "
                          "console's update preview")
    diff.add_argument("where", metavar="WHERE", help="a registry source (registry.json) or a built site (index.json)")
    diff.add_argument("item_id", metavar="ITEM_ID")
    diff.add_argument("a", metavar="A")
    diff.add_argument("b", metavar="B")
    diff.add_argument("--json", action="store_true", help="print the result as JSON")
    parsers.append(diff)
    if fn is not None:
        for parser in parsers:
            parser.set_defaults(fn=fn)


def run(args: argparse.Namespace, prog: str = "watcher market") -> int:
    """Run one registry command. Never prints a key, only its did:key."""
    from . import market  # noqa: PLC0415 - pydantic loads only when a command runs

    command = args.market_command
    try:
        if command == "keygen":
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", args.name):
                print("rw: --name is lower-case letters, digits and dashes", file=sys.stderr)
                return 2
            path = Path(args.out) if args.out else market.DEFAULT_KEY_DIR / f"{args.name}.key"
            did = market.keygen(path)
            print(f"{did}\nkey written to {path.expanduser()} (mode 0600; keep it out of every repository)")
        elif command == "did":
            print(market.key_did(market.load_key(Path(args.key))))
        elif command == "new":
            folder = market.scaffold(
                Path(args.source), args.item_id, args.kind, title=args.title, summary=args.summary, url=args.url,
                domain=args.domain, key=Path(args.key) if args.key else None, publisher_name=args.publisher_name,
            )
            pub, _ = market.split_id(args.item_id)
            print(f"wrote {folder}\nnext:\n  1. edit item.json and 1.0.0/ (the real description and files)\n"
                  f"  2. {prog} lint {args.source}\n  3. {prog} sign {args.source} --publisher {pub} --key <your key>")
        elif command == "version":
            folder = market.add_version(Path(args.source), args.item_id, args.version, base=args.base)
            print(f"wrote {folder}\nnext: edit it, write {folder.parent}/{args.version}.md (what changed), then "
                  f"{prog} lint and {prog} sign")
        elif command == "revoke":
            market.revoke(Path(args.source), args.item_id, args.version, args.reason)
            print(f"withdrew {args.item_id} {args.version}: the maintainers build the site again and Watcher turns it "
                  "off on its next sync")
        elif command == "rotate":
            did = market.rotate(Path(args.source), args.publisher, Path(args.key), Path(args.new_key))
            print(f"{args.publisher} now signs with {did}; old versions stay valid. next: {prog} lint "
                  f"{args.source}, open a pull request")
        elif command == "retire":
            market.retire(
                Path(args.source), args.publisher, args.reason, did=args.did,
                new_key=Path(args.new_key) if args.new_key else None, until=args.until, compromised=args.compromised,
            )
            print(f"retired the key in publishers/{args.publisher}.json. next: {prog} sign {args.source} --publisher "
                  f"{args.publisher} --key <the current key> (re-signs what the old key may no longer cover), "
                  f"{prog} lint, open a pull request")
        elif command == "sign":
            signed = market.sign(Path(args.source), args.publisher, Path(args.key))
            print("\n".join(f"signed {s}" for s in signed) or "every version is already signed")
        elif command == "lint":
            problems = market.lint(Path(args.source), Path(args.site) if args.site else None)
            for p in problems:
                print(p, file=sys.stderr)
            if problems:
                return 1
            light = "" if market.DEEP else (" (light checks: Watcher's watcher market lint also checks extension.json "
                                            "and template.json fully)")
            print(f"{args.source}: lints clean{light}")
        elif command == "build":
            built = market.build(Path(args.source), Path(args.out), Path(args.key),
                                 previous_key=Path(args.previous_key) if args.previous_key else None)
            versions = sum(len(i.versions) for i in built.index.items)
            media = sum(len(i.media) for i in built.index.items)
            print(f"built {args.out}: {len(built.index.items)} items, {versions} versions, "
                  f"{len(built.index.items) + 1} pages, {media} screenshots, signed by "
                  f"{market.key_did(market.load_key(Path(args.key)))}")
        elif command == "check":
            problems = market.check(Path(args.dir), args.did)
            for p in problems:
                print(p, file=sys.stderr)
            if problems:
                return 1
            print(f"{args.dir}: the index, every bundle and every screenshot verify")
        elif command == "export":
            path = market.export(Path(args.source), args.item_id, Path(args.key), version=args.version,
                                 out=Path(args.out) if args.out else None)
            print(f"wrote {path}\nnext: an admin imports it on #/market → Import a file (signed by its publisher; no "
                  "registry vouches for it)")
        elif command == "try":
            path = market.try_file(Path(args.source), args.item_id, version=args.version,
                                   out=Path(args.out) if args.out else None, key=Path(args.key) if args.key else None)
            print(f"wrote {path}\nnext: on a test stack started with RWCTL_MARKET_TRY=1, open #/market → Import a "
                  "file, then install once without trusting. Never import it on a real workspace (it refuses).")
        elif command == "check-item":
            parsed, _ = market.read_item_file(Path(args.file))
            v = parsed.item.versions[0]
            trial = " (a try file: only a test stack imports it)" if parsed.trial else ""
            print(f"{args.file}: {parsed.item.id} {v.version} ({parsed.item.kind}) verifies, signed by "
                  f"{parsed.publisher.did}{trial}")
        else:
            result = market.diff(Path(args.where), args.item_id, args.a, args.b)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else _diff_text(result, Path(args.where)))
    except (OSError, ValueError) as exc:
        print(f"rw: {exc}", file=sys.stderr)
        return 1
    return 0


def _diff_text(result: dict[str, Any], where: Path) -> str:
    """``diff``'s result, one line per change."""
    lines = [f"{result['item']} {result['from']} → {result['to']} ({result['kind']})"]
    for key, value in result["changes"].items():
        if not value:
            continue
        if isinstance(value, dict):
            text = "; ".join(f"{k}: {', '.join(v)}" for k, v in value.items())
        elif isinstance(value, list):
            text = ", ".join(value)
        else:
            text = "yes"
        lines.append(f"  {key.replace('_', ' ')}: {text}")
    if len(lines) == 1:
        lines.append("  nothing the update preview lists")
    files = result["files"]
    lines.append(f"  files: {len(files['added'])} added, {len(files['removed'])} removed, "
                 f"{len(files['changed'])} changed")
    if not (where / "registry.json").is_file():
        lines.append("  (bundles checked against their publisher's signature; check --did verifies the registry's)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m watcher_market", description="Watcher Marketplace registry tools")
    add_commands(parser.add_subparsers(dest="market_command", required=True))
    return run(parser.parse_args(argv), prog="python -m watcher_market")
