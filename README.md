# Watcher Marketplace

The official registry for Watcher's Marketplace: extensions, skill packs, starter bots (bot templates), MCP presets
and sticker packs. The site under `docs/` is served by GitHub Pages at
<https://ayashasw.github.io/watcher-marketplace/>; Watcher fetches `index.json` and the bundles from there and
verifies every signature before it shows or installs anything.

## Layout

```
registry/                                 the source
  registry.json                           {"name", "url", "did"?}
  publishers/<publisher>.json             {id, name, did, url?, verified?, previous_keys?}
  items/<publisher>/<name>/item.json      {kind, title, summary, description?, categories?, tags?, homepage?, license?, icon?, media?}
  items/<publisher>/<name>/media/         optional screenshots (PNG, JPEG or WebP; at most 6, 1 MiB each, 4 MiB in all, 64–4096 px)
  items/<publisher>/<name>/<version>/     the bundle's files
  items/<publisher>/<name>/<version>.md   optional changelog for that version
  items/<publisher>/<name>/<version>.requires.json   optional [{id, range}]: items of this registry it needs
  items/<publisher>/<name>/versions.json  written by `sign`
  signatures/<publisher>/<name>/<version>.sig   written by `sign`
  revoked.json                            optional [{id, version or "*", reason}]
docs/                                     the built site (`build` output): index.json, bundles/, media/, the catalog
                                          pages (index.html, items/…/index.html, catalog.css), .nojekyll
```

Each bundle holds its kind's document at its root: `extension.json`, `skillpack.json` (beside
`skills/<x>/SKILL.md`), `template.json`, `preset.json`, `stickers.json` (beside the pictures), or the document of
one of the newer kinds (`watcher market new --kind <kind>` writes a working example of each). Kinds: `extension`,
`skill_pack`, `bot_template`, `mcp_preset`, `sticker_pack`, `lens_suite` (a Lens pipeline and its cases; no custom
scorers), `avatar_pack` (characters drawn from a fixed set of SVG shapes, ids `m-…`), `persona_pack` (2–12 starter
bots and the bot-chat links between them), `check_pack` (tuning for checks a bot already has; it never adds,
turns off or caps a check). Categories: Productivity, Engineering, Support, Marketing, Finance, Data, Fun,
Integrations.

A requirement's `range` is `*`, `^1.2.0`, `~1.2.0`, a bare version, or up to 3 comparators (`>=1.0.0 <2.0.0`).

## Tools

The registry tools are Watcher's `watcher market` commands. Two ways to run them:

- **With Watcher** (from a Watcher checkout): `uv run watcher market …`.
- **Without Watcher** (its repository is private), from this repository, with the vendored copy in
  `tools/watcher_market/`:
  `PYTHONPATH=tools uv run --no-project --python 3.12 --with pydantic==2.13.5 python -m watcher_market …`.

The commands are the same (`--help` on each): `keygen`, `did`, `new`, `version`, `revoke`, `sign`, `lint`,
`build`, `check`, `rotate`, `retire`, `export`, `try`, `check-item`, `diff`. The vendored `lint` checks
`extension.json` and `template.json` lightly; Watcher's checks them fully. Below, `market` stands for either form.

## Publishing

1. Make a key once: `market keygen --name <you>` writes `~/.config/watcher-market/<you>.key` (mode 0600) and prints
   its DID (`market did --key <file>` prints it again later). Keep the file private; never commit it (`*.key` is
   ignored here).
2. Start the item: `market new registry <you>/<item> --kind <kind> --title "…" --summary "…" --key <your key>`.
   It writes `item.json`, a working `1.0.0/` of that kind and, the first time, `registry/publishers/<you>.json`.
   An MCP preset also needs `--url https://…`.
3. Edit `item.json` and `1.0.0/`: the real description and files.
4. Check it: `market lint registry` (no key needed; lists every problem).
5. Sign it: `market sign registry --publisher <you> --key <your key>`.
6. Open a pull request.

### A new version

`market version registry <you>/<item> <version>` copies the newest version folder (an extension's
`extension.json` gets the new version). Edit it, write `items/<you>/<item>/<version>.md` (what changed), then lint
and sign as above.

### Withdrawing a version

`market revoke registry <you>/<item> <version or *> --reason "…"` adds it to `registry/revoked.json`. The
maintainers build the site again; Watcher turns the version off on its next sync.

### Changes between versions

`market diff registry <you>/<item> <a> <b>` (or a built site instead of `registry`) shows what an update changes,
the same list Watcher's console shows before an update (`--json` for a machine-readable form).

### Without a registry: item files

- `market export registry <you>/<item> --key <your key> [--version V]` writes one signed item file
  (`<you>-<item>-<version>.market.json`). An admin imports it on Watcher's Marketplace page (Import a file); it
  then installs with the usual approval. Imported items get no withdrawals and update only from a newer file.
- `market try registry <you>/<item>` writes a trial file signed by a throwaway key
  (`~/.config/watcher-market/try.key`). Only a test stack started with `RWCTL_MARKET_TRY=1` imports it.
- `market check-item <file>` verifies an item file the way Watcher does.

### Keys

- **Moving to a new key** (you still have the old one): `market rotate registry --publisher <you> --key <old>
  --new-key <new>`. The old key signs a handover; versions it signed stay valid, and Watcher carries an admin's
  trust over to the new key. Sign new versions with the new key.
- **Retiring a key** (lost or no longer used): `market retire registry --publisher <you> --reason "…" --new-key
  <new>` (or `--did <an older key>`). Versions signed with it after `--until` count as withdrawn; with
  `--compromised`, everything it signed does, and Watcher distrusts the key. Run `sign` afterwards to re-sign what
  the old key no longer covers.

## Maintainers

1. `uv run watcher market build registry --out docs --key ~/.config/watcher-market/official.key` (with Watcher,
   for the full checks). It also writes the catalog pages and the screenshots.
2. `market check docs --did did:key:z6Mkm8G2KVKPtF8RudfvPP2J6BDQSmpmGkQUMw9FWdwgWdfS`.
3. `market lint registry --site docs` (the built site, pages and screenshots match the source).
4. Commit `docs/`.

Moving the registry to a new key: build with the new key and `--previous-key <old>` (the old key endorses the
index), and keep doing so until the admins of the workspaces that use the registry have accepted the new key on
their Marketplace page; for the official registry, Watcher's `global.market` config names the key. Then build
with the new key alone and change the DID in CI.

After Watcher's market code changes, refresh the vendored tools from a Watcher checkout:
`uv run watcher market vendor <this repository>/tools`.

## CI

`.github/workflows/check.yml` runs the vendored tools:
- `lint registry` on every pull request and push;
- `check docs` (the built site's signatures) on every pull request and push;
- `lint registry --site docs` (the site is fresh) on pushes to main;
- a warning on a pull request that changes a publisher file: a maintainer checks a new DID by hand.


## Getting listed as a publisher

Open a pull request that adds `registry/publishers/<id>.json` with your id, name, DID (from `keygen`) and an
optional URL, together with your first signed item. The official maintainers review the item, check that you
control the key and the name, and may set `"verified": true`. Admins still decide per workspace whose items they
trust.

## Items

- `watcher/instagram` (skill pack, MIT): Jake Schincariol's
  [instagram-agent-skill](https://github.com/Jakeschincariol/instagram-agent-skill); its LICENSE and README ship
  inside the bundle.
