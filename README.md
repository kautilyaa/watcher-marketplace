# Watcher Marketplace

The official registry for Watcher's Marketplace: extensions, skill packs, starter bots (bot templates), MCP presets
and sticker packs. The site under `docs/` is served by GitHub Pages at
<https://kautilyaa.github.io/watcher-marketplace/>; Watcher fetches `index.json` and the bundles from there and
verifies every signature before it shows or installs anything.

## Layout

```
registry/                                 the source
  registry.json                           {"name", "url"}
  publishers/<publisher>.json             {id, name, did, url?, verified?}
  items/<publisher>/<name>/item.json      {kind, title, summary, description?, categories?, tags?, homepage?, license?, icon?}
  items/<publisher>/<name>/<version>/     the bundle's files
  items/<publisher>/<name>/<version>.md   optional changelog for that version
  items/<publisher>/<name>/versions.json  written by `sign`
  signatures/<publisher>/<name>/<version>.sig   written by `sign`
  revoked.json                            optional [{id, version or "*", reason}]
docs/                                     the built site (`build` output): index.json, bundles/, .nojekyll
```

Each bundle holds its kind's document at its root: `extension.json`, `skillpack.json` (beside
`skills/<x>/SKILL.md`), `template.json`, `preset.json` or `stickers.json` (beside the pictures). Kinds:
`extension`, `skill_pack`, `bot_template`, `mcp_preset`, `sticker_pack`. Categories: Productivity, Engineering,
Support, Marketing, Finance, Data, Fun, Integrations.

## Publishing

With the `watcher` CLI (from the Watcher repository, `uv run watcher market …`):

1. Make a key once: `watcher market keygen --name <publisher>` writes `~/.config/watcher-market/<publisher>.key`
   (mode 0600) and prints its DID. Keep the file private; never commit it (`*.key` is ignored here).
2. Add your item under `registry/items/<publisher>/<name>/` (`item.json` and a `<version>/` folder).
3. Sign it: `watcher market sign registry --publisher <publisher> --key ~/.config/watcher-market/<publisher>.key`.
4. The registry maintainers build and check the site with the registry key:
   `watcher market build registry --out docs --key ~/.config/watcher-market/official.key`, then
   `watcher market check docs --did <registry DID>`.

A new version is a new `<version>/` folder, signed again. To withdraw a version, add it to `registry/revoked.json`
and rebuild; Watcher disables installs of it on its next sync.

## Getting listed as a publisher

Open a pull request that adds `registry/publishers/<id>.json` with your id, name, DID (from `keygen`) and an
optional URL, together with your first signed item. The official maintainers review the item, check that you
control the key and the name, and may set `"verified": true`. Admins still decide per workspace whose items they
trust.

## Items

- `watcher/instagram` (skill pack, MIT): Jake Schincariol's
  [instagram-agent-skill](https://github.com/Jakeschincariol/instagram-agent-skill); its LICENSE and README ship
  inside the bundle.
