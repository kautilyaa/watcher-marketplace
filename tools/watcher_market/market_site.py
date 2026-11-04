"""A registry's browsable catalog: plain HTML pages rendered from its index (``market.build`` writes them beside
``index.json``; ``market.lint --site`` renders them again and compares bytes).

Pages: ``index.html`` (every item, grouped by kind), ``items/<publisher>/<name>/index.html`` (one item with its
screenshots, every version and what each requires) and ``catalog.css``. Every link is relative, so the site works
under a GitHub Pages sub-path; each page
carries a Content-Security-Policy that allows only its own stylesheet and pictures: no scripts, nothing from
elsewhere. Every text from the index is escaped; an item's description is rendered from a small safe Markdown subset
(``#`` headings, ``-`` lists, paragraphs, ``**bold**`` and `` `code` ``), never as raw HTML.

Standard library only (``market.vendor`` copies it into a registry repository) and deterministic: the same index
gives the same bytes (no clock, sorted, ``\\n`` line endings).
"""

from __future__ import annotations

import html
import re
from typing import Any

CSP = "default-src 'none'; img-src 'self'; style-src 'self'"
# The kinds in the order the catalog lists them, with their headings; a kind not listed here follows, by name.
KIND_TITLES = {
    "extension": "Extensions",
    "skill_pack": "Skill packs",
    "bot_template": "Starter bots",
    "mcp_preset": "MCP servers",
    "sticker_pack": "Sticker packs",
    "lens_suite": "Lens suites",
    "avatar_pack": "Avatar packs",
    "persona_pack": "Bot packs",
    "check_pack": "Check packs",
}

CSS = """\
:root { color-scheme: light dark; --fg: #1d1d1f; --muted: #6e6e73; --line: #d2d2d7; --card: #f5f5f7;
  --accent: #5b3fd9; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #f5f5f7; --muted: #a1a1a6; --line: #3a3a3c; --card: #1c1c1e; --accent: #a28bff; }
}
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 960px; padding: 24px 16px 48px; font: 15px/1.5 system-ui, sans-serif;
  color: var(--fg); }
a { color: var(--accent); }
header h1 { margin: 0 0 4px; font-size: 28px; }
h2 { margin: 32px 0 12px; font-size: 20px; }
.muted, footer { color: var(--muted); }
code, pre { font: 13px/1.4 ui-monospace, monospace; overflow-wrap: anywhere; }
pre { white-space: pre-wrap; background: var(--card); padding: 8px 12px; border-radius: 8px; }
nav ul, .cards, .versions { list-style: none; padding: 0; }
nav li { display: inline-block; margin-right: 16px; }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; }
.card p { margin: 6px 0 0; }
.icon { font-size: 20px; margin-right: 6px; }
.pill { display: inline-block; border: 1px solid var(--line); border-radius: 999px; padding: 0 8px; font-size: 12px;
  color: var(--muted); margin: 2px 4px 0 0; }
.withdrawn { color: #c9302c; }
.facts { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; }
.facts dt { color: var(--muted); }
.facts dd { margin: 0; }
.versions li { border-top: 1px solid var(--line); padding: 8px 0; }
.versions h3 { margin: 0; font-size: 16px; }
footer { margin-top: 48px; font-size: 13px; }
.shots { display: flex; flex-wrap: wrap; gap: 12px; }
.shots img { max-height: 240px; width: auto; height: auto; max-width: 100%; border: 1px solid var(--line);
  border-radius: 8px; }
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def kind_title(kind: str) -> str:
    return KIND_TITLES.get(kind) or kind.replace("_", " ").capitalize() + "s"


def _kind_order(kinds: set[str]) -> list[str]:
    return [k for k in KIND_TITLES if k in kinds] + sorted(kinds - KIND_TITLES.keys())


def _withdrawn(index: dict[str, Any], item_id: str, version: str) -> str:
    """The reason a version is withdrawn (the index's ``revoked``, by version or ``*``), or ``""``."""
    for entry in index.get("revoked") or []:
        if entry.get("id") == item_id and entry.get("version") in (version, "*"):
            return str(entry.get("reason") or "withdrawn")
    return ""


def _latest(index: dict[str, Any], item: dict[str, Any]) -> dict[str, Any] | None:
    """The newest version not withdrawn (as wctl's browse picks it), or None when every version is."""
    for v in item.get("versions") or []:
        if not _withdrawn(index, item["id"], v["version"]):
            return v
    return None


def _size(n: int) -> str:
    return f"{n} bytes" if n < 1024 else f"{n / 1024:.1f} KiB" if n < 1 << 20 else f"{n / (1 << 20):.1f} MiB"


def _inline(text: str) -> str:
    """Escaped text with ``**bold**`` and `` `code` `` (applied after escaping, so nothing raw gets through)."""
    out = _e(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)


def markdown(text: str) -> str:
    """A description's safe Markdown subset as HTML: ``#``–``###`` headings (as h2–h4: the page's h1 is the item's
    title), ``-``/``*`` list items, paragraphs (lines joined), inline bold and code. Everything else is text."""
    blocks: list[str] = []
    para: list[str] = []
    items: list[str] = []

    def flush() -> None:
        if para:
            blocks.append("<p>" + _inline(" ".join(para)) + "</p>")
            para.clear()
        if items:
            blocks.append("<ul>" + "".join(f"<li>{_inline(i)}</li>" for i in items) + "</ul>")
            items.clear()

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        heading = re.match(r"(#{1,3}) +(.+)", line)
        bullet = re.match(r"[-*] +(.+)", line)
        if not line:
            flush()
        elif heading:
            flush()
            level = len(heading.group(1)) + 1
            blocks.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif bullet:
            if para:
                flush()
            items.append(bullet.group(1))
        else:
            if items:
                flush()
            para.append(line)
    flush()
    return "\n".join(blocks)


def _page(title: str, root: str, body: list[str]) -> bytes:
    head = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>{_e(title)}</title>",
        f'<link rel="stylesheet" href="{root}catalog.css">',
        "</head>",
        "<body>",
    ]
    return ("\n".join([*head, *body, "</body>", "</html>"]) + "\n").encode()


def _add(index: dict[str, Any], did: str | None) -> list[str]:
    """How a Watcher admin adds this registry."""
    out = [
        '<section class="add">',
        "<h2>Add it to Watcher</h2>",
        "<p>An admin adds this registry in Watcher on <b>Marketplace → Registries</b> with its address:</p>",
        f"<pre>{_e(index.get('url'))}</pre>",
    ]
    if did:
        out += ["<p>Its key (Watcher checks every index against it):</p>", f"<pre>{_e(did)}</pre>"]
    out += ["<p>Installing an item then takes an admin's approval in Watcher.</p>", "</section>"]
    return out


def _footer(index: dict[str, Any], root: str) -> str:
    return (f"<footer>Built {_e(index.get('generated_at'))} from a signed index "
            f'(<a href="{root}index.json">index.json</a>).</footer>')


def _pills(item: dict[str, Any]) -> str:
    return "".join(f'<span class="pill">{_e(x)}</span>' for x in [*item.get("categories", []), *item.get("tags", [])])


def _index_page(index: dict[str, Any], publishers: dict[str, dict[str, Any]], did: str | None) -> bytes:
    items = sorted(index.get("items") or [], key=lambda i: (str(i.get("title", "")).lower(), i["id"]))
    kinds = _kind_order({i["kind"] for i in items})
    body = [
        "<header>",
        f"<h1>{_e(index.get('name'))}</h1>",
        f'<p class="muted">A Watcher Marketplace registry: {len(items)} items.</p>',
        "</header>",
        "<main>",
    ]
    if kinds:
        body += ["<nav><ul>"]
        body += [f'<li><a href="#{k}">{_e(kind_title(k))}</a> ({sum(i["kind"] == k for i in items)})</li>'
                 for k in kinds]
        body += ["</ul></nav>"]
    for kind in kinds:
        body += [f'<section id="{_e(kind)}">', f"<h2>{_e(kind_title(kind))}</h2>", '<ul class="cards">']
        for item in (i for i in items if i["kind"] == kind):
            pub = publishers.get(item.get("publisher"), {})
            latest = _latest(index, item)
            version = (f'<span class="pill">{_e(latest["version"])}</span>' if latest
                       else '<span class="pill withdrawn">withdrawn</span>')
            verified = " ✓" if pub.get("verified") else ""
            body += [
                '<li class="card">',
                f'<a href="items/{_e(item["id"])}/index.html"><span class="icon">{_e(item.get("icon"))}</span>'
                f'<b>{_e(item.get("title"))}</b></a> {version}',
                f'<p class="muted">{_e(pub.get("name", item.get("publisher")))}{verified}</p>',
                f"<p>{_e(item.get('summary'))}</p>",
                f"<p>{_pills(item)}</p>" if _pills(item) else "",
                "</li>",
            ]
        body += ["</ul>", "</section>"]
    body += _add(index, did)
    body += ["</main>", _footer(index, "")]
    return _page(str(index.get("name") or "Marketplace"), "", [line for line in body if line])


def _item_page(index: dict[str, Any], item: dict[str, Any], pub: dict[str, Any], did: str | None) -> bytes:
    root = "../../../"
    item_id = item["id"]
    facts = [
        ("Id", f"<code>{_e(item_id)}</code>"),
        ("Kind", _e(kind_title(item["kind"]))),
        ("Publisher", f"{_e(pub.get('name', item.get('publisher')))}"
                      f"{' (verified by this registry)' if pub.get('verified') else ''}"
                      f"<br><code>{_e(pub.get('did'))}</code>"),
    ]
    if item.get("license"):
        facts.append(("License", _e(item["license"])))
    if item.get("homepage"):
        facts.append(("Homepage", f'<a href="{_e(item["homepage"])}" rel="noopener noreferrer nofollow">'
                                  f"{_e(item['homepage'])}</a>"))
    if _pills(item):
        facts.append(("Tags", _pills(item)))
    body = [
        "<header>",
        f'<p><a href="{root}index.html">← {_e(index.get("name"))}</a></p>',
        f'<h1><span class="icon">{_e(item.get("icon"))}</span>{_e(item.get("title"))}</h1>',
        f"<p>{_e(item.get('summary'))}</p>",
        "</header>",
        "<main>",
        '<dl class="facts">',
        *(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts),
        "</dl>",
    ]
    if item.get("description"):
        body += ['<section class="description">', markdown(item["description"]), "</section>"]
    if item.get("media"):
        body += ["<h2>Screenshots</h2>", '<div class="shots">']
        for m in item["media"]:
            src = f"{root}{_e(m['file'])}"
            body.append(f'<a href="{src}"><img src="{src}" alt="{_e(m.get("alt"))}" width="{int(m["width"])}" '
                        f'height="{int(m["height"])}" loading="lazy"></a>')
        body.append("</div>")
    titles = {i["id"]: i.get("title") or i["id"] for i in index.get("items") or []}
    body += ["<h2>Versions</h2>", '<ol class="versions">']
    for v in item.get("versions") or []:
        reason = _withdrawn(index, item_id, v["version"])
        requires = [
            (f'<a href="{root}items/{_e(r["id"])}/index.html">{_e(titles[r["id"]])}</a>' if r["id"] in titles
             else f"<code>{_e(r['id'])}</code>") + f" <code>{_e(r['range'])}</code>"
            for r in v.get("requires") or []
        ]
        body += [
            "<li>",
            f"<h3>{_e(v['version'])}</h3>",
            f'<p class="muted">Published {_e(str(v.get("published_at", ""))[:10])} · {_size(int(v.get("size", 0)))}'
            f' · <a href="{root}{_e(v["bundle"])}">bundle</a> · sha256 <code>{_e(v.get("sha256"))}</code></p>',
            f'<p class="withdrawn">Withdrawn: {_e(reason)}</p>' if reason else "",
            f"<p>Requires {', '.join(requires)}</p>" if requires else "",
            f"<pre>{_e(v['changelog'])}</pre>" if v.get("changelog") else "",
            "</li>",
        ]
    body += ["</ol>", *_add(index, did), "</main>", _footer(index, root)]
    return _page(f"{item.get('title')} · {index.get('name')}", root, [line for line in body if line])


def render(index: dict[str, Any], did: str | None = None) -> dict[str, bytes]:
    """The catalog pages of an index document (``MarketIndex`` as JSON), by their path in the site: ``index.html``,
    ``catalog.css`` and ``items/<publisher>/<name>/index.html``. ``did`` is the registry's did:key, shown on how to
    add it (``registry.json``'s optional ``did``)."""
    publishers = {p["id"]: p for p in index.get("publishers") or []}
    pages = {"index.html": _index_page(index, publishers, did), "catalog.css": CSS.encode()}
    for item in index.get("items") or []:
        pages[f"items/{item['id']}/index.html"] = _item_page(index, item, publishers.get(item["publisher"], {}), did)
    return pages
