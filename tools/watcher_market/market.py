"""The marketplace's formats (plan: signed registries): a registry's signed ``index.json`` and the bundles it lists.

A registry is a static site: ``<url>index.json`` (a :class:`MarketIndexFile`: the index plus the registry key's
signature) and ``<url>bundles/<publisher>/<name>/<version>.tar.gz``. Every bundle is signed by its publisher's key;
the index by the registry's key. Keys are did:key Ed25519 keys (``watcher.vouch``); a key file holds the 32-byte seed
as hex, mode 0600 (default ``~/.config/watcher-market/<name>.key``). wctl (``control/internal/market``) verifies both
signatures before it shows or installs anything.

Signed messages (bytes; signatures are multibase base58btc, ``"z" + base58(signature)``):

- index: ``b"watcher-market-index-v1\\n" + canonical(index)`` (RFC 8785 JSON of the ``index`` object as written);
  while a registry moves to a new key, its previous key signs the same bytes as the file's ``endorsement``;
- bundle: ``f"watcher-market-bundle-v1\\n{kind}\\n{id}\\n{version}\\n{sha256}"`` (sha256 of the .tar.gz, hex);
- key handover: ``f"watcher-market-key-v1\\n{publisher}\\n{old did}\\n{next did}\\n{until}"``, signed by the old key
  (``rotate``);
- item file: ``b"watcher-market-item-v1\\n" + canonical({"item", "publisher", "trial"})``, signed by the publisher
  (``export``; ``try`` with a throwaway key).

A publisher's earlier keys are its ``previous_keys`` (newest first): a version signed by one carries ``signer``; it
counts as withdrawn when it was published after that key's ``until`` or the key is ``compromised`` (``retire``).

A registry's source (what ``watcher market sign`` and ``build`` read)::

    registry.json                          {"name": …, "url": "https://…/", "did"?: the registry key's did:key}
    publishers/<publisher>.json            a MarketPublisher: {id, name, did, url?, verified?, previous_keys?}
    items/<publisher>/<name>/item.json     the item without id, publisher and versions: {kind, title, summary,
                                           description?, categories?, tags?, homepage?, license?, icon?, verified?,
                                           media?: [{file, alt}] (MediaRef)}
    items/<publisher>/<name>/media/<file>  optional: the screenshots item.json's media names (PNG, JPEG or WebP)
    items/<publisher>/<name>/<version>/    the bundle's files (packed by pack_dir; dotfiles are left out)
    items/<publisher>/<name>/<version>.md  optional: that version's changelog
    items/<publisher>/<name>/<version>.requires.json  optional: [{id, range}, …] other items of this registry that
                                           version needs (MarketRequirement; ``range_ok``)
    items/<publisher>/<name>/versions.json written by sign: {version: published_at}
    signatures/<publisher>/<name>/<version>.sig   written by sign: the publisher's signature of the bundle
    revoked.json                           optional: [MarketRevocation, …] ({id, version or "*", reason})

Screenshots and requirements are covered by the registry's signature of the index, not by the publisher's of the
bundle. In the index a screenshot is a MarketMedia on its item (the site serves it content-addressed as
``media/<publisher>/<name>/<sha256>.<ext>``) and requirements are the version's ``requires``; both are left out when
empty, so an index that uses neither keeps its earlier bytes.

Each bundle holds its kind's document at its root: ``extension.json`` (an extension manifest whose name is the
item's name and whose version is the folder's), ``skillpack.json`` (SkillPackMeta, beside ``skills/<x>/SKILL.md``),
``template.json`` (TemplateDoc), ``preset.json`` (PresetDoc), ``stickers.json`` (StickerPackDoc, beside the
pictures), ``suite.json`` (LensSuiteDoc, beside ``cases.jsonl``; never Lens's code-running ``custom`` scorer),
``avatars.json`` (AvatarPackDoc: characters of whitelisted SVG elements, ids ``m-…``), ``personas.json``
(PersonaPackDoc: 2-12 starter bots and their bot-to-bot links) or ``checks.json`` (CheckPackDoc: tuning for a bot's
existing checks, never turning one off). An index's ``kind`` is any lower-case word (KIND_PATTERN) so a newer kind
doesn't break older Watchers; a source keeps to KINDS. ``build`` writes ``out/index.json``, ``out/bundles/…``,
``out/media/…``, ``out/.nojekyll`` (GitHub Pages serves it as is) and the browsable catalog (``market_site``:
``out/index.html``, ``out/catalog.css``, ``out/items/<publisher>/<name>/index.html``); ``check`` verifies a built
site the way wctl does; ``lint`` checks a source without any key (and, with a site, that the site and its pages are
built from it).
``scaffold``, ``add_version`` and ``revoke`` write the source files above for a publisher (``watcher market new``,
``version``, ``revoke``).

An item file (``<publisher>-<name>-<version>.market.json``, a :class:`MarketItemFile`) carries one signed version
and its bundle (base64) for an admin to import without a registry: ``export`` writes it from a signed source,
``try`` writes a ``trial`` one under the publisher ``try-<publisher>`` with a throwaway key (only a test stack started
with ``RWCTL_MARKET_TRY=1`` imports it), ``read_item_file`` verifies it as wctl's import does. ``diff`` shows what a
version changes against another, as the console's update preview (``extension_changes`` and ``front_matter`` are
ports of wctl's, pinned by shared vectors).

This module imports nothing from Watcher but ``vouch`` and ``market_site``, so ``vendor`` can copy it (with
``market_cli``, ``market_site`` and ``vouch``) into a registry repository as ``watcher_market``, which needs only
Python and pydantic. In such a copy ``DEEP`` is False: ``extension.json`` and ``template.json`` get light checks.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import struct
import tarfile
import tempfile
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from . import market_site, vouch

try:  # inside Watcher; a vendored copy (watcher market vendor) has no extensions module
    from .extensions import ExtensionManifest
except ImportError:
    ExtensionManifest = None
DEEP = ExtensionManifest is not None  # False in a vendored copy: extension.json and template.json get light checks

# The same rule as watcher.extensions.SEMVER (tests pin it).
SEMVER = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$"


class Strict(BaseModel):
    """Unknown keys are an error, never silently ignored."""

    model_config = ConfigDict(extra="forbid")


KINDS = (
    "extension", "skill_pack", "bot_template", "mcp_preset", "sticker_pack",
    "lens_suite", "avatar_pack", "persona_pack", "check_pack",
)
CATEGORIES = ("Productivity", "Engineering", "Support", "Marketing", "Finance", "Data", "Fun", "Integrations")
# The document at the root of each kind's bundle.
KIND_FILE = {
    "extension": "extension.json",
    "skill_pack": "skillpack.json",
    "bot_template": "template.json",
    "mcp_preset": "preset.json",
    "sticker_pack": "stickers.json",
    "lens_suite": "suite.json",
    "avatar_pack": "avatars.json",
    "persona_pack": "personas.json",
    "check_pack": "checks.json",
}
# A kind's shape in an index: any lower-case word, so an index listing a kind newer than this Watcher still verifies
# (wctl shows such an item as needing a newer Watcher); publishers' sources keep to KINDS.
KIND_PATTERN = r"^[a-z][a-z_]{2,23}$"
MAX_BUNDLE_BYTES = 10 << 20
# wctl's extensions.ReadArchive limits (control/internal/extensions/extensions.go), which read_archive applies.
MAX_FILES = 200
MAX_UNPACKED_BYTES = 50 << 20
MAX_PATH = 240
# An item file (export / try): the bundle, base64, plus its metadata.
MAX_ITEM_FILE_BYTES = 15 << 20
ITEM_CONTEXT = b"watcher-market-item-v1\n"
INDEX_CONTEXT = b"watcher-market-index-v1\n"
KEY_CONTEXT = "watcher-market-key-v1\n"
DEFAULT_KEY_DIR = Path("~/.config/watcher-market")

_PUBLISHER = r"[a-z0-9][a-z0-9-]{1,39}"
_ITEM = r"[a-z0-9][a-z0-9-]{1,47}"
PublisherId = Annotated[str, StringConstraints(pattern=rf"^{_PUBLISHER}$")]
ItemName = Annotated[str, StringConstraints(pattern=rf"^{_ITEM}$")]
ItemId = Annotated[str, StringConstraints(pattern=rf"^{_PUBLISHER}/{_ITEM}$")]
_DID_KEY = r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}"
DidKey = Annotated[str, StringConstraints(pattern=rf"^{_DID_KEY}$")]
Signature = Annotated[str, StringConstraints(pattern=r"^z[1-9A-HJ-NP-Za-km-z]{80,100}$")]
SemVer = Annotated[str, StringConstraints(max_length=32, pattern=SEMVER)]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
# A relative path whose parts never start with a dot (no "..", no hidden files); RE2-safe (no look-arounds), as Go's
# JSON Schema validator runs it too.
RelPath = Annotated[
    str,
    StringConstraints(max_length=200, pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"),
]
HttpsUrl = Annotated[str, StringConstraints(max_length=300, pattern=r"^https://[^\s/?#@]+(/[^\s]*)?$")]
# A registry's base URL: https, a DNS name, a path ending in /.
HttpsBase = Annotated[
    str,
    StringConstraints(
        max_length=300,
        pattern=r"^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+/([A-Za-z0-9._~-]+/)*$",
    ),
]
Tag = Annotated[str, StringConstraints(min_length=1, max_length=24, pattern=r"^[a-z0-9-]+$")]


# A UTC time to the second, kept as the string it was written as so the signed bytes never drift.
UtcSecond = Annotated[str, StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")]


class MarketPublisherKey(Strict):
    """A publisher's previous key (``watcher market rotate`` / ``retire``)."""

    did: DidKey
    until: UtcSecond  # versions published after it aren't this key's
    reason: str = Field("", max_length=200)
    compromised: bool = False  # every bundle it signed is distrusted, whenever published
    handover: Signature | None = None  # its signature of key_message(publisher, did, next, until); next = the newer key


class MarketPublisher(Strict):
    id: PublisherId
    name: str = Field(min_length=1, max_length=80)
    did: DidKey
    url: HttpsUrl | None = None
    verified: bool = False
    previous_keys: list[MarketPublisherKey] = Field(default_factory=list, max_length=20)  # newest first

    @model_validator(mode="after")
    def _keys(self) -> MarketPublisher:
        dids = [k.did for k in self.previous_keys]
        if len(set(dids)) != len(dids) or self.did in dids:
            raise ValueError(f"{self.id}: a key is listed twice in did and previous_keys")
        untils = [k.until for k in self.previous_keys]
        if any(a <= b for a, b in zip(untils, untils[1:], strict=False)):
            raise ValueError(f"{self.id}: previous_keys are newest first, their until strictly earlier")
        for k in self.previous_keys:
            if k.compromised and k.handover is not None:
                raise ValueError(f"{self.id}: a compromised key carries no handover")
        return self


# A version range a requirement names (``range_ok``): ``*``, or one to three comparators separated by single spaces,
# each ``(>=|<=|>|<|=|^|~)?MAJOR.MINOR.PATCH`` (a bare version is exact; no pre-releases). RE2-safe.
_COMPARATOR = r"(>=|<=|>|<|=|\^|~)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
RANGE = rf"^(\*|{_COMPARATOR}( {_COMPARATOR}){{0,2}})$"
VersionRange = Annotated[str, StringConstraints(max_length=64, pattern=RANGE)]
MAX_REQUIRES = 10
# Screenshots on an item (``items/<publisher>/<name>/media/``): at most MAX_MEDIA, each at most MAX_MEDIA_BYTES, all
# together at most MAX_MEDIA_TOTAL, MEDIA_SIDES pixels a side; PNG, JPEG or WebP, never animated.
MAX_MEDIA = 6
MAX_MEDIA_BYTES = 1 << 20
MAX_MEDIA_TOTAL = 4 << 20
MEDIA_SIDES = (64, 4096)
MEDIA_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}


class MarketRequirement(Strict):
    """Another item of the same registry a version needs (``<version>.requires.json``)."""

    id: ItemId
    range: VersionRange


class MarketMedia(Strict):
    """A screenshot as the index lists it: content-addressed in the site (``media/<p>/<n>/<sha256>.<ext>``)."""

    file: RelPath
    sha256: Sha256Hex
    size: int = Field(ge=1, le=MAX_MEDIA_BYTES)
    type: Literal["image/png", "image/jpeg", "image/webp"]
    width: int = Field(ge=MEDIA_SIDES[0], le=MEDIA_SIDES[1])
    height: int = Field(ge=MEDIA_SIDES[0], le=MEDIA_SIDES[1])
    alt: str = Field(min_length=1, max_length=200)


class MediaRef(Strict):
    """A screenshot as ``item.json`` names it: a file in the item's ``media/`` folder and its alt text."""

    file: RelPath
    alt: str = Field(min_length=1, max_length=200)


class MarketVersion(Strict):
    version: SemVer
    published_at: AwareDatetime
    changelog: str = Field("", max_length=2000)
    bundle: RelPath
    size: int = Field(ge=1, le=MAX_BUNDLE_BYTES)
    sha256: Sha256Hex
    signature: Signature
    signer: DidKey | None = None  # a previous key of the publisher that signed it; None: its did
    requires: list[MarketRequirement] = Field(default_factory=list, max_length=MAX_REQUIRES)  # left out when empty


class MarketItem(Strict):
    kind: str = Field(pattern=KIND_PATTERN)
    id: ItemId
    publisher: PublisherId
    title: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1, max_length=200)
    description: str = Field("", max_length=4000)
    categories: list[
        Literal["Productivity", "Engineering", "Support", "Marketing", "Finance", "Data", "Fun", "Integrations"]
    ] = Field(default_factory=list, max_length=3)
    tags: list[Tag] = Field(default_factory=list, max_length=10)
    homepage: HttpsUrl | None = None
    license: str = Field("", max_length=40)
    icon: str = Field("", max_length=4)
    verified: bool = False
    versions: list[MarketVersion] = Field(min_length=1, max_length=50)  # newest first
    media: list[MarketMedia] = Field(default_factory=list, max_length=MAX_MEDIA)  # left out when empty

    @model_validator(mode="after")
    def _consistent(self) -> MarketItem:
        if not self.id.startswith(self.publisher + "/"):
            raise ValueError(f"{self.id}: an item's id starts with its publisher ({self.publisher}/)")
        numbers = [v.version for v in self.versions]
        if len(set(numbers)) != len(numbers):
            raise ValueError(f"{self.id}: two versions share a number")
        if sum(m.size for m in self.media) > MAX_MEDIA_TOTAL:
            raise ValueError(f"{self.id}: screenshots add up to over {MAX_MEDIA_TOTAL >> 20} MiB")
        return self


class MarketRevocation(Strict):
    id: ItemId
    version: SemVer | Literal["*"]
    reason: str = Field(min_length=1, max_length=200)


class MarketIndex(Strict):
    format: Literal[1]
    name: str = Field(min_length=1, max_length=80)
    url: HttpsBase
    generated_at: AwareDatetime
    key: DidKey | None = None  # the registry key that signs this index (build always writes it)
    publishers: list[MarketPublisher] = Field(default_factory=list, max_length=200)
    items: list[MarketItem] = Field(default_factory=list, max_length=2000)
    revoked: list[MarketRevocation] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def _consistent(self) -> MarketIndex:
        ids = [p.id for p in self.publishers]
        if len(set(ids)) != len(ids):
            raise ValueError("two publishers share an id")
        publishers = {p.id: p for p in self.publishers}
        for item in self.items:
            if item.publisher not in ids:
                raise ValueError(f"{item.id}: its publisher {item.publisher} is not in publishers")
            previous = {k.did for k in publishers[item.publisher].previous_keys}
            for v in item.versions:
                if v.signer is not None and v.signer not in previous:
                    raise ValueError(f"{item.id} {v.version}: its signer is not one of {item.publisher}'s "
                                     "previous_keys")
        items = [i.id for i in self.items]
        if len(set(items)) != len(items):
            raise ValueError("two items share an id")
        return self


class MarketEndorsement(Strict):
    """While a registry moves to a new key: the previous key's signature of the same index message."""

    did: DidKey
    signature: Signature


class MarketIndexFile(Strict):
    index: MarketIndex
    signature: Signature
    endorsement: MarketEndorsement | None = None

    @model_validator(mode="after")
    def _endorsed(self) -> MarketIndexFile:
        if self.endorsement is not None and self.endorsement.did == self.index.key:
            raise ValueError("the endorsement is by the index's own key: it comes from the previous registry key")
        return self


# --- bundle documents -------------------------------------------------------------------------------------------
class SkillPackMeta(Strict):
    """``skillpack.json``: the pack's domain tag and the source title its skills cite."""

    domain: str = Field(min_length=1, max_length=60)
    source_title: str = Field("", max_length=120)


class TemplateDoc(Strict):
    """``template.json``: a starter bot, the shape of ``config/bots/templates/*.yaml`` (``schemas.bot_templates``)."""

    template: str = Field(pattern=r"^[a-z][a-z0-9_]{2,31}$")
    title: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1, max_length=200)
    bot: dict[str, Any]
    connectors: list[dict[str, Any]] = Field(default_factory=list, max_length=20)


class RemotePreset(Strict):
    url: HttpsUrl
    auth: Literal["oauth", "token"]
    dcr: bool = False
    note: str = Field("", max_length=400)


class LocalPreset(Strict):
    label: str = Field(min_length=1, max_length=60)
    command: str = Field(min_length=1, max_length=200)
    args: list[Annotated[str, StringConstraints(max_length=300)]] = Field(default_factory=list, max_length=30)
    notes: list[Annotated[str, StringConstraints(max_length=400)]] = Field(default_factory=list, max_length=10)
    match: str = Field(min_length=1, max_length=40)


class PresetDoc(Strict):
    """``preset.json``: an MCP server for the Integrations page, remote (a URL) or local (a command)."""

    name: str = Field(min_length=1, max_length=60)
    blurb: str = Field(min_length=1, max_length=200)
    keywords: str = Field("", max_length=120)
    remote: RemotePreset | None = None
    local: LocalPreset | None = None

    @model_validator(mode="after")
    def _one(self) -> PresetDoc:
        if (self.remote is None) == (self.local is None):
            raise ValueError("a preset is remote or local: exactly one of them")
        return self


class StickerEntry(Strict):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    description: str = Field(min_length=1, max_length=200)
    file: RelPath


class StickerPackDoc(Strict):
    """``stickers.json``: the shape of ``migrations/stickers/watcher/manifest.json``."""

    pack: str = Field(min_length=1, max_length=40)
    stickers: list[StickerEntry] = Field(min_length=1, max_length=120)


# --- Lens eval suites (lens_suite): data only; Lens's code-running `custom` scorer is never allowed ----------------
LensScorerType = Literal["exact", "text", "contains", "regex", "json_fields", "labels", "numeric"]
LENS_SLUG = r"^[a-z0-9][a-z0-9_-]{0,63}$"  # watcher_lens.store.SLUG_RE
LENS_CASE_ID = r"^[A-Za-z0-9_.:-]{1,128}$"  # watcher_lens.store.CASE_ID_RE
MAX_LENS_CASES = 5000


class LensScorer(Strict):
    """A Lens scorer config (watcher_lens.scorers), every type but ``custom``."""

    type: LensScorerType = "exact"
    field: str | None = Field(None, min_length=1, max_length=200)
    case_sensitive: bool | None = None
    strip_punctuation: bool | None = None
    keep_whitespace: bool | None = None
    pattern: str | None = Field(None, min_length=1, max_length=200)
    full_match: bool | None = None
    ignore_case: bool | None = None
    tolerance: float | None = Field(None, ge=0)
    relative: bool | None = None
    metric: Literal["f1", "precision", "recall", "jaccard"] | None = None
    threshold: float | None = Field(None, ge=0, le=1)
    weight: float | None = Field(None, ge=0, le=100)  # a json_fields field's weight
    fields: dict[Annotated[str, StringConstraints(min_length=1, max_length=64)], LensScorer | LensScorerType] | None = (
        Field(None, max_length=30)
    )


class LensSuiteDoc(Strict):
    """``suite.json``: a Lens pipeline (slug, name, description, scorer); its cases are ``cases.jsonl`` beside it,
    one ``{case_id, input, expected?, tags?}`` per line."""

    slug: str = Field(pattern=LENS_SLUG)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field("", max_length=2000)
    scorer: LensScorer = Field(default_factory=LensScorer)


def lens_cases(text: str) -> list[dict[str, Any]]:
    """A suite's ``cases.jsonl`` read with Lens's case rules (watcher_lens.store.upsert_cases): 1 to 5000 objects,
    each with a unique case_id and an input, tags 1-64 character strings, no other keys."""
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"cases.jsonl line {n}: not JSON ({exc})") from exc
        if not isinstance(case, dict):
            raise ValueError(f"cases.jsonl line {n}: a case is an object")
        extra = set(case) - {"case_id", "input", "expected", "tags"}
        if extra:
            raise ValueError(f"cases.jsonl line {n}: unknown keys {', '.join(sorted(extra))}")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not re.fullmatch(LENS_CASE_ID, case_id):
            raise ValueError(f"cases.jsonl line {n}: case_id is 1-128 of letters, digits, '_', '.', ':' or '-'")
        if case_id in seen:
            raise ValueError(f"cases.jsonl line {n}: case_id {case_id} is there twice")
        seen.add(case_id)
        if "input" not in case:
            raise ValueError(f"cases.jsonl line {n}: case {case_id} has no input")
        tags = case.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) and 0 < len(t) <= 64 for t in tags):
            raise ValueError(f"cases.jsonl line {n}: tags are a list of 1-64 character strings")
        cases.append(case)
    if not cases:
        raise ValueError("cases.jsonl holds no case")
    if len(cases) > MAX_LENS_CASES:
        raise ValueError(f"cases.jsonl holds at most {MAX_LENS_CASES} cases")
    return cases


# --- avatar packs (avatar_pack): characters drawn from whitelisted SVG primitives, never free-form SVG ------------
Mood = Literal["idle", "thinking", "talking", "happy", "worried", "sleeping", "alarmed", "sad", "confused", "proud",
               "excited", "focused"]
Motion = Literal["bob", "wag", "prowl", "sway", "hop", "waddle", "flap", "buzz", "swim", "scuttle", "crawl", "slither",
                 "stomp", "float", "launch", "spin", "swing", "flicker", "drip", "wobble", "bloom", "pulse", "scan",
                 "flip", "grow", "beep", "twist", "tap"]
Trait = Literal["steam", "bubbles", "buzz", "sparkle", "notes", "signal", "embers", "glow", "exhaust", "hearts"]
Color = Annotated[str, StringConstraints(pattern=r"^#[0-9a-f]{6}$")]
# A paint: a colour, none, a shade of the character's body or accent tone, or the face's ink / line colour.
Paint = Annotated[
    str, StringConstraints(pattern=r"^(#[0-9a-f]{6}|none|(body|accent)\.(base|light|shade|deep|fill)|ink|line)$"),
]
Coord = Annotated[float, Field(ge=-64, le=128)]
# Path data: commands, numbers and separators only (RE2 caps repeat counts at 1000, so the length is max_length).
PathData = Annotated[
    str, StringConstraints(min_length=1, max_length=4000, pattern=r"^[MmLlHhVvCcSsQqTtAaZz0-9eE.,+\- ]+$"),
]
AVATAR_ID = r"^m-[a-z0-9][a-z0-9-]{1,29}$"  # the marketplace's namespace; no built-in character starts with m-
MAX_SVG_DEPTH = 4
MAX_SVG_NODES = 600


class SvgTransform(Strict):
    translate: list[Coord] | None = Field(None, min_length=2, max_length=2)
    rotate: list[Annotated[float, Field(ge=-360, le=360)]] | None = Field(None, min_length=1, max_length=3)
    scale: list[Annotated[float, Field(ge=-4, le=4)]] | None = Field(None, min_length=1, max_length=2)


class SvgNode(Strict):
    """One SVG element of a character's layer; the console maps each key to its attribute and nothing else."""

    el: Literal["g", "path", "circle", "ellipse", "rect", "line", "polygon", "polyline"]
    cx: Coord | None = None
    cy: Coord | None = None
    r: Coord | None = None
    rx: Coord | None = None
    ry: Coord | None = None
    x: Coord | None = None
    y: Coord | None = None
    width: Coord | None = None
    height: Coord | None = None
    x1: Coord | None = None
    y1: Coord | None = None
    x2: Coord | None = None
    y2: Coord | None = None
    d: PathData | None = None
    points: list[Coord] | None = Field(None, max_length=200)
    fill: Paint | None = None
    stroke: Paint | None = None
    opacity: float | None = Field(None, ge=0, le=1)
    fill_opacity: float | None = Field(None, ge=0, le=1)
    stroke_opacity: float | None = Field(None, ge=0, le=1)
    stroke_width: float | None = Field(None, ge=0, le=12)
    linecap: Literal["butt", "round", "square"] | None = None
    linejoin: Literal["miter", "round", "bevel"] | None = None
    fill_rule: Literal["nonzero", "evenodd"] | None = None
    transform: SvgTransform | None = None
    clip: bool = False  # clipped to the body's shape
    anim: Literal["av-tail", "av-leaf"] | None = None
    children: list[SvgNode] = Field(default_factory=list, max_length=60)


class ShapeCircle(Strict):
    circle: list[Coord] = Field(min_length=3, max_length=3)


class ShapeEllipse(Strict):
    ellipse: list[Coord] = Field(min_length=4, max_length=4)


class ShapeRect(Strict):
    rect: list[Coord] = Field(min_length=5, max_length=5)


class ShapePath(Strict):
    d: PathData


class AvatarEyes(Strict):
    scale: float | None = Field(None, ge=0.3, le=3)
    spread: float | None = Field(None, ge=-16, le=16)
    ring: Color | None = None
    kind: Literal["round", "almond"] | None = None


class AvatarFace(Strict):
    variant: Literal["standard", "wink", "grump"] | None = None
    dx: float | None = Field(None, ge=-32, le=32)
    dy: float | None = Field(None, ge=-32, le=32)
    scale: float | None = Field(None, ge=0.3, le=3)
    mouth: bool | None = None
    mouth_dy: float | None = Field(None, ge=-32, le=32)
    ink: Color | None = None
    eyes: AvatarEyes | None = None


def _svg_count(nodes: list[SvgNode], depth: int = 1) -> int:
    if nodes and depth > MAX_SVG_DEPTH:
        raise ValueError(f"SVG elements nest at most {MAX_SVG_DEPTH} deep")
    return sum(1 + _svg_count(n.children, depth + 1) for n in nodes)


class AvatarDoc(Strict):
    """One character of an avatar pack: the console's Recipe as data (control/web/src/avatar/dataRecipe.tsx)."""

    id: str = Field(pattern=AVATAR_ID)
    name: str = Field(min_length=1, max_length=40)
    tagline: str = Field(min_length=1, max_length=140)
    keywords: str = Field("", max_length=200)
    body: Color
    accent: Color | None = None
    tint: Literal["body", "accent"] | None = None
    shape: (Literal["blob", "round", "egg", "bean", "wide", "tall", "box", "drop", "cloud"]
            | ShapeCircle | ShapeEllipse | ShapeRect | ShapePath | None) = None
    face: AvatarFace | None = None
    cheeks: Color | Literal[False] | None = None
    motion: Motion
    trait: Trait | None = None
    personality: str = Field("", max_length=300)
    reactions: dict[Mood, Annotated[str, StringConstraints(min_length=1, max_length=140)]] = Field(default_factory=dict)
    composure: dict[Mood, Mood] = Field(default_factory=dict)
    back: list[SvgNode] = Field(default_factory=list, max_length=120)
    front: list[SvgNode] = Field(default_factory=list, max_length=120)
    top: list[SvgNode] = Field(default_factory=list, max_length=120)

    @model_validator(mode="after")
    def _bounded(self) -> AvatarDoc:
        if _svg_count(self.back) + _svg_count(self.front) + _svg_count(self.top) > MAX_SVG_NODES:
            raise ValueError(f"{self.id}: a character has at most {MAX_SVG_NODES} SVG elements")
        return self


class AvatarPackDoc(Strict):
    """``avatars.json``: characters for the avatar gallery, ids in the ``m-`` namespace."""

    pack: str = Field(min_length=1, max_length=40)
    characters: list[AvatarDoc] = Field(min_length=1, max_length=60)

    @model_validator(mode="after")
    def _unique(self) -> AvatarPackDoc:
        ids = [c.id for c in self.characters]
        if len(set(ids)) != len(ids):
            raise ValueError("two characters share an id")
        return self


# --- persona packs (persona_pack): starter bots that work together ----------------------------------------------
class PersonaPackDoc(Strict):
    """``personas.json``: 2-12 starter bots (TemplateDoc) and which of them may ask which (``global.botchat.allow``
    edges, only between bots of the pack; never ``*``)."""

    templates: list[TemplateDoc] = Field(min_length=2, max_length=12)
    botchat: dict[str, list[str]] = Field(default_factory=dict, max_length=12)

    @model_validator(mode="after")
    def _edges(self) -> PersonaPackDoc:
        ids = [t.template for t in self.templates]
        if len(set(ids)) != len(ids):
            raise ValueError("two starter bots share a template id")
        for asker, asked in self.botchat.items():
            for ref in [asker, *asked]:
                if ref not in ids:
                    raise ValueError(f"botchat: {ref!r} is not a starter bot of this pack")
            if asker in asked:
                raise ValueError(f"botchat: {asker} can't ask itself")
            if len(set(asked)) != len(asked):
                raise ValueError(f"botchat: {asker} lists a bot twice")
        return self


# --- check packs (check_pack): tuning for checks a bot already has; never new checks, never turning one off -------
CheckId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]{0,11}(-[A-Z0-9]{1,12}){1,3}$")]  # config.CheckId
FieldName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]  # config.FieldName
Label = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:/-]{1,64}$")]  # config.Label
# config.PublicUrl: a public https page (host name with a dot, no IP, port, credentials, query or fragment).
PublicUrl = Annotated[
    str,
    StringConstraints(
        pattern=r"^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(/[A-Za-z0-9._~%/-]{0,200})?$"
    ),
]


class CheckPackLabels(Strict):
    when: dict[Label, Label] = Field(min_length=1, max_length=8)
    values: dict[FieldName, Any] = Field(min_length=1, max_length=50)


class CheckPackOverride(Strict):
    """A check's tuning (config.CheckOverride without ``enabled`` and ``max_severity``: a pack can't silence it)."""

    cadence: str | None = Field(None, max_length=130, pattern=r"^(every [0-9]{1,7}[smhd]|cron [ -~]{9,120})$")
    thresholds: dict[FieldName, Any] = Field(default_factory=dict, max_length=50)
    label_overrides: list[CheckPackLabels] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _changes(self) -> CheckPackOverride:
        if self.cadence is None and not self.thresholds and not self.label_overrides:
            raise ValueError("an override sets cadence, thresholds or label_overrides")
        return self


class CheckPackDoc(Strict):
    """``checks.json``: tuning for one bot's existing checks (``bots.<bot>.checks``) and, optionally, public pages for
    its site checks (``global.product.monitor``)."""

    bot: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    overrides: dict[CheckId, CheckPackOverride] = Field(min_length=1, max_length=50)
    monitor: list[PublicUrl] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _once(self) -> CheckPackDoc:
        if len(set(self.monitor)) != len(self.monitor):
            raise ValueError("monitor: each URL once")
        return self


BUNDLE_DOCS: dict[str, type[Strict]] = {
    "SkillPackMeta": SkillPackMeta,
    "TemplateDoc": TemplateDoc,
    "PresetDoc": PresetDoc,
    "StickerPackDoc": StickerPackDoc,
    "LensSuiteDoc": LensSuiteDoc,
    "AvatarPackDoc": AvatarPackDoc,
    "PersonaPackDoc": PersonaPackDoc,
    "CheckPackDoc": CheckPackDoc,
}


def index_schema() -> dict[str, Any]:
    """The JSON Schema wctl checks a registry's index.json against (control/schema/market_index.schema.json)."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$comment": "generated by `watcher schema export` from watcher.market; do not edit",
        **MarketIndexFile.model_json_schema(),
    }


def bundles_schema() -> dict[str, Any]:
    """The bundle documents' JSON Schemas, one per ``$defs`` entry (control/schema/market_bundles.schema.json)."""
    from pydantic.json_schema import models_json_schema  # noqa: PLC0415

    _, schema = models_json_schema([(model, "validation") for model in BUNDLE_DOCS.values()])
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$comment": "generated by `watcher schema export` from watcher.market; do not edit",
        **schema,
    }


# --- signing ----------------------------------------------------------------------------------------------------
def index_message(index: dict[str, Any]) -> bytes:
    return INDEX_CONTEXT + vouch.canonical(index)


def bundle_message(kind: str, item_id: str, version: str, sha256: str) -> bytes:
    return f"watcher-market-bundle-v1\n{kind}\n{item_id}\n{version}\n{sha256}".encode()


def key_message(publisher: str, old: str, next_did: str, until: str) -> bytes:
    """What a publisher's old key signs to hand over to its next key (``previous_keys[].handover``)."""
    return f"{KEY_CONTEXT}{publisher}\n{old}\n{next_did}\n{until}".encode()


def _publisher_doc(publisher: MarketPublisher) -> dict[str, Any]:
    """A publisher as JSON, the key fields it doesn't use left out (so old documents keep their shape)."""
    doc = publisher.model_dump(mode="json")
    keys = []
    for key in doc.pop("previous_keys"):
        for field, unused in (("reason", ""), ("compromised", False), ("handover", None)):
            if key[field] == unused:
                del key[field]
        keys.append(key)
    if keys:
        doc["previous_keys"] = keys
    return doc


def _trim_item(item: dict[str, Any]) -> dict[str, Any]:
    """An item dumped as JSON with its unused optional fields left out (a version's ``signer`` and ``requires``, the
    item's ``media``), so an index or item file that uses none of them keeps its phase-1 bytes."""
    if not item.get("media"):
        item.pop("media", None)
    for v in item["versions"]:
        if v.get("signer") is None:
            v.pop("signer", None)
        if not v.get("requires"):
            v.pop("requires", None)
    return item


def _index_doc(index: MarketIndex) -> dict[str, Any]:
    """The index as JSON, as build writes and signs it: key fields that are unused are left out."""
    doc = index.model_dump(mode="json")
    if doc["key"] is None:
        del doc["key"]
    doc["publishers"] = [_publisher_doc(p) for p in index.publishers]
    for item in doc["items"]:
        _trim_item(item)
    return doc


def _when(stamp: Any) -> datetime:
    """A published_at or until string (or datetime) as an aware UTC datetime."""
    if isinstance(stamp, datetime):
        return stamp.astimezone(UTC)
    return datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).astimezone(UTC)


def _utc_second(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _handover_problems(publishers: Any) -> list[str]:
    """Each previous key's handover verifies: the old key signed key_message(publisher, old, next, until)."""
    problems = []
    for pub in publishers:
        newer = pub.did
        for k in pub.previous_keys:
            if k.handover is not None and not signature_ok(k.did, key_message(pub.id, k.did, newer, k.until),
                                                            k.handover):
                problems.append(f"{pub.id}'s key handover from {k.did[:16]}… doesn't verify")
            newer = k.did
    return problems


def signature(seed: bytes, message: bytes) -> str:
    return "z" + vouch.base58(vouch.sign(seed, message))


def signature_ok(did: str, message: bytes, sig: str) -> bool:
    try:
        public = vouch.public_key(did)
        raw = vouch.unbase58(sig.removeprefix("z"))
    except ValueError:
        return False
    return sig.startswith("z") and vouch.verify(public, message, raw)


def keygen(path: Path) -> str:
    """Write a new signing key (32 random bytes as hex, mode 0600, its folder 0700) and answer its did:key. Refuses
    to overwrite a key."""
    path = path.expanduser()
    if path.exists():
        raise FileExistsError(f"{path} exists: a key is never overwritten")
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
    seed = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    return vouch.did_key(vouch.public_from_seed(seed))


def load_key(path: Path) -> bytes:
    text = path.expanduser().read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError(f"{path}: a key file holds 64 hex characters")
    return bytes.fromhex(text)


def key_did(seed: bytes) -> str:
    return vouch.did_key(vouch.public_from_seed(seed))


# --- bundles ----------------------------------------------------------------------------------------------------
def _files(root: Path) -> list[Path]:
    """Every file and folder under ``root`` (paths relative to it), dotfiles left out, sorted."""
    out = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"{path}: a bundle holds only files and folders")
        out.append(rel)
    return sorted(out, key=lambda p: p.as_posix())


def pack_dir(path: Path) -> bytes:
    """A .tar.gz of the folder's files that is the same bytes for the same files (no times, owners or order of its
    own), as ``improve.skill_md`` builds its bundles."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as archive:
        for rel in _files(path):
            full = path / rel
            info = tarfile.TarInfo(rel.as_posix())
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if full.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            else:
                data = full.read_bytes()
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class ArchiveError(ValueError):
    """Why a bundle can't be unpacked."""


def read_archive(data: bytes) -> dict[str, bytes]:
    """A .tar.gz's files by their clean relative path, with wctl's ``extensions.ReadArchive`` rules: only files and
    folders, relative paths without ``..``, at most ``MAX_FILES`` files and ``MAX_UNPACKED_BYTES`` unpacked."""
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                name = member.name
                if name.startswith("/") or "\\" in name or "\x00" in name or len(name) > MAX_PATH:
                    raise ArchiveError(f"the bundle holds an unsafe path: {name[:80]!r}")
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if ".." in parts:
                    raise ArchiveError(f"the bundle holds an unsafe path: {name[:80]!r}")
                if member.isdir():
                    continue
                if not member.isreg():
                    raise ArchiveError(f"a bundle may hold only files and folders (no links or devices): {name[:80]}")
                if not parts:
                    continue
                if len(files) >= MAX_FILES:
                    raise ArchiveError(f"a bundle holds at most {MAX_FILES} files")
                handle = archive.extractfile(member)
                content = handle.read(MAX_UNPACKED_BYTES - total + 1) if handle is not None else b""
                total += len(content)
                if total > MAX_UNPACKED_BYTES:
                    raise ArchiveError("the bundle unpacks to more than 50 MB")
                files["/".join(parts)] = content
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise ArchiveError("the bundle is not a .tar.gz") from exc
    return files


def unpack(files: dict[str, bytes], root: Path) -> None:
    """Write ``files`` (from ``read_archive``) under ``root``."""
    for name, content in files.items():
        path = root / name
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        except OSError as exc:  # e.g. a file and a folder of the same name
            raise ArchiveError(f"the bundle holds a path it can't unpack: {name[:80]!r}") from exc


def semver_key(version: str) -> tuple[int, int, int, int, str]:
    core, _, pre = version.split("+")[0].partition("-")
    major, minor, patch = (int(n) for n in core.split("."))
    return major, minor, patch, 0 if pre else 1, pre


def _bounds(op: str, major: int, minor: int, patch: int) -> list[tuple[str, tuple[int, int, int]]]:
    """A comparator as plain ``(operator, version)`` checks: ``^`` and ``~`` become a lower and an upper bound."""
    if op == "^":
        upper = (major + 1, 0, 0) if major else (0, minor + 1, 0) if minor else (0, 0, patch + 1)
        return [(">=", (major, minor, patch)), ("<", upper)]
    if op == "~":
        return [(">=", (major, minor, patch)), ("<", (major, minor + 1, 0))]
    return [(op or "=", (major, minor, patch))]


def range_ok(version: str, rng: str) -> bool:
    """Whether ``version`` satisfies a requirement's range (RANGE: ``*``, or space-separated comparators that must
    all hold; ``^1.2.3`` is ``>=1.2.3 <2.0.0``, ``^0.2.3`` is ``>=0.2.3 <0.3.0``, ``~1.2.3`` is ``>=1.2.3 <1.3.0``,
    a bare version is exact). wctl's ``satisfies`` is the same rule. Raises ``ValueError`` on a malformed range."""
    if not re.fullmatch(RANGE, rng) or len(rng) > 64:
        raise ValueError(f"{rng!r} isn't a version range (like ^1.2.0 or >=1.0.0 <2.0.0)")
    if rng == "*":
        return True
    have = semver_key(version)
    for part in rng.split(" "):
        found = re.fullmatch(_COMPARATOR, part)
        assert found is not None
        for op, bound in _bounds(found.group(1) or "", *(int(n) for n in found.group(2, 3, 4))):
            want = semver_key("{}.{}.{}".format(*bound))
            ok = {"=": have == want, ">=": have >= want, "<=": have <= want, ">": have > want, "<": have < want}[op]
            if not ok:
                return False
    return True


_NOT_PICTURE = "not a PNG, JPEG or WebP picture"


def image_info(data: bytes) -> tuple[str, int, int]:
    """A screenshot's ``(type, width, height)`` read from its bytes, whatever its name says: PNG (an ``acTL`` chunk
    before the first IDAT is an animated PNG), JPEG (the first SOF marker) or WebP (VP8, VP8L or VP8X; the extended
    header's animation flag). Raises ``ValueError`` for anything else and for animated pictures (wctl's
    ``inspectMedia`` reads them the same way)."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 33 or data[12:16] != b"IHDR":
            raise ValueError(_NOT_PICTURE)
        width, height = struct.unpack(">II", data[16:24])
        at = 8
        while at + 8 <= len(data):
            (n,), kind = struct.unpack(">I", data[at:at + 4]), data[at + 4:at + 8]
            if kind == b"acTL":
                raise ValueError("an animated picture: a screenshot stands still")
            if kind == b"IDAT" or at + 12 + n > len(data):
                break
            at += 12 + n
        return "image/png", width, height
    if data.startswith(b"\xff\xd8"):
        at = 2
        while at + 4 <= len(data):
            if data[at] != 0xFF:
                raise ValueError(_NOT_PICTURE)
            marker = data[at + 1]
            if marker == 0xFF:  # fill byte
                at += 1
                continue
            if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
                at += 2
                continue
            (n,) = struct.unpack(">H", data[at + 2:at + 4])
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                if n < 7 or at + 9 > len(data):
                    raise ValueError(_NOT_PICTURE)
                height, width = struct.unpack(">HH", data[at + 5:at + 9])
                if not width or not height:
                    raise ValueError(_NOT_PICTURE)
                return "image/jpeg", width, height
            if marker in (0xD9, 0xDA) or n < 2:  # end of image or scan data before any frame header
                raise ValueError(_NOT_PICTURE)
            at += 2 + n
        raise ValueError(_NOT_PICTURE)
    if len(data) >= 30 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        if int.from_bytes(data[4:8], "little") + 8 > len(data):
            raise ValueError(_NOT_PICTURE)
        chunk = data[12:16]
        if chunk == b"VP8 ":
            if data[23:26] != b"\x9d\x01\x2a":
                raise ValueError(_NOT_PICTURE)
            width = int.from_bytes(data[26:28], "little") & 0x3FFF
            height = int.from_bytes(data[28:30], "little") & 0x3FFF
        elif chunk == b"VP8L":
            if data[20] != 0x2F:
                raise ValueError(_NOT_PICTURE)
            bits = int.from_bytes(data[21:25], "little")
            width, height = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        elif chunk == b"VP8X":
            if data[20] & 0x02:
                raise ValueError("an animated picture: a screenshot stands still")
            width = int.from_bytes(data[24:27], "little") + 1
            height = int.from_bytes(data[27:30], "little") + 1
        else:
            raise ValueError(_NOT_PICTURE)
        if not width or not height:
            raise ValueError(_NOT_PICTURE)
        return "image/webp", width, height
    raise ValueError(_NOT_PICTURE)


_MEDIA_SUFFIX = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}


def _media(
    root: Path, pub: str, name: str, refs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """An item's screenshots (``item.json`` ``media``, files in ``media/``) as index entries and site files
    (``media/<p>/<n>/<sha256>.<ext>``), each checked: a still PNG, JPEG or WebP whose name agrees, within the
    limits."""
    where = f"items/{pub}/{name}"
    entries: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}
    total = 0
    seen: set[str] = set()
    for ref in refs:
        file = ref["file"]
        if file in seen:
            raise ValueError(f"{where}/item.json: media lists {file} twice")
        seen.add(file)
        path = root / "items" / pub / name / "media" / file
        if not path.is_file():
            raise ValueError(f"{where}/media/{file} is missing")
        data = path.read_bytes()
        if len(data) > MAX_MEDIA_BYTES:
            raise ValueError(f"{where}/media/{file} is over {MAX_MEDIA_BYTES >> 20} MiB")
        try:
            mime, width, height = image_info(data)
        except ValueError as exc:
            raise ValueError(f"{where}/media/{file}: {exc}") from exc
        named = _MEDIA_SUFFIX.get(Path(file).suffix.lower())
        if named != mime:
            raise ValueError(f"{where}/media/{file}: its name says {Path(file).suffix or 'nothing'} but it holds a "
                             f"{mime.removeprefix('image/').upper()} picture")
        low, high = MEDIA_SIDES
        if not (low <= width <= high and low <= height <= high):
            raise ValueError(f"{where}/media/{file} is {width}×{height}: a screenshot is {low} to {high} pixels a "
                             "side")
        total += len(data)
        digest = hashlib.sha256(data).hexdigest()
        rel = f"media/{pub}/{name}/{digest}.{MEDIA_EXT[mime]}"
        files[rel] = data
        entries.append({"file": rel, "sha256": digest, "size": len(data), "type": mime, "width": width,
                        "height": height, "alt": ref["alt"]})
    if total > MAX_MEDIA_TOTAL:
        raise ValueError(f"{where}: screenshots add up to over {MAX_MEDIA_TOTAL >> 20} MiB")
    return entries, files


def _requires(path: Path, where: str) -> list[dict[str, Any]]:
    """A version's ``<version>.requires.json`` (``[{"id", "range"}, …]``), checked; empty when there is none."""
    if not path.exists():
        return []
    data = _read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"{where}: a list of {{id, range}}")
    if len(data) > MAX_REQUIRES:
        raise ValueError(f"{where}: at most {MAX_REQUIRES} requirements")
    try:
        reqs = [MarketRequirement.model_validate(r).model_dump() for r in data]
    except ValidationError as exc:
        raise ValueError(f"{where}: {_one_line(exc)}") from exc
    ids = [r["id"] for r in reqs]
    if len(set(ids)) != len(ids):
        raise ValueError(f"{where}: an item is required twice")
    return reqs


def _withdrawn_reason(revoked: Any, item_id: str, version: str) -> str | None:
    for entry in revoked if isinstance(revoked, list) else []:
        if isinstance(entry, dict) and entry.get("id") == item_id and entry.get("version") in (version, "*"):
            return str(entry.get("reason", ""))
    return None


def _requirement_problems(items: list[dict[str, Any]], revoked: Any, source: Path) -> list[str]:
    """What is wrong with the items' requirements: an unknown item, a range no version that isn't withdrawn
    matches, an item requiring itself, and cycles (through each item's newest version)."""
    by_id = {i["id"]: i for i in items}
    problems = []
    for item in items:
        for v in item["versions"]:
            for req in v.get("requires") or []:
                rid, rng = req["id"], req["range"]
                where = f"{item['id']} {v['version']}"
                if rid == item["id"]:
                    problems.append(f"{where}: requires itself")
                elif rid not in by_id:
                    problems.append(f"{where}: requires {rid}, which is not in {source}")
                elif not any(range_ok(o["version"], rng) and _withdrawn_reason(revoked, rid, o["version"]) is None
                             for o in by_id[rid]["versions"]):
                    problems.append(f"{where}: no version of {rid} matches {rng}")
    graph = {i["id"]: [r["id"] for r in i["versions"][0].get("requires") or [] if r["id"] != i["id"]]
             for i in items}
    cycles: set[tuple[str, ...]] = set()
    done: set[str] = set()

    def walk(node: str, path: list[str]) -> None:
        if node in path:
            loop = path[path.index(node):]
            turn = loop.index(min(loop))
            cycles.add(tuple(loop[turn:] + loop[:turn]))
            return
        if node in done:
            return
        for nxt in graph.get(node, []):
            walk(nxt, [*path, node])
        done.add(node)

    for start in sorted(graph):
        walk(start, [])
    problems += [f"requires cycle: {' → '.join([*loop, loop[0]])}" for loop in sorted(cycles)]
    return problems


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path}: {exc}") from exc


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def check_bundle(kind: str, name: str, version: str, folder: Path) -> None:
    """The kind's document is at the bundle's root and valid."""
    doc_path = folder / KIND_FILE[kind]
    data = _read_json(doc_path)
    try:
        if kind == "extension":
            if ExtensionManifest is None:  # a vendored copy: the name and version only
                if not isinstance(data, dict):
                    raise ValueError("extension.json is an object")
                found_name, found_version = data.get("name"), data.get("version")
            else:
                manifest = ExtensionManifest.model_validate(data)
                found_name, found_version = manifest.name, manifest.version
            if found_name != name:
                raise ValueError(f"extension.json is named {found_name}, not {name}")
            if found_version != version:
                raise ValueError(f"extension.json says version {found_version}, not {version}")
        elif kind == "skill_pack":
            SkillPackMeta.model_validate(data)
            if not list(folder.glob("skills/*/SKILL.md")):
                raise ValueError("a skill pack holds skills/<folder>/SKILL.md")
        elif kind == "bot_template":
            TemplateDoc.model_validate(data)
            try:
                from .schemas import check_template  # noqa: PLC0415 - schemas imports every config module
            except ImportError:  # a vendored copy
                check_template = None
            if check_template is not None:
                check_template(data, where="template.json")
        elif kind == "mcp_preset":
            PresetDoc.model_validate(data)
        elif kind == "sticker_pack":
            pack = StickerPackDoc.model_validate(data)
            for sticker in pack.stickers:
                if not (folder / sticker.file).is_file():
                    raise ValueError(f"the sticker {sticker.name}'s file {sticker.file} is missing")
        elif kind == "lens_suite":
            _check_lens_suite(data, folder)
        elif kind == "avatar_pack":
            AvatarPackDoc.model_validate(data)
        elif kind == "persona_pack":
            personas = PersonaPackDoc.model_validate(data)
            try:
                from .schemas import check_template  # noqa: PLC0415 - schemas imports every config module
            except ImportError:  # a vendored copy
                check_template = None
            if check_template is not None:
                for t in personas.templates:
                    try:
                        check_template(t.model_dump(mode="json"), where=f"personas.json {t.template}")
                    except ValidationError as exc:
                        raise ValueError(f"personas.json {t.template}: {_one_line(exc)}") from exc
        elif kind == "check_pack":
            _check_check_pack(CheckPackDoc.model_validate(data))
        else:
            raise ValueError(f"kind is one of {', '.join(KINDS)}")
    except ValidationError as exc:
        raise ValueError(f"{doc_path}: {' '.join(str(exc).split())[:300]}") from exc
    except ValueError as exc:
        raise ValueError(f"{doc_path}: {exc}") from exc


def _check_lens_suite(data: Any, folder: Path) -> None:
    """``suite.json`` and its ``cases.jsonl``; inside Watcher Lens's own scorer check runs too."""
    suite = LensSuiteDoc.model_validate(data)
    cases = folder / "cases.jsonl"
    if not cases.is_file():
        raise ValueError("a Lens suite holds cases.jsonl beside suite.json")
    lens_cases(cases.read_text())
    if not DEEP:  # a vendored copy: the shape only
        return
    try:
        from watcher_lens.scorers import ScorerConfigError, validate  # noqa: PLC0415
    except ImportError:
        return
    try:
        validate(suite.scorer.model_dump(mode="json", exclude_none=True))
    except ScorerConfigError as exc:
        raise ValueError(f"scorer: {exc}") from exc


def _check_check_pack(pack: CheckPackDoc) -> None:
    """Inside Watcher: every check exists in this build, is the pack's bot's, isn't pinned, and its thresholds are
    the check's (a vendored copy checks the shape only)."""
    try:
        from .checks.registry import registered  # noqa: PLC0415 - imports every check module
    except ImportError:
        return
    checks = registered()
    for check_id, override in pack.overrides.items():
        cls = checks.get(check_id)
        if cls is None:
            raise ValueError(f"{check_id} is not a check of this Watcher: a pack tunes existing checks only")
        if cls.spec.bot != pack.bot:
            raise ValueError(f"{check_id} is {cls.spec.bot}'s check, not {pack.bot}'s")
        if cls.spec.pinned:
            raise ValueError(f"{check_id} is pinned: its settings can't change")
        try:
            cls.Thresholds.model_validate({**cls.Thresholds().model_dump(), **override.thresholds})
        except ValidationError as exc:
            raise ValueError(f"{check_id} thresholds: {_one_line(exc)}") from exc


class _Source:
    """A registry source folder, read."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.registry = _read_json(root / "registry.json")
        if not isinstance(self.registry, dict):
            raise ValueError(f"{root / 'registry.json'}: registry.json is an object")
        self.publishers = {
            p.stem: MarketPublisher.model_validate(_read_json(p)) for p in sorted((root / "publishers").glob("*.json"))
        }
        for pid, pub in self.publishers.items():
            if pub.id != pid:
                raise ValueError(f"publishers/{pid}.json: its id is {pub.id}")
        did = self.registry.get("did")  # optional: the registry's did:key, shown on the catalog pages
        if did is not None and not (isinstance(did, str) and re.fullmatch(_DID_KEY, did)):
            raise ValueError(f"{root / 'registry.json'}: did is the registry key's did:key (watcher market did)")

    def items(self) -> list[tuple[str, str, dict[str, Any], list[str]]]:
        """(publisher, name, item.json, versions newest first) of every item."""
        out = []
        for path in sorted((self.root / "items").glob("*/*/item.json")):
            folder = path.parent
            pub, name = folder.parent.name, folder.name
            if pub not in self.publishers:
                raise ValueError(f"{path}: no publishers/{pub}.json")
            versions = [d.name for d in folder.iterdir() if d.is_dir() and re.fullmatch(SEMVER, d.name)]
            if not versions:
                raise ValueError(f"{folder}: no <version>/ folder")
            out.append((pub, name, _read_json(path), sorted(versions, key=semver_key, reverse=True)))
        return out

    def sig_path(self, pub: str, name: str, version: str) -> Path:
        return self.root / "signatures" / pub / name / f"{version}.sig"


def _signed_by(pub: MarketPublisher, message: bytes, sig: str) -> tuple[bool, MarketPublisherKey | None]:
    """Whether one of the publisher's keys made ``sig``, and which previous key (None: its current key)."""
    if signature_ok(pub.did, message, sig):
        return True, None
    for k in pub.previous_keys:
        if signature_ok(k.did, message, sig):
            return True, k
    return False, None


def _key_problem(k: MarketPublisherKey, published_at: Any) -> str | None:
    """Why a version signed by previous key ``k`` no longer counts (Watcher withdraws it), or None."""
    if k.compromised:
        return "signed with a compromised key: run watcher market sign"
    if _when(published_at) > _when(k.until):
        return f"signed with a retired key after {k.until}: run watcher market sign"
    return None


def sign(source: Path, publisher: str, key: Path, now: datetime | None = None) -> list[str]:
    """Sign every version of ``publisher``'s items whose signature is missing or no longer matches its bundle, and
    record when each was first published (``versions.json``). Answers ``<id> <version>`` of each signed one. A
    signature by a previous key stays while that key isn't compromised and the version was published by its
    ``until``; others are signed again with the current key."""
    src = _Source(source)
    if publisher not in src.publishers:
        raise ValueError(f"no publishers/{publisher}.json in {source}")
    seed = load_key(key)
    did = src.publishers[publisher].did
    if key_did(seed) != did:
        raise ValueError(f"{key} is not {publisher}'s key ({did})")
    stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
    signed = []
    for pub, name, item, versions in src.items():
        if pub != publisher:
            continue
        kind = item.get("kind")
        if kind not in KINDS:
            raise ValueError(f"items/{pub}/{name}/item.json: kind is one of {', '.join(KINDS)}")
        published_path = source / "items" / pub / name / "versions.json"
        published = _read_json(published_path) if published_path.exists() else {}
        for version in versions:
            folder = source / "items" / pub / name / version
            check_bundle(kind, name, version, folder)
            digest = hashlib.sha256(pack_dir(folder)).hexdigest()
            message = bundle_message(kind, f"{pub}/{name}", version, digest)
            sig_path = src.sig_path(pub, name, version)
            if sig_path.exists():
                ok, old = _signed_by(src.publishers[publisher], message, sig_path.read_text().strip())
                if ok and (old is None or (version in published and _key_problem(old, published[version]) is None)):
                    continue
            sig_path.parent.mkdir(parents=True, exist_ok=True)
            sig_path.write_text(signature(seed, message) + "\n")
            published.setdefault(version, stamp)
            signed.append(f"{pub}/{name} {version}")
        _write_json(published_path, dict(sorted(published.items(), key=lambda kv: semver_key(kv[0]), reverse=True)))
    return signed


def _one_line(exc: Exception) -> str:
    return " ".join(str(exc).split())[:300]


def split_id(item_id: str) -> tuple[str, str]:
    """``(publisher, name)`` of an item id ``publisher/name``."""
    found = re.fullmatch(rf"({_PUBLISHER})/({_ITEM})", item_id)
    if not found:
        raise ValueError("an item id is <publisher>/<name>: lower-case letters, digits and dashes")
    return found.group(1), found.group(2)


# A valid version, only so an item.json can be checked as a MarketItem before it has any.
_PLACEHOLDER = {
    "version": "0.0.0", "published_at": "2000-01-01T00:00:00Z", "bundle": "x.tar.gz", "size": 1,
    "sha256": "0" * 64, "signature": "z" + "1" * 88,
}


def check_item_file(data: Any, publisher: str, name: str) -> None:
    """An ``item.json`` is a MarketItem without id, publisher and versions (``build`` adds them); its optional
    ``media`` names screenshots in the item's ``media/`` folder (MediaRef: ``{file, alt}``)."""
    if not isinstance(data, dict):
        raise ValueError("item.json is an object")
    if {"id", "publisher", "versions"} & data.keys():
        raise ValueError("item.json leaves out id, publisher and versions: build adds them")
    media = data.get("media", [])
    if not isinstance(media, list):
        raise ValueError("item.json: media is a list of {file, alt}")
    if len(media) > MAX_MEDIA:
        raise ValueError(f"item.json: media holds at most {MAX_MEDIA} screenshots")
    try:
        for ref in media:
            MediaRef.model_validate(ref)
        MarketItem.model_validate({**{k: v for k, v in data.items() if k != "media"}, "id": f"{publisher}/{name}",
                                   "publisher": publisher, "versions": [_PLACEHOLDER]})
    except ValidationError as exc:
        raise ValueError(f"item.json: {_one_line(exc)}") from exc


def _version(
    src: _Source, pub: str, name: str, kind: str, version: str, published: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    """One version's index entry and bundle, its files checked and its publisher's signature verified (by its
    current key, or a previous key that was neither compromised nor retired before the version was published)."""
    source = src.root
    folder = source / "items" / pub / name / version
    check_bundle(kind, name, version, folder)
    data = pack_dir(folder)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError(f"{pub}/{name} {version}: the bundle is over {MAX_BUNDLE_BYTES >> 20} MiB")
    digest = hashlib.sha256(data).hexdigest()
    sig_path = src.sig_path(pub, name, version)
    if not sig_path.exists():
        raise ValueError(f"{pub}/{name} {version} is not signed: run watcher market sign")
    sig = sig_path.read_text().strip()
    ok, old = _signed_by(src.publishers[pub], bundle_message(kind, f"{pub}/{name}", version, digest), sig)
    if not ok:
        raise ValueError(f"{pub}/{name} {version}: its signature doesn't match its files (changed after "
                         "signing?): sign it again")
    if version not in published:
        raise ValueError(f"{pub}/{name} {version}: no published_at in versions.json: run watcher market sign")
    if old is not None and (problem := _key_problem(old, published[version])):
        raise ValueError(f"{pub}/{name} {version}: {problem}")
    changelog = source / "items" / pub / name / f"{version}.md"
    entry = {
        "version": version, "published_at": published[version],
        "changelog": changelog.read_text().strip() if changelog.exists() else "",
        "bundle": f"bundles/{pub}/{name}/{version}.tar.gz", "size": len(data), "sha256": digest, "signature": sig,
    }
    if old is not None:
        entry["signer"] = old.did
    requires = _requires(source / "items" / pub / name / f"{version}.requires.json",
                         f"{pub}/{name}/{version}.requires.json")
    if requires:
        entry["requires"] = requires
    return entry, data


def _assemble(
    src: _Source, problems: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """Every item's index entry and every site file (bundles and screenshots, by their path in the site). Without
    ``problems`` the first problem raises; with a list each is appended and its version (or item) left out, and an
    item left without versions is dropped. A publisher's key handover that doesn't verify is a problem too, and so
    is a requirement no item of the source meets (or a cycle of them)."""
    items: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}
    for problem in _handover_problems(src.publishers.values()):
        if problems is None:
            raise ValueError(problem)
        problems.append(problem)
    for pub, name, item, versions in src.items():
        try:
            kind = item.get("kind") if isinstance(item, dict) else None
            if kind not in KINDS:
                raise ValueError(f"items/{pub}/{name}/item.json: kind is one of {', '.join(KINDS)}")
            try:
                check_item_file(item, pub, name)
            except ValueError as exc:
                raise ValueError(f"items/{pub}/{name}/{exc}") from exc
            media, media_files = _media(src.root, pub, name, item.get("media", []))
            published_path = src.root / "items" / pub / name / "versions.json"
            published = _read_json(published_path) if published_path.exists() else {}
            if not isinstance(published, dict):
                raise ValueError(f"{published_path}: versions.json is an object")
        except ValueError as exc:
            if problems is None:
                raise
            problems.append(str(exc))
            continue
        entries = []
        for version in versions:
            try:
                entry, data = _version(src, pub, name, kind, version, published)
            except ValueError as exc:
                if problems is None:
                    raise
                problems.append(str(exc))
                continue
            files[entry["bundle"]] = data
            entries.append(entry)
        if entries:
            entry = {k: v for k, v in item.items() if k != "media"}
            if media:
                entry["media"] = media
                files.update(media_files)
            items.append({**entry, "id": f"{pub}/{name}", "publisher": pub, "versions": entries})
    revoked_path = src.root / "revoked.json"
    revoked = _read_json(revoked_path) if revoked_path.exists() else []
    for problem in _requirement_problems(items, revoked, src.root):
        if problems is None:
            raise ValueError(problem)
        problems.append(problem)
    return items, files


def _fields(src: _Source, items: list[dict[str, Any]]) -> dict[str, Any]:
    """The index's fields but ``generated_at``."""
    revoked_path = src.root / "revoked.json"
    return {
        "format": 1, "name": src.registry.get("name"), "url": src.registry.get("url"),
        "publishers": [p.model_dump(mode="json") for p in src.publishers.values()],
        "items": items,
        "revoked": _read_json(revoked_path) if revoked_path.exists() else [],
    }


def build(
    source: Path, out: Path, key: Path, now: datetime | None = None, previous_key: Path | None = None,
) -> MarketIndexFile:
    """Pack every version, check its publisher's signature, and write the site: ``out/bundles/…`` and the
    screenshots ``out/media/<publisher>/<name>/<sha256>.<ext>`` (files no longer in the source are removed),
    ``out/index.json`` signed with the registry's ``key`` (and named in the index's ``key``), ``out/.nojekyll`` and
    the catalog pages (``market_site``: ``index.html``, ``catalog.css``, ``items/<publisher>/<name>/index.html``;
    pages of items no longer in the source are removed).
    ``registry.json``'s optional ``did`` must be ``key``'s. While the registry moves to a new key, ``previous_key``
    (the old one) endorses the same index message, so Watchers that pin it keep syncing until an admin accepts the
    new key."""
    src = _Source(source)
    seed = load_key(key)
    old_seed = load_key(previous_key) if previous_key is not None else None
    if old_seed is not None and key_did(old_seed) == key_did(seed):
        raise ValueError("--previous-key is the registry's current key: pass the key it moves from")
    items, files = _assemble(src)
    generated_at = (now or datetime.now(UTC)).astimezone(UTC)
    index = MarketIndex.model_validate({**_fields(src, items), "generated_at": generated_at, "key": key_did(seed)})
    doc = _index_doc(index)
    message = index_message(doc)
    endorsement = None
    if old_seed is not None:
        endorsement = MarketEndorsement(did=key_did(old_seed), signature=signature(old_seed, message))
    result = MarketIndexFile(index=index, signature=signature(seed, message), endorsement=endorsement)
    registry_did = src.registry.get("did")
    if registry_did is not None and registry_did != key_did(seed):
        raise ValueError(f"registry.json's did {registry_did} isn't the key's ({key_did(seed)})")
    shutil.rmtree(out / "bundles", ignore_errors=True)
    shutil.rmtree(out / "media", ignore_errors=True)
    for rel, data in files.items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
    written: dict[str, Any] = {"index": doc, "signature": result.signature}
    if endorsement is not None:
        written["endorsement"] = endorsement.model_dump(mode="json")
    _write_json(out / "index.json", written)
    (out / ".nojekyll").write_bytes(b"")
    shutil.rmtree(out / "items", ignore_errors=True)
    for rel, page in market_site.render(doc, registry_did).items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(page)
    return result


def lint(source: Path, site: Path | None = None) -> list[str]:
    """Every problem a build would find in a registry source, without any key (signatures are checked against the
    publishers' did:keys); with ``site``, also that the built site is the source's (index, every bundle, screenshot
    and catalog page, no stale bundle, screenshot or page). Empty when it is clean."""
    try:
        src = _Source(source)
    except ValueError as exc:
        return [_one_line(exc)]
    problems: list[str] = []
    try:
        items, files = _assemble(src, problems)
        fields = _fields(src, items)
    except ValueError as exc:  # the source's layout (an item without publisher or version folder, revoked.json)
        return [*problems, _one_line(exc)]
    valid = True
    try:
        MarketIndex.model_validate({**fields, "generated_at": datetime.now(UTC)})
    except ValidationError as exc:
        valid = False
        problems.append(f"the index: {_one_line(exc)}")
    for entry in fields["revoked"] if isinstance(fields["revoked"], list) else []:
        if not isinstance(entry, dict):
            continue
        item_id, version = entry.get("id"), entry.get("version")
        folder = source / "items" / str(item_id)
        known = (
            isinstance(item_id, str)
            and re.fullmatch(rf"{_PUBLISHER}/{_ITEM}", item_id) is not None
            and (folder / "item.json").is_file()
            and (version == "*" or (isinstance(version, str) and re.fullmatch(SEMVER, version) is not None
                                    and (folder / version).is_dir()))
        )
        if not known:
            problems.append(f"revoked.json: {item_id} {version} is not in {source}")
    if site is not None and valid:
        problems += _site_problems(source, site, fields, files, src.registry.get("did"))
    return problems


def _site_problems(
    source: Path, site: Path, fields: dict[str, Any], files: dict[str, bytes], did: str | None = None,
) -> list[str]:
    """What differs between a built site and what ``build`` would write from the source (bar the time and the
    registry's signature, which ``check`` verifies): the index, every bundle, screenshot and catalog page, and no
    stale bundle, screenshot or page."""
    try:
        raw = json.loads((site / "index.json").read_text())
        MarketIndexFile.model_validate(raw)
    except (OSError, ValueError) as exc:
        return [f"{site}/index.json: {_one_line(exc)}"]
    problems = []
    generated_at = raw["index"]["generated_at"]
    expected = _index_doc(MarketIndex.model_validate(
        {**fields, "generated_at": generated_at, "key": raw["index"].get("key")}))
    if expected != raw["index"]:
        problems.append(f"{site}/index.json is out of date with {source}: build it again")
    for rel, data in files.items():
        path = site / rel
        if not path.is_file():
            problems.append(f"{site}/{rel} is missing")
        elif path.read_bytes() != data:
            problems.append(f"{site}/{rel} differs from {source}")
    stale = [*(site / "bundles").rglob("*.tar.gz"), *(p for p in (site / "media").rglob("*") if p.is_file())]
    for path in sorted(stale):
        rel = path.relative_to(site).as_posix()
        if rel not in files:
            problems.append(f"{site}/{rel} is not in {source} any more")
    pages = market_site.render(expected, did)
    for rel, page in pages.items():
        path = site / rel
        if not path.is_file():
            problems.append(f"{site}/{rel} is missing")
        elif path.read_bytes() != page:
            problems.append(f"{site}/{rel} differs from {source}")
    for path in sorted((site / "items").rglob("*")):
        rel = path.relative_to(site).as_posix()
        if path.is_file() and rel not in pages:
            problems.append(f"{site}/{rel} is not in {source} any more")
    return problems


# --- writing a source (watcher market new, version, revoke) -----------------------------------------------------
def _bundle_files(kind: str, name: str, title: str, summary: str, url: str | None, domain: str) -> dict[str, Any]:
    """A working 1.0.0 of the kind: relative path → a JSON value, text (``str``) or bytes."""
    if kind == "extension":
        return {
            "extension.json": {
                "name": name, "title": title, "version": "1.0.0", "description": summary,
                "tools": [{"name": "hello", "description": "Says hello to a name", "run": ["python3", "hello.py"],
                           "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}}}],
            },
            "tools/hello/hello.py": 'import json, sys\nprint("Hello, " + json.load(sys.stdin).get("name", "there"))\n',
        }
    if kind == "skill_pack":
        return {
            "skillpack.json": {"domain": domain},
            f"skills/{name}/SKILL.md": (
                f"---\nname: {name}\ndescription: {summary}\n---\n\n# {title}\n\n"
                "Write the steps the bot follows here.\n"
            ),
        }
    if kind == "bot_template":
        tid = name.replace("-", "_")
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", tid):
            raise ValueError(f"a starter bot's id comes from the item name: {tid} needs a letter first and at most "
                             "32 characters")
        return {"template.json": _starter(tid, title, summary)}
    if kind == "persona_pack":
        base = name.replace("-", "_")[:24]
        if not re.fullmatch(r"[a-z][a-z0-9_]*", base):
            raise ValueError(f"a bot pack's ids come from the item name: {base} needs a letter first")
        lead, helper = f"{base}_lead", f"{base}_helper"
        return {"personas.json": {
            "templates": [_starter(lead, f"{title} lead"[:80], summary),
                          _starter(helper, f"{title} helper"[:80], summary)],
            "botchat": {lead: [helper]},
        }}
    if kind == "lens_suite":
        cases = [{"case_id": "hello-1", "input": {"text": "hello"}, "expected": "hello"},
                 {"case_id": "hello-2", "input": {"text": "goodbye"}, "expected": "goodbye"}]
        return {
            "suite.json": {"slug": name, "name": title, "description": summary, "scorer": {"type": "exact"}},
            "cases.jsonl": "".join(json.dumps(c, sort_keys=True) + "\n" for c in cases),
        }
    if kind == "avatar_pack":
        return {"avatars.json": {"pack": title[:40], "characters": [{
            "id": f"m-{name}"[:32].rstrip("-"), "name": title[:40], "tagline": summary[:140],
            "body": "#7c5cff", "accent": "#ffd166", "shape": "blob", "motion": "bob",
            "personality": f"{title[:200]}: friendly and calm.",
            "top": [{"el": "circle", "cx": 32, "cy": 6, "r": 4, "fill": "accent.base", "stroke": "line",
                     "stroke_width": 1.5}],
        }]}}
    if kind == "check_pack":
        return {"checks.json": {"bot": "lookout", "overrides": {"LKT-SLOW-01": {"thresholds": {"slow_s": 5}}}}}
    if kind == "mcp_preset":
        if not url or not url.startswith("https://"):
            raise ValueError("an MCP preset needs --url, the server's https address")
        return {"preset.json": {
            "name": title[:60], "blurb": summary, "keywords": "",
            "remote": {"url": url, "auth": "oauth", "dcr": True, "note": ""},
        }}
    return {
        "stickers.json": {"pack": title[:40], "stickers": [
            {"name": "hello", "description": f"{title}: hello", "file": "hello.png"},
        ]},
        "hello.png": png(256, (124, 92, 255)),
    }


def _starter(tid: str, title: str, summary: str) -> dict[str, Any]:
    """A read-only starter bot's template.json (a bot_template, or one of a persona pack's)."""
    return {
        "template": tid, "title": title, "summary": summary,
        "bot": {
            "display_name": title, "icon": ":seedling:", "avatar": "scout", "tagline": summary,
            "suggestions": ["What can you do?"],
            "persona": f"{title} answers questions plainly and never changes anything.",
            "respond": "mentions", "access": "read_only", "models": {"qa": ["@default"]},
        },
        "connectors": [],
    }


def scaffold(
    source: Path, item_id: str, kind: str, *, title: str, summary: str, url: str | None = None,
    domain: str = "general", key: Path | None = None, publisher_name: str | None = None,
) -> Path:
    """Start an item in a registry source: ``item.json`` and a working ``1.0.0/`` of its kind (checked as a bundle),
    plus ``publishers/<publisher>.json`` from ``key`` when the publisher is new. Answers the item's folder."""
    pub, name = split_id(item_id)
    if kind not in KINDS:
        raise ValueError(f"kind is one of {', '.join(KINDS)}")
    pub_path = source / "publishers" / f"{pub}.json"
    publisher_doc = None
    if not pub_path.exists():
        if key is None:
            raise ValueError(f"no publishers/{pub}.json: pass --key (your publisher key) to write it")
        publisher_doc = {"id": pub, "name": publisher_name or pub, "did": key_did(load_key(key))}
        try:
            MarketPublisher.model_validate(publisher_doc)
        except ValidationError as exc:
            raise ValueError(f"publishers/{pub}.json: {_one_line(exc)}") from exc
    elif key is not None:
        did = MarketPublisher.model_validate(_read_json(pub_path)).did
        if key_did(load_key(key)) != did:
            raise ValueError(f"{key} is not {pub}'s key ({did})")
    folder = source / "items" / pub / name
    if folder.exists():
        raise ValueError(f"items/{pub}/{name} exists")
    item = {"kind": kind, "title": title, "summary": summary}
    check_item_file(item, pub, name)
    files = _bundle_files(kind, name, title, summary, url, domain)
    try:
        if publisher_doc is not None:
            _write_json(pub_path, publisher_doc)
        _write_json(folder / "item.json", item)
        for rel, value in files.items():
            path = folder / "1.0.0" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                path.write_bytes(value)
            elif isinstance(value, str):
                path.write_text(value)
            else:
                _write_json(path, value)
        check_bundle(kind, name, "1.0.0", folder / "1.0.0")
    except ValueError:
        shutil.rmtree(folder, ignore_errors=True)
        if publisher_doc is not None:
            pub_path.unlink(missing_ok=True)
        raise
    return folder


def _version_folders(folder: Path) -> list[str]:
    """An item's version folders, newest first."""
    found = [d.name for d in folder.iterdir() if d.is_dir() and re.fullmatch(SEMVER, d.name)]
    return sorted(found, key=semver_key, reverse=True)


def add_version(source: Path, item_id: str, version: str, *, base: str | None = None) -> Path:
    """Add a version to an item: a copy of its newest (or ``base``) version folder, an extension's manifest bumped.
    Answers the new folder."""
    pub, name = split_id(item_id)
    folder = source / "items" / pub / name
    if not (folder / "item.json").is_file():
        raise ValueError(f"no item {item_id} in {source}")
    if not re.fullmatch(SEMVER, version):
        raise ValueError(f"{version} isn't a semver version (like 1.2.0)")
    target = folder / version
    if target.exists():
        raise ValueError(f"{item_id} {version} exists")
    versions = _version_folders(folder)
    if not versions:
        raise ValueError(f"{folder}: no <version>/ folder")
    newest = versions[0]
    base = base or newest
    if base not in versions:
        raise ValueError(f"{item_id} has no version {base}")
    if semver_key(version) <= semver_key(newest):
        raise ValueError(f"{version} isn't newer than {newest}")
    shutil.copytree(folder / base, target)
    requires = folder / f"{base}.requires.json"
    if requires.is_file():
        shutil.copyfile(requires, folder / f"{version}.requires.json")
    item = _read_json(folder / "item.json")
    if isinstance(item, dict) and item.get("kind") == "extension":
        manifest = _read_json(target / "extension.json")
        if isinstance(manifest, dict):
            manifest["version"] = version
            _write_json(target / "extension.json", manifest)
    return target


def revoke(source: Path, item_id: str, version: str, reason: str) -> None:
    """Withdraw a version of an item (``*``: every version) in ``revoked.json``."""
    pub, name = split_id(item_id)
    folder = source / "items" / pub / name
    if not (folder / "item.json").is_file():
        raise ValueError(f"no item {item_id} in {source}")
    if version != "*" and not (re.fullmatch(SEMVER, version) and (folder / version).is_dir()):
        raise ValueError(f"{item_id} has no version {version}")
    path = source / "revoked.json"
    entries = _read_json(path) if path.exists() else []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: revoked.json is a list")
    if any(isinstance(e, dict) and e.get("id") == item_id and e.get("version") == version for e in entries):
        raise ValueError(f"{item_id} {version} is already withdrawn")
    if len(entries) >= 500:
        raise ValueError("revoked.json holds at most 500 entries")
    try:
        entry = MarketRevocation.model_validate({"id": item_id, "version": version, "reason": reason})
    except ValidationError as exc:
        raise ValueError(f"revoked.json: {_one_line(exc)}") from exc
    _write_json(path, [*entries, entry.model_dump()])


def _publisher_file(source: Path, publisher: str) -> tuple[Path, MarketPublisher]:
    path = source / "publishers" / f"{publisher}.json"
    if not path.is_file():
        raise ValueError(f"no publishers/{publisher}.json in {source}")
    try:
        return path, MarketPublisher.model_validate(_read_json(path))
    except ValidationError as exc:
        raise ValueError(f"publishers/{publisher}.json: {_one_line(exc)}") from exc


def _write_publisher(path: Path, doc: dict[str, Any]) -> MarketPublisher:
    try:
        publisher = MarketPublisher.model_validate(doc)
    except ValidationError as exc:
        raise ValueError(f"{path.name}: {_one_line(exc)}") from exc
    written = _publisher_doc(publisher)
    if written.get("url") is None:
        written.pop("url", None)
    _write_json(path, written)
    return publisher


def _until(now: datetime | None, pub: MarketPublisher) -> str:
    """Now to the second, rounded up, so a version signed this second is still the old key's; and at least a second
    after the publisher's newest previous key's until (they are strictly ordered)."""
    when = (now or datetime.now(UTC)).astimezone(UTC)
    if when.microsecond:
        when = when.replace(microsecond=0) + timedelta(seconds=1)
    if pub.previous_keys and when <= _when(pub.previous_keys[0].until):
        when = _when(pub.previous_keys[0].until) + timedelta(seconds=1)
    return _utc_second(when)


def rotate(source: Path, publisher: str, key: Path, new_key: Path, now: datetime | None = None) -> str:
    """Move a publisher to a new key: the current key becomes the newest of ``previous_keys`` (until now) with its
    signed handover to the new key. Versions it signed stay valid; ``sign`` signs only with the new key from then on.
    Answers the new did:key."""
    path, pub = _publisher_file(source, publisher)
    old_seed = load_key(key)
    if key_did(old_seed) != pub.did:
        raise ValueError(f"{key} is not {publisher}'s current key ({pub.did})")
    new_did = key_did(load_key(new_key))
    if new_did == pub.did or new_did in {k.did for k in pub.previous_keys}:
        raise ValueError(f"{new_key} is one of {publisher}'s keys already: make a new one with watcher market keygen")
    until = _until(now, pub)
    handover = signature(old_seed, key_message(publisher, pub.did, new_did, until))
    doc = pub.model_dump(mode="json")
    doc["previous_keys"] = [{"did": pub.did, "until": until, "handover": handover}, *doc["previous_keys"]]
    doc["did"] = new_did
    _write_publisher(path, doc)
    return new_did


def retire(
    source: Path, publisher: str, reason: str, *, did: str | None = None, new_key: Path | None = None,
    until: str | None = None, compromised: bool = False,
) -> None:
    """Retire one of a publisher's keys: versions it signed after ``until`` (default now) count as withdrawn, and
    every version it signed when ``compromised``. Retiring the current key needs ``new_key``, which becomes the
    current key (no handover: the old key may be lost). Retiring a previous key again updates its entry; its
    ``until`` only moves earlier."""
    path, pub = _publisher_file(source, publisher)
    target = did or pub.did
    doc = pub.model_dump(mode="json")
    if until is not None and not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", until):
        raise ValueError(f"until is a UTC time like 2026-11-01T12:00:00Z, not {until}")
    if target == pub.did:
        if new_key is None:
            raise ValueError("retiring the current key needs --new-key: a publisher always has a current key "
                             "(to drop the publisher, withdraw its items with revoke)")
        new_did = key_did(load_key(new_key))
        if new_did == pub.did or new_did in {k.did for k in pub.previous_keys}:
            raise ValueError(f"{new_key} is one of {publisher}'s keys already: make a new one with watcher market "
                             "keygen")
        entry = {"did": pub.did, "until": until or _until(None, pub), "reason": reason, "compromised": compromised}
        doc["previous_keys"] = [entry, *doc["previous_keys"]]
        doc["did"] = new_did
    else:
        entry = next((k for k in doc["previous_keys"] if k["did"] == target), None)
        if entry is None:
            raise ValueError(f"{target} is not one of {publisher}'s keys")
        if until is not None:
            if until > entry["until"]:
                raise ValueError(f"until only moves earlier (now {entry['until']})")
            entry["until"] = until
        entry["reason"] = reason
        entry["compromised"] = entry["compromised"] or compromised
    if entry["compromised"]:
        entry["handover"] = None
    _write_publisher(path, doc)


def vendor(out: Path, version: str) -> Path:
    """Copy the marketplace tools (this module, ``market_cli``, ``market_site`` and ``vouch``) into
    ``out/watcher_market``, a package a registry repository runs with Python and pydantic only. Other files there are
    left alone."""
    dest = out / "watcher_market"
    dest.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).parent
    for name in ("market.py", "market_cli.py", "market_site.py", "vouch.py"):
        (dest / name).write_bytes((here / name).read_bytes())
    (dest / "__init__.py").write_text(
        f'"""The Watcher Marketplace tools, vendored from Watcher {version} by `watcher market vendor`.\n\n'
        "Don't edit these files: refresh them from Watcher. Needs Python 3.12 and pydantic 2. Run:\n"
        'PYTHONPATH=<parent folder> python -m watcher_market --help\n"""\n'
    )
    (dest / "__main__.py").write_text("from .market_cli import main\n\nraise SystemExit(main())\n")
    return dest


def png(side: int, color: tuple[int, int, int]) -> bytes:
    """A side×side RGB PNG: a disc of ``color`` on white."""
    rows = b""
    centre, radius = (side - 1) / 2, side * 0.4
    for y in range(side):
        row = b"\0"
        for x in range(side):
            inside = (x - centre) ** 2 + (y - centre) ** 2 <= radius**2
            row += bytes(color) if inside else b"\xff\xff\xff"
        rows += row

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    header = struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def check(out: Path, did: str) -> list[str]:
    """What is wrong with a built site, checked as wctl does: the index's schema and signature by ``did`` (or, while
    the registry moves to the key the index names, ``did``'s endorsement plus that key's signature), every
    publisher's key handovers, and every bundle's size, checksum and publisher signature (by its ``signer``). Empty
    when it is good."""
    try:
        raw = _read_json(out / "index.json")
        parsed = MarketIndexFile.model_validate(raw)
    except (ValueError, ValidationError) as exc:
        return [f"index.json: {' '.join(str(exc).split())[:300]}"]
    problems = []
    message = index_message(raw["index"])
    named = parsed.index.key
    if signature_ok(did, message, parsed.signature):
        if named is not None and named != did:
            problems.append(f"index.json: the index names key {named} but is signed by {did}")
    elif not (
        parsed.endorsement is not None and parsed.endorsement.did == did and named is not None
        and signature_ok(did, message, parsed.endorsement.signature) and signature_ok(named, message, parsed.signature)
    ):
        problems.append(f"index.json: the registry's signature doesn't match {did}")
    problems += [f"index.json: {p}" for p in _handover_problems(parsed.index.publishers)]
    publishers = {p.id: p for p in parsed.index.publishers}
    for item in parsed.index.items:
        for v in item.versions:
            where = f"{item.id} {v.version}"
            path = out / v.bundle
            if not path.is_file():
                problems.append(f"{where}: {v.bundle} is missing")
                continue
            data = path.read_bytes()
            if len(data) != v.size or hashlib.sha256(data).hexdigest() != v.sha256:
                problems.append(f"{where}: the bundle doesn't match its checksum")
                continue
            message = bundle_message(item.kind, item.id, v.version, v.sha256)
            if not signature_ok(v.signer or publishers[item.publisher].did, message, v.signature):
                problems.append(f"{where}: the publisher's signature doesn't match")
        for m in item.media:
            path = out / m.file
            if not path.is_file():
                problems.append(f"{item.id}: {m.file} is missing")
                continue
            data = path.read_bytes()
            if len(data) != m.size or hashlib.sha256(data).hexdigest() != m.sha256:
                problems.append(f"{item.id}: {m.file} doesn't match its checksum")
    return problems


# --- item files (watcher market export / try) -------------------------------------------------------------------
TRY_KEY = DEFAULT_KEY_DIR / "try.key"


class MarketItemFile(Strict):
    """A signed item file an admin imports without a registry (``#/market`` → Import a file). ``export`` writes it
    with the publisher's key; ``try`` with a throwaway key and ``trial`` set (only a test stack imports those).
    ``signature`` is the publisher's signature of ``item_file_message`` (the item, the publisher and ``trial``, as
    written); the bundle's bytes are covered by its one version's own bundle signature."""

    format: Literal[1]
    trial: bool = Field(strict=True)
    publisher: MarketPublisher
    item: MarketItem
    bundle: str = Field(max_length=14_000_000, pattern=r"^[A-Za-z0-9+/]*={0,2}$")  # the .tar.gz, base64
    signature: Signature

    @model_validator(mode="after")
    def _one(self) -> MarketItemFile:
        if len(self.item.versions) != 1:
            raise ValueError("an item file holds exactly one version")
        if self.item.publisher != self.publisher.id:
            raise ValueError(f"the item's publisher is {self.item.publisher}, not the file's {self.publisher.id}")
        if self.item.versions[0].bundle != "bundle.tar.gz":
            raise ValueError("an item file's version names its bundle bundle.tar.gz")
        return self


def item_file_schema() -> dict[str, Any]:
    """The JSON Schema of an item file (control/schema/market_item_file.schema.json)."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$comment": "generated by `watcher schema export` from watcher.market; do not edit",
        **MarketItemFile.model_json_schema(),
    }


def item_file_message(doc: dict[str, Any]) -> bytes:
    """What an item file's ``signature`` signs: its ``item``, ``publisher`` and ``trial`` as written."""
    return ITEM_CONTEXT + vouch.canonical({"item": doc["item"], "publisher": doc["publisher"], "trial": doc["trial"]})


def _item_doc(item: MarketItem) -> dict[str, Any]:
    """An item as JSON, as an index writes it (unused optional fields left out)."""
    return _trim_item(item.model_dump(mode="json"))


def _write_item_file(
    path: Path, publisher: MarketPublisher, item: dict[str, Any], data: bytes, seed: bytes, *, trial: bool,
) -> Path:
    try:
        doc = {"item": _item_doc(MarketItem.model_validate(item)), "publisher": _publisher_doc(publisher),
               "trial": trial}
        written = {**doc, "format": 1, "bundle": base64.b64encode(data).decode(),
                   "signature": signature(seed, item_file_message(doc))}
        MarketItemFile.model_validate(written)
    except ValidationError as exc:
        raise ValueError(f"the item file: {_one_line(exc)}") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(written, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return path


def _item_json(folder: Path, pub: str, name: str) -> tuple[dict[str, Any], str]:
    """An item's checked ``item.json`` (without its ``media``: an item file carries no screenshots) and its kind."""
    item = _read_json(folder / "item.json")
    kind = item.get("kind") if isinstance(item, dict) else None
    if kind not in KINDS:
        raise ValueError(f"items/{pub}/{name}/item.json: kind is one of {', '.join(KINDS)}")
    try:
        check_item_file(item, pub, name)
    except ValueError as exc:
        raise ValueError(f"items/{pub}/{name}/{exc}") from exc
    return {k: v for k, v in item.items() if k != "media"}, kind


def export(source: Path, item_id: str, key: Path, *, version: str | None = None, out: Path | None = None) -> Path:
    """Write one signed version of an item as an item file (default ``<publisher>-<name>-<version>.market.json``):
    the version must be signed (``sign``) and ``key`` is the publisher's current key. ``verified`` is false: no
    registry vouches for a file. Answers the file's path."""
    pub, name = split_id(item_id)
    src = _Source(source)
    folder = source / "items" / pub / name
    if pub not in src.publishers or not (folder / "item.json").is_file():
        raise ValueError(f"no item {item_id} in {source}")
    item, kind = _item_json(folder, pub, name)
    versions = _version_folders(folder)
    version = version or (versions[0] if versions else None)
    if version not in versions:
        raise ValueError(f"{item_id} has no version {version}")
    publisher = src.publishers[pub]
    seed = load_key(key)
    if key_did(seed) != publisher.did:
        raise ValueError(f"{key} is not {pub}'s key ({publisher.did})")
    published_path = folder / "versions.json"
    published = _read_json(published_path) if published_path.exists() else {}
    if not isinstance(published, dict):
        raise ValueError(f"{published_path}: versions.json is an object")
    entry, data = _version(src, pub, name, kind, version, published)
    doc = {**item, "verified": False, "id": item_id, "publisher": pub,
           "versions": [{**entry, "bundle": "bundle.tar.gz"}]}
    path = out or Path(f"{pub}-{name}-{version}.market.json")
    return _write_item_file(path, publisher.model_copy(update={"verified": False}), doc, data, seed, trial=False)


def try_file(
    source: Path, item_id: str, *, version: str | None = None, out: Path | None = None, key: Path | None = None,
    now: datetime | None = None,
) -> Path:
    """Write a version of an item, signed or not, as a trial item file for a test stack: signed with a throwaway key
    (``key``, default ``~/.config/watcher-market/try.key``, made when missing) under the publisher ``try-<publisher>``,
    so it never collides with the real item. Nothing in the source is signed or changed. Answers the file's path."""
    pub, name = split_id(item_id)
    folder = source / "items" / pub / name
    if not (folder / "item.json").is_file():
        raise ValueError(f"no item {item_id} in {source}")
    item, kind = _item_json(folder, pub, name)
    versions = _version_folders(folder)
    version = version or (versions[0] if versions else None)
    if version not in versions:
        raise ValueError(f"{item_id} has no version {version}")
    try_pub = f"try-{pub}"
    if len(try_pub) > 40:
        raise ValueError(f"{try_pub} is longer than a publisher id may be (40)")
    check_bundle(kind, name, version, folder / version)
    data = pack_dir(folder / version)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError(f"{item_id} {version}: the bundle is over {MAX_BUNDLE_BYTES >> 20} MiB")
    key = key or TRY_KEY
    if not key.expanduser().exists():
        keygen(key)
    seed = load_key(key)
    try_id, digest = f"{try_pub}/{name}", hashlib.sha256(data).hexdigest()
    changelog = folder / f"{version}.md"
    entry = {
        "version": version, "published_at": _utc_second(now or datetime.now(UTC)),
        "changelog": changelog.read_text().strip() if changelog.exists() else "",
        "bundle": "bundle.tar.gz", "size": len(data), "sha256": digest,
        "signature": signature(seed, bundle_message(kind, try_id, version, digest)),
    }
    publisher = MarketPublisher(id=try_pub, name=f"{pub} (try)"[:80], did=key_did(seed))
    doc = {**item, "verified": False, "id": try_id, "publisher": try_pub, "versions": [entry]}
    path = out or Path(f"{try_pub}-{name}-{version}.market.json")
    return _write_item_file(path, publisher, doc, data, seed, trial=True)


def read_item_file(path: Path) -> tuple[MarketItemFile, bytes]:
    """An item file and its bundle's bytes, checked as wctl's import does: its schema, the publisher's signature of
    the file, the bundle's size, checksum and signature, and the kind's document. Raises ``ValueError``."""
    if path.stat().st_size > MAX_ITEM_FILE_BYTES:
        raise ValueError(f"the item file is over {MAX_ITEM_FILE_BYTES >> 20} MiB")
    try:
        raw = json.loads(path.read_bytes())
    except ValueError as exc:
        raise ValueError("the file is not a marketplace item file") from exc
    try:
        parsed = MarketItemFile.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"the item file: {_one_line(exc)}") from exc
    publisher, item, v = parsed.publisher, parsed.item, parsed.item.versions[0]
    if not signature_ok(publisher.did, item_file_message(raw), parsed.signature):
        raise ValueError("the publisher's signature of the item file doesn't match")
    if problems := _handover_problems([publisher]):
        raise ValueError(f"the item file: {problems[0]}")
    try:
        data = base64.b64decode(parsed.bundle, validate=True)
    except ValueError as exc:
        raise ValueError("the item file's bundle is not base64") from exc
    where = f"{item.id} {v.version}"
    if len(data) != v.size or hashlib.sha256(data).hexdigest() != v.sha256:
        raise ValueError(f"{where}: the bundle doesn't match its checksum")
    if v.signer is not None:
        old = next((k for k in publisher.previous_keys if k.did == v.signer), None)
        if old is None:
            raise ValueError(f"{where}: its signer {v.signer} is not one of {publisher.id}'s keys")
        if problem := _key_problem(old, v.published_at):
            raise ValueError(f"{where}: {problem}")
    if not signature_ok(v.signer or publisher.did, bundle_message(item.kind, item.id, v.version, v.sha256),
                        v.signature):
        raise ValueError(f"{where}: the publisher's signature doesn't match")
    with tempfile.TemporaryDirectory(prefix="watcher-market-") as tmp:
        unpack(read_archive(data), Path(tmp))
        try:
            check_bundle(item.kind, split_id(item.id)[1], v.version, Path(tmp))
        except ValueError as exc:
            raise ValueError(f"{where}: {str(exc).replace(tmp + '/', '')}") from exc
    return parsed, data


# --- diff (watcher market diff): what a version changes, as the console's update preview ------------------------
def front_matter(text: str) -> dict[str, str]:
    """A SKILL.md's top-level ``name`` and ``description``, read as wctl's ``frontMatter`` does (plain, quoted or
    block-scalar values between the first two ``---`` lines)."""
    out = {"name": "", "description": ""}
    lines = text.replace("\r\n", "\n").split("\n")
    if lines[0].strip() != "---":
        return out
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), len(lines))
    i = 1
    while i < end:
        line = lines[i]
        if line == "" or line[0] in " \t" or ":" not in line:
            i += 1
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if value and value[0] in ">|":
            block = []
            while i + 1 < end and (lines[i + 1] == "" or lines[i + 1][0] in " \t"):
                i += 1
                block.append(lines[i].strip())
            value = _block_scalar(block, folded=value[0] == ">")
        elif len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        if key.strip() in out:
            out[key.strip()] = value
        i += 1
    return out


def _block_scalar(lines: list[str], *, folded: bool) -> str:
    """wctl's ``blockScalar``: folded joins a paragraph's lines with spaces and keeps blank lines as line breaks."""
    while lines and lines[-1] == "":
        lines = lines[:-1]
    if not folded:
        return "\n".join(lines)
    out = ""
    for i, line in enumerate(lines):
        if line == "":
            out += "\n"
        elif i > 0 and lines[i - 1] != "":
            out += " " + line
        else:
            out += line
    return out


def _minus(a: list[str], b: list[str]) -> list[str]:
    return [s for s in a if s not in b]


def _needs(tool: dict[str, Any]) -> list[str]:
    """What an admin enables before an extension tool runs (wctl's ``ToolSpec.Needs``)."""
    return [n for n, on in (("network", tool.get("network")), ("secret", tool.get("env"))) if on]


def extension_changes(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """What a new ``extension.json`` adds to an old one, as wctl's ``extensionChanges`` (the update preview): tools,
    needs per tool, env, triggers, an app. A shared vector pins the two (testdata/market/diff)."""
    old_tools = {t.get("name"): t for t in old.get("tools") or []}
    old_env = {e for t in old_tools.values() for e in t.get("env") or []}
    added: list[str] = []
    env: list[str] = []
    needs: dict[str, list[str]] = {}
    for tool in new.get("tools") or []:
        name = tool.get("name")
        prev = old_tools.get(name)
        if prev is None:
            added.append(name)
        fresh = [n for n in _needs(tool) if prev is None or n not in _needs(prev)]
        if fresh:
            needs[name] = fresh
        env += [e for e in tool.get("env") or [] if e not in old_env and e not in env]
    old_triggers = {t.get("name") for t in old.get("triggers") or []}
    triggers = [t.get("name") for t in new.get("triggers") or [] if t.get("name") not in old_triggers]
    return {"added_tools": added, "new_needs": needs, "added_env": env, "added_triggers": triggers,
            "app_added": old.get("app") is None and new.get("app") is not None}


def _document(kind: str, files: dict[str, bytes]) -> dict[str, Any]:
    name = KIND_FILE.get(kind)
    if name is None:
        raise ValueError(f"kind is one of {', '.join(KINDS)}")
    try:
        doc = json.loads(files[name])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"the bundle has no valid {name} at its root") from exc
    if not isinstance(doc, dict):
        raise ValueError(f"{name} is an object")
    return doc


def _skill_names(files: dict[str, bytes]) -> list[str]:
    """A skill pack's skills, as wctl's ``prepareSkillPack`` names them (front matter name, else the folder)."""
    names = []
    for path in sorted(files):
        folder, _, file = path.removeprefix("skills/").partition("/")
        if path.startswith("skills/") and file == "SKILL.md":
            names.append(front_matter(files[path].decode("utf-8", "replace"))["name"] or folder)
    return names


def _sticker_shas(files: dict[str, bytes]) -> dict[str, str]:
    """A sticker pack's pictures by name (in the pack's order): their sha256."""
    doc = _document("sticker_pack", files)
    return {s.get("name"): hashlib.sha256(files.get(s.get("file"), b"")).hexdigest()
            for s in doc.get("stickers") or [] if isinstance(s, dict)}


def _changed_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """The top-level keys that differ, one level deeper for objects (``bot.persona``)."""
    out = []
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        if a == b:
            continue
        if isinstance(a, dict) and isinstance(b, dict):
            out += [f"{key}.{k}" for k in sorted(a.keys() | b.keys()) if a.get(k) != b.get(k)]
        else:
            out.append(key)
    return out


def changes(kind: str, old: dict[str, bytes], new: dict[str, bytes]) -> dict[str, Any]:
    """What version ``new`` (its files) changes against ``old``, per kind as the console's update preview shows it;
    starter bots and MCP presets (which wctl doesn't compare) list their ``changed_fields``."""
    if kind == "extension":
        return extension_changes(_document(kind, old), _document(kind, new))
    if kind == "skill_pack":
        before, after = _skill_names(old), _skill_names(new)
        return {"added": _minus(after, before), "removed": _minus(before, after)}
    if kind == "sticker_pack":
        before, after = _sticker_shas(old), _sticker_shas(new)
        names = sorted(before)
        return {"added": _minus(list(after), names), "removed": _minus(names, list(after)),
                "changed": [n for n in names if n in after and after[n] != before[n]]}
    return {"changed_fields": _changed_fields(_document(kind, old), _document(kind, new))}


def _version_files(where: Path, item_id: str, version: str) -> tuple[str, dict[str, bytes]]:
    """(kind, files) of one version of an item in a registry source, or in a built site (its bundle checked against
    its size, checksum and publisher signature, and unpacked with wctl's rules)."""
    pub, name = split_id(item_id)
    if (where / "registry.json").is_file():
        folder = where / "items" / pub / name
        if not (folder / "item.json").is_file():
            raise ValueError(f"no item {item_id} in {where}")
        _, kind = _item_json(folder, pub, name)
        if version not in _version_folders(folder):
            raise ValueError(f"{item_id} has no version {version}")
        root = folder / version
        return kind, {rel.as_posix(): (root / rel).read_bytes() for rel in _files(root) if (root / rel).is_file()}
    if (where / "index.json").is_file():
        try:
            index = MarketIndexFile.model_validate(_read_json(where / "index.json")).index
        except ValidationError as exc:
            raise ValueError(f"{where}/index.json: {_one_line(exc)}") from exc
        item = next((i for i in index.items if i.id == item_id), None)
        if item is None:
            raise ValueError(f"no item {item_id} in {where}")
        v = next((v for v in item.versions if v.version == version), None)
        if v is None:
            raise ValueError(f"{item_id} has no version {version}")
        data = (where / v.bundle).read_bytes()
        if len(data) != v.size or hashlib.sha256(data).hexdigest() != v.sha256:
            raise ValueError(f"{item_id} {version}: the bundle doesn't match its checksum")
        did = v.signer or next(p.did for p in index.publishers if p.id == item.publisher)
        if not signature_ok(did, bundle_message(item.kind, item.id, v.version, v.sha256), v.signature):
            raise ValueError(f"{item_id} {version}: the publisher's signature doesn't match")
        return item.kind, read_archive(data)
    raise ValueError(f"{where} is neither a registry source (registry.json) nor a built site (index.json)")


def diff(where: Path, item_id: str, a: str, b: str) -> dict[str, Any]:
    """What version ``b`` of an item changes against version ``a``, from a registry source or a built site:
    ``{item, kind, from, to, changes, files: {added, removed, changed}}`` (``changes`` as ``changes``). A site's
    bundles are checked against their publisher's signature, not the registry's (``check --did`` does that)."""
    if a == b:
        raise ValueError(f"{a} and {b} are the same version")
    kind, old = _version_files(where, item_id, a)
    _, new = _version_files(where, item_id, b)
    return {
        "item": item_id, "kind": kind, "from": a, "to": b, "changes": changes(kind, old, new),
        "files": {
            "added": sorted(new.keys() - old.keys()),
            "removed": sorted(old.keys() - new.keys()),
            "changed": sorted(k for k in old.keys() & new.keys() if old[k] != new[k]),
        },
    }
