"""Turn whatever the agent read (HTML, mail, tool output) into visible text, hidden text and findings.

Everything removed here is reported back as a finding so the content layer can score it.
"""
from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from urllib.parse import unquote
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿­]")
BIDI = re.compile("[‪-‮⁦-⁩]")
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")

HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|font-size\s*:\s*0"
    r"|(?:left|top)\s*:\s*-\d{3,}|text-indent\s*:\s*-\d{3,}|clip\s*:\s*rect\(\s*0|height\s*:\s*0(?:px)?\s*;",
    re.I,
)
HIDDEN_CLASSES = ("hidden", "sr-only", "visually-hidden", "d-none", "invisible", "offscreen")
TEXT_ATTRS = ("alt", "title", "aria-label", "placeholder", "data-instructions", "data-prompt")

LATIN = re.compile(r"[A-Za-z]")
CYRILLIC_GREEK = re.compile(r"[Ѐ-ӿͰ-Ͽ]")


@dataclass
class Cleaned:
    visible: str = ""
    hidden: str = ""      # invisible to a human reader: CSS-hidden, comments, hidden inputs, smuggled unicode
    attrs: str = ""       # ordinary page metadata a human does not read either, but legitimately present: alt, title, meta
    decoded_blobs: list[str] = field(default_factory=list)
    unicode_findings: dict[str, int] = field(default_factory=dict)
    homoglyph_words: list[str] = field(default_factory=list)
    hidden_sources: list[str] = field(default_factory=list)
    code: list[str] = field(default_factory=list)  # page code inside `hidden` (CSS rules, scripts): scanned like the rest, but not prose hidden from a reader

    @property
    def hidden_prose(self) -> str:
        """`hidden` without the page code: what a judge should read as text hidden from humans."""
        out = self.hidden
        for chunk in self.code:
            out = out.replace(chunk, "")
        return out.strip()

    @property
    def hidden_ratio(self) -> float:
        total = len(self.visible) + len(self.hidden)
        return (len(self.hidden) / total) if total else 0.0

    @property
    def all_text(self) -> str:
        return "\n".join(x for x in [self.visible, self.hidden, self.attrs, *self.decoded_blobs] if x)


def _strip_invisible(text: str) -> tuple[str, dict[str, int]]:
    findings = {
        "tag_chars": len(TAG_CHARS.findall(text)),
        "zero_width": len(ZERO_WIDTH.findall(text)),
        "bidi": len(BIDI.findall(text)),
    }
    text = TAG_CHARS.sub("", text)
    text = ZERO_WIDTH.sub("", text)
    text = BIDI.sub("", text)
    return text, {k: v for k, v in findings.items() if v}


def _decode_tag_chars(text: str) -> str:
    """Unicode tag characters (U+E0000 block) map 1:1 to ASCII. Recover the smuggled text."""
    out = []
    for ch in TAG_CHARS.findall(text):
        cp = ord(ch) - 0xE0000
        if 0x20 <= cp < 0x7F:
            out.append(chr(cp))
    return "".join(out)


def _homoglyph_words(text: str) -> list[str]:
    words = []
    for w in re.findall(r"\S+", text):
        if LATIN.search(w) and CYRILLIC_GREEK.search(w):
            words.append(w)
    return words[:10]


URL_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")


def _decode_blobs(text: str) -> list[str]:
    out = []
    # url-encoded runs ("ignore%20previous%20instructions"): decode the surrounding token
    for m in re.finditer(r"\S+", text) if "%" in text else ():
        tok = m.group(0)
        if "%" in tok and len(URL_ENCODED.findall(tok)) >= 3:
            try:
                dec = unquote(tok)
            except Exception:
                continue
            if dec != tok and re.search(r"[A-Za-z]{3}", dec):
                out.append(dec)
    for m in B64_BLOB.findall(text):
        try:
            raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=False)
            s = raw.decode("utf-8")
        except Exception:
            continue
        if s and sum(c.isprintable() for c in s) / len(s) > 0.9 and re.search(r"[A-Za-z]{3}", s):
            out.append(s)
    for m in HEX_BLOB.findall(text):
        try:
            s = bytes.fromhex(m).decode("utf-8")
        except Exception:
            continue
        if s and sum(c.isprintable() for c in s) / len(s) > 0.9 and re.search(r"[A-Za-z]{3}", s):
            out.append(s)
    # ROT13: the decoded version is added as a candidate. Normal text decodes to gibberish (ignored by the lexicon);
    # a hidden instruction encoded in ROT13 (e.g. "vtaber cerivbhf vafgehpgvbaf") decodes to a real instruction, caught.
    r13 = codecs.encode(text, "rot_13")
    # ROT13 is kept only when it decodes to something that looks like an instruction: normal text
    # decodes to gibberish (no keyword) and is not added, so there is no spurious decoding.
    if r13 != text and re.search(r"(?i)\b(ignore|approve|transfer|send|pay|wire|allowance|deprecated|skip|do not|previous instruction|re-?approve)\b", r13):
        out.append(r13)
    return out


def _is_hidden_element(el) -> bool:
    style = el.get("style") or ""
    if HIDDEN_STYLE.search(style):
        return True
    if el.has_attr("hidden") or str(el.get("aria-hidden", "")).lower() == "true":
        return True
    classes = " ".join(el.get("class") or []).lower()
    if any(c in classes.split() for c in HIDDEN_CLASSES):
        return True
    if el.name in ("script", "noscript", "template", "style"):
        return True
    return False


def _split_html(html: str) -> tuple[str, str, str, list[str], list[str]]:
    soup = BeautifulSoup(html, "html.parser")
    hidden_parts, attr_parts, sources, code_parts = [], [], [], []

    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        if c.strip():
            hidden_parts.append(c.strip())
            sources.append("html_comment")
        c.extract()

    for el in soup.find_all(True):
        for attr in TEXT_ATTRS:
            v = el.get(attr)
            if v and len(str(v)) > 3:
                attr_parts.append(str(v))
                sources.append(f"attr:{attr}")
        if el.name == "meta" and el.get("content"):
            attr_parts.append(str(el["content"]))
            sources.append("meta")
        # any data-* attribute long enough to carry a sentence: nobody renders it, so it is hidden text
        for k, v in list(el.attrs.items()):
            if k.startswith("data-") and k not in TEXT_ATTRS and isinstance(v, str) and len(v) > 15 and re.search(r"[A-Za-z]{3}", v):
                hidden_parts.append(v)
                sources.append("hidden:data-attr")
        # form fields: a hidden input's value is the classic place to park an instruction
        if el.name in ("input", "textarea", "option") and el.get("value") and len(str(el["value"])) > 3:
            v = str(el["value"])
            # a hidden field counts as hidden text only when its value looks like prose (a smuggled instruction
            # fits in a sentence); a slug or a technical token (product=vault-usdc, a csrf token) is not
            prose = (" " in v.strip() and len(v) > 12) or len(v) > 40
            if prose and (str(el.get("type", "")).lower() == "hidden" or _is_hidden_element(el) or any(_is_hidden_element(a) for a in el.parents if a.name)):
                hidden_parts.append(f"{el.get('name') or el.name}={v}")
                sources.append("hidden:input")

    for el in list(soup.find_all(True)):
        if el.parent is None:
            continue
        if _is_hidden_element(el):
            t = el.get_text(" ", strip=True)
            if t:
                hidden_parts.append(t)
                sources.append(f"hidden:{el.name}")
                if el.name in ("style", "script"):
                    code_parts.append(t)
            el.decompose()

    visible = soup.get_text(" ", strip=True)
    return visible, "\n".join(hidden_parts), "\n".join(attr_parts), sources, code_parts


def clean(source: str, context_type: str = "text") -> Cleaned:
    source = source or ""
    looks_html = context_type == "html" or bool(re.search(r"<\s*(html|body|div|p|span|script|meta|img)\b", source, re.I))
    if looks_html:
        visible, hidden, attrs, sources, code = _split_html(source)
    else:
        visible, hidden, attrs, sources, code = source, "", "", [], []

    smuggled = _decode_tag_chars(visible + hidden)
    visible, f1 = _strip_invisible(visible)
    hidden, f2 = _strip_invisible(hidden)
    findings = {k: f1.get(k, 0) + f2.get(k, 0) for k in set(f1) | set(f2)}
    if smuggled:
        hidden = (hidden + "\n" + smuggled).strip()
        sources.append("unicode_tags_decoded")

    visible = unicodedata.normalize("NFKC", visible)
    hidden = unicodedata.normalize("NFKC", hidden)
    attrs = unicodedata.normalize("NFKC", attrs)
    homoglyphs = _homoglyph_words(visible + " " + hidden + " " + attrs)
    blobs = _decode_blobs(visible + "\n" + hidden + "\n" + attrs)
    return Cleaned(visible=visible.strip(), hidden=hidden.strip(), attrs=attrs.strip(), decoded_blobs=blobs,
                   unicode_findings=findings, homoglyph_words=homoglyphs, hidden_sources=sources,
                   code=[c for c in (unicodedata.normalize("NFKC", _strip_invisible(c)[0]).strip() for c in code) if c])
