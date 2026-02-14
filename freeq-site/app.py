"""freeq.at — static site with markdown docs rendering."""

import os
from pathlib import Path

from flask import Flask, render_template, abort, send_from_directory
import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.toc import TocExtension

app = Flask(__name__)

# Docs directory — repo docs/ relative to this file
DOCS_DIR = Path(__file__).parent / "docs"

# Markdown renderer
MD_EXTENSIONS = [
    FencedCodeExtension(),
    CodeHiliteExtension(css_class="highlight", guess_lang=False),
    TableExtension(),
    TocExtension(permalink=True),
    "nl2br",
]


def render_md(filepath: Path) -> dict:
    """Render a markdown file, return {html, toc, title}."""
    text = filepath.read_text()
    md = markdown.Markdown(extensions=MD_EXTENSIONS)
    html = md.convert(text)
    toc = getattr(md, "toc", "")
    # Extract title from first H1
    title = "freeq"
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    md.reset()
    return {"html": html, "toc": toc, "title": title}


# ── Routes ────────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/connect/")
def connect():
    return render_template("connect.html")


@app.route("/sdk/")
def sdk():
    return render_template("sdk.html")


@app.route("/about/")
def about():
    return render_template("about.html")


@app.route("/docs/")
def docs_index():
    return render_template("docs_index.html")


@app.route("/docs/<path:slug>/")
def docs_page(slug):
    """Render a doc page from the docs/ directory."""
    # Map URL slugs to filenames
    slug_map = {
        "protocol": "PROTOCOL.md",
        "features": "Features.md",
        "limitations": "KNOWN-LIMITATIONS.md",
        "architecture": "architecture-decisions.md",
        "s2s": "s2s-audit.md",
        "future": "FutureDirection.md",
        "web-infra": "proposal-web-infra.md",
    }
    filename = slug_map.get(slug)
    if not filename:
        abort(404)
    filepath = DOCS_DIR / filename
    if not filepath.exists():
        abort(404)
    doc = render_md(filepath)
    return render_template("doc_page.html", doc=doc)


@app.route("/favicon.ico")
def favicon():
    return "", 204


if __name__ == "__main__":
    app.run(debug=True, port=8000)
