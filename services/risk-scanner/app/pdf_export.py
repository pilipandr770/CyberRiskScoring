"""
Renders the two report markdown documents (agent/underwriter and client)
to a downloadable, professionally-styled PDF via WeasyPrint. Same source
markdown either report already has — this module only handles the
markdown -> styled HTML -> PDF conversion, not report content.
"""

import markdown as md_lib

from app.config import INSURER_NAME

_BASE_CSS = """
@page { size: A4; margin: 2.2cm 1.8cm; }
body { font-family: 'DejaVu Sans', sans-serif; font-size: 10.5pt; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 20pt; margin-bottom: 0.2em; }
h2 { font-size: 13pt; margin-top: 1.4em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }
h3 { font-size: 11pt; margin-top: 1em; }
code, pre { font-family: 'DejaVu Sans Mono', monospace; font-size: 9pt; }
pre { background: #f5f5f5; padding: 0.8em; border-radius: 4px; white-space: pre-wrap; }
em { color: #555; }
ul, ol { margin: 0.3em 0; padding-left: 1.4em; }
li { margin-bottom: 0.25em; }
.header-band { background: #14213d; color: white; padding: 1em 1.4em; margin: -2.2cm -1.8cm 1.2em -1.8cm; }
.header-band h1 { color: white; margin: 0; }
.header-band .subtitle { font-size: 9pt; opacity: 0.85; }
"""


def _wrap(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>{_BASE_CSS}</style></head>
<body>
<div class="header-band">
  <h1>{title}</h1>
  <div class="subtitle">{INSURER_NAME}</div>
</div>
{body_html}
</body></html>"""


def markdown_to_pdf(markdown_text: str, title: str) -> bytes:
    from weasyprint import HTML

    body_html = md_lib.markdown(markdown_text, extensions=["extra", "sane_lists"])
    full_html = _wrap(title, body_html)
    return HTML(string=full_html).write_pdf()
