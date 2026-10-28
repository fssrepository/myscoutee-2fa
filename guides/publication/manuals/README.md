# MyScoutee 2FA technical guide

The English PDF is `MyScoutee_2FA_Technical_Guide_EN.pdf`. Its editable source is `myscoutee-2fa-guide-en.html`, `manual.css` and `myscoutee-logo.png`. Keep the document version at 1.5.0 for subsequent corrections unless explicitly requested to change it. Keep only the versionless PDF in Git; rebuild it in place after source edits.

Build from the repository root with `node guides/publication/manuals/build-manual.mjs`. The builder uses the sibling MyScoutee backend frontend Playwright installation by default; set `DOCS_PLAYWRIGHT_PACKAGE_ROOT` to another installed Playwright package when needed. Set `DOCS_CHROME_PATH` if Chrome is installed elsewhere.
