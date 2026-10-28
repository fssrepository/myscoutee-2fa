#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(directory, '..', '..', '..');
const source = path.join(directory, 'myscoutee-2fa-guide-en.html');
const output = path.join(directory, 'MyScoutee_2FA_Technical_Guide_EN.pdf');
const required = [source, path.join(directory, 'manual.css'), path.join(directory, 'myscoutee-logo.png')];
for (const file of required) await fs.access(file);

const packageRoot = process.env.DOCS_PLAYWRIGHT_PACKAGE_ROOT
  ? path.resolve(process.env.DOCS_PLAYWRIGHT_PACKAGE_ROOT)
  : path.resolve(repository, '..', 'myscoutee-backend', 'frontend');
const requireFromPackage = createRequire(path.join(packageRoot, 'package.json'));
const { chromium } = requireFromPackage('playwright');
const browser = await chromium.launch({
  executablePath: process.env.DOCS_CHROME_PATH || '/usr/bin/google-chrome',
  headless: true,
  args: ['--disable-dev-shm-usage', '--font-render-hinting=none', ...(process.getuid?.() === 0 ? ['--no-sandbox'] : [])]
});
const page = await browser.newPage({ locale: 'en-US', colorScheme: 'light' });
const errors = [];
page.on('pageerror', error => errors.push(error.message));
page.on('requestfailed', request => errors.push(`${request.url()}: ${request.failure()?.errorText}`));
try {
  await page.goto(pathToFileURL(source).href, { waitUntil: 'load' });
  await page.emulateMedia({ media: 'print' });
  await page.evaluate(async () => {
    await document.fonts.ready;
    for (const image of document.images) {
      if (!image.complete) await new Promise((resolve, reject) => {
        image.addEventListener('load', resolve, { once: true });
        image.addEventListener('error', reject, { once: true });
      });
    }
  });
  const validation = await page.evaluate(() => {
    const problems = [];
    if (document.documentElement.lang !== 'en') problems.push('missing English language');
    if (!document.querySelector('.cover img')?.naturalWidth) problems.push('logo did not load');
    if (!document.querySelector('link[rel="stylesheet"]')) problems.push('stylesheet is missing');
    const ids = [...document.querySelectorAll('[id]')].map(node => node.id);
    if (new Set(ids).size !== ids.length) problems.push('duplicate HTML id');
    for (const link of document.querySelectorAll('a[href^="#"]')) {
      if (!document.getElementById(decodeURIComponent(link.hash.slice(1)))) problems.push(`broken internal link: ${link.hash}`);
    }
    return problems;
  });
  errors.push(...validation);
  if (errors.length) throw new Error(errors.join('\n'));
  await page.pdf({
    path: output,
    format: 'A4',
    preferCSSPageSize: true,
    printBackground: true,
    displayHeaderFooter: true,
    tagged: true,
    outline: true,
    headerTemplate: `<div style="box-sizing:border-box;color:#5b6773;font-family:Arial,sans-serif;font-size:7.5px;padding:0 16mm;width:100%;"><span style="float:left">MyScoutee · 2FA Technical Guide</span><span style="float:right">MSC-2FA-001 · 1.5.0</span></div>`,
    footerTemplate: `<div style="box-sizing:border-box;color:#5b6773;font-family:Arial,sans-serif;font-size:7.5px;padding:0 16mm;width:100%;"><span style="float:left">Development documentation · 28 Oct 2026 · EN</span><span style="float:right"><span class="pageNumber"></span> / <span class="totalPages"></span> pages</span></div>`
  });
  const file = await fs.open(output, 'r');
  try { const magic = Buffer.alloc(5); await file.read(magic, 0, 5, 0); if (magic.toString('ascii') !== '%PDF-') throw new Error('invalid PDF output'); }
  finally { await file.close(); }
  const stats = await fs.stat(output);
  if (stats.size < 10_000) throw new Error(`PDF too small: ${stats.size} bytes`);
  process.stdout.write(`Generated ${path.relative(repository, output)} (${stats.size} bytes)\n`);
} finally {
  await page.close();
  await browser.close();
}
