import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BASE = '/blastradius';
export const DIST = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist');

/** Every built page, as a route under the base ("/blastradius/docs/why/"), read from dist/. */
export function routes() {
  const out = [];
  const walk = dir => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === 'index.html') out.push(`${BASE}/${path.relative(DIST, dir).split(path.sep).join('/')}/`.replace(/\/+$/, '/').replace(`${BASE}//`, `${BASE}/`));
      else if (e.name === '404.html') out.push(`${BASE}/404.html`);
    }
  };
  walk(DIST);
  return out.sort();
}

/** Does this URL path (under the base) exist in dist/? Directories resolve to their index.html. */
export function builtFile(urlPath) {
  const rel = decodeURIComponent(urlPath.slice(BASE.length)).replace(/^\/+/, '');
  const p = path.join(DIST, rel);
  if (!p.startsWith(DIST)) return null;
  if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  const idx = path.join(p, 'index.html');
  return fs.existsSync(idx) ? idx : null;
}

/** Five reviewed advisories, enough for the page to call the feed LIVE. */
export const ADVISORIES = ['critical', 'high', 'high', 'medium', 'low', 'critical'].map((severity, i) => ({
  ghsa_id: `GHSA-aaaa-bbbb-c${i}c${i}`,
  cve_id: `CVE-2026-100${i}`,
  severity,
  summary: `Fixture advisory number ${i}`,
  html_url: `https://github.com/advisories/GHSA-aaaa-bbbb-c${i}c${i}`,
  published_at: `2026-10-0${i + 1}T00:00:00Z`,
  vulnerabilities: [{ package: { ecosystem: 'npm', name: `fixture-pkg-${i}` } }],
}));

export async function stubGitHub(page) {
  await page.route('https://api.github.com/**', r => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(ADVISORIES) }));
}

export async function blockGitHub(page) {
  await page.route('https://api.github.com/**', r => r.abort());
}

/** Fonts: never hit the network. Answer with empty CSS and record which families were asked for. */
export async function stubFonts(page, seen) {
  await page.route(/https:\/\/fonts\.(googleapis|gstatic)\.com\/.*/, r => {
    const u = new URL(r.request().url());
    for (const f of u.searchParams.getAll('family')) seen.add(f.split(':')[0]);
    return r.fulfill({ status: 200, contentType: 'text/css', body: '' });
  });
}

/** Collect console errors and uncaught page errors. */
export function watchErrors(page) {
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
  page.on('pageerror', e => errors.push(`pageerror: ${e.message}`));
  return errors;
}
