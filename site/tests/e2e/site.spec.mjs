import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import { BASE, ADVISORIES, builtFile, routes, stubFonts, stubGitHub, blockGitHub, watchErrors } from './helpers.mjs';

const ROUTES = routes();
const GENERATED = ROUTES.filter(r => /\/docs\/(why|action|mcp|playbooks)\//.test(r));

test('the built site has the routes the brief names', () => {
  for (const r of ['/', '/docs/', '/docs/why/', '/docs/action/', '/docs/mcp/', '/docs/playbooks/', '/404.html']) expect(ROUTES).toContain(BASE + r);
  expect(ROUTES.filter(r => r.startsWith(`${BASE}/docs/playbooks/`)).length).toBeGreaterThan(1);
  expect(fs.existsSync(builtFile(`${BASE}/llms.txt`))).toBe(true);
  expect(fs.existsSync(builtFile(`${BASE}/robots.txt`))).toBe(true);
});

for (const route of ROUTES) {
  test.describe(route, () => {
    test.beforeEach(async ({ page }) => {
      await stubFonts(page, new Set());
      await stubGitHub(page);
    });

    test('loads without console or page errors, and the game runs', async ({ page }) => {
      const errors = watchErrors(page);
      await page.goto(route);
      await expect(page.locator('#src')).toHaveText('LIVE', { timeout: 10_000 });
      const game = await page.evaluate(() => window.brGame());
      expect(game.zones.length).toBeGreaterThan(0);
      expect(game.source).toBe('live');
      await page.waitForTimeout(300);
      expect(errors).toEqual([]);
    });

    for (const width of [390, 1280]) {
      test(`does not scroll sideways at ${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 800 });
        await page.goto(route);
        await page.waitForLoadState('load');
        const m = await page.evaluate(() => ({ s: document.documentElement.scrollWidth, c: document.documentElement.clientWidth, b: document.body.scrollWidth }));
        expect(m.s, `scrollWidth ${m.s} vs clientWidth ${m.c}`).toBeLessThanOrEqual(m.c);
        expect(m.b).toBeLessThanOrEqual(m.c);
      });
    }

    test('the HUD stays one row at 1280px', async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(route);
      await page.waitForLoadState('load');
      await page.evaluate(() => document.fonts.ready);
      const rows = await page.evaluate(() => new Set([...document.querySelectorAll('.hud .wrap > *')].filter(e => e.offsetParent).map(e => (r => Math.round((r.top + r.bottom) / 40))(e.getBoundingClientRect()))).size);
      expect(rows).toBe(1);
    });

    test('every internal link resolves to a built page and an existing anchor', async ({ page }) => {
      await page.goto(route);
      const links = await page.evaluate(() => [...document.querySelectorAll('a[href], img[src], link[href], script[src]')].map(e => e.getAttribute('href') ?? e.getAttribute('src')));
      const problems = [];
      const ids = new Map();
      const idsOf = file => {
        if (!ids.has(file)) ids.set(file, new Set([...fs.readFileSync(file, 'utf8').matchAll(/\sid="([^"]+)"/g)].map(m => m[1])));
        return ids.get(file);
      };
      for (const raw of links) {
        if (!raw || /^(mailto:|tel:|data:|javascript:)/.test(raw)) continue;
        const u = new URL(raw, `http://localhost:4321${route}`);
        if (u.origin !== 'http://localhost:4321') continue;
        if (!u.pathname.startsWith(BASE + '/') && u.pathname !== BASE) { problems.push(`outside base: ${raw}`); continue; }
        const file = builtFile(u.pathname === BASE ? BASE + '/' : u.pathname);
        if (!file) { problems.push(`404: ${raw}`); continue; }
        if (u.hash && u.hash.length > 1 && file.endsWith('.html') && !idsOf(file).has(decodeURIComponent(u.hash.slice(1)))) problems.push(`missing anchor: ${raw}`);
      }
      expect(problems).toEqual([]);
    });
  });
}

test.describe('home', () => {
  test('the latest table fills with rows from the feed', async ({ page }) => {
    await stubFonts(page, new Set());
    await stubGitHub(page);
    await page.goto(`${BASE}/`);
    await expect(page.locator('#latestbody tr')).toHaveCount(Math.min(8, ADVISORIES.length));
    await expect(page.locator('#latestbody')).toContainText('GHSA-aaaa-bbbb-c0c0');
    await expect(page.locator('#latestnote')).toContainText('Live');
  });

  test('the Install key goes to the home page install section', async ({ page }) => {
    await stubFonts(page, new Set());
    await stubGitHub(page);
    await page.goto(`${BASE}/docs/why/`);
    const href = await page.locator('header a', { hasText: 'Install' }).first().getAttribute('href');
    expect(href).toBe(`${BASE}/#install`);
  });
});

test.describe('without the GitHub API', () => {
  for (const route of [`${BASE}/`, `${BASE}/docs/`]) {
    test(`${route} falls back to SAMPLE`, async ({ page }) => {
      const errors = watchErrors(page);
      await stubFonts(page, new Set());
      await blockGitHub(page);
      await page.goto(route);
      await expect(page.locator('#src')).toHaveText('SAMPLE', { timeout: 10_000 });
      const game = await page.evaluate(() => window.brGame());
      expect(game.source).toBe('sample');
      if (route === `${BASE}/`) await expect(page.locator('#latestbody tr').first()).toBeVisible();
      // The blocked request is the only failure the browser may log.
      expect(errors.filter(e => !/api\.github\.com|Failed to load resource|ERR_FAILED/.test(e))).toEqual([]);
    });
  }
});

test.describe('generated pages', () => {
  test('every H2 sits in a section.zone with a data-level', async ({ page }) => {
    await stubFonts(page, new Set());
    await stubGitHub(page);
    for (const route of GENERATED) {
      await page.goto(route);
      const bad = await page.evaluate(() => [...document.querySelectorAll('article h2')].filter(h => {
        const s = h.closest('section.zone');
        return !s || !s.getAttribute('data-level') || !s.getAttribute('data-zone');
      }).map(h => h.textContent));
      expect(bad, route).toEqual([]);
      const last = await page.evaluate(() => { const z = [...document.querySelectorAll('article section.zone')]; return z.at(-1)?.getAttribute('data-zone'); });
      expect(last, route).toBe('core');
    }
  });

  test('scrolling to a section marks its sidebar link', async ({ page }) => {
    await stubFonts(page, new Set());
    await stubGitHub(page);
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE}/docs/why/`);
    const ids = await page.evaluate(() => [...document.querySelectorAll('article section.zone[id]')].map(s => s.id));
    expect(ids.length).toBeGreaterThan(2);
    for (const id of [ids[1], ids.at(-1)]) {
      await page.evaluate(i => document.getElementById(i).scrollIntoView({ block: 'start' }), id);
      await expect(page.locator(`.side a.on`)).toHaveAttribute('href', `#${id}`);
    }
  });

  test('Copy copies the commands without prompts or output', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'http://localhost:4321' });
    await stubFonts(page, new Set());
    await stubGitHub(page);
    await page.goto(`${BASE}/docs/playbooks/appsec-oncall/`);
    const block = page.locator('.code').first();
    await block.locator('.copy').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('br demo status');

    await page.goto(`${BASE}/docs/mcp/`);
    const multi = page.locator('.code', { hasText: 'printf' }).first();
    await multi.locator('.copy').click();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied.startsWith("printf '%s\\n' \\\n")).toBe(true);
    expect(copied).toContain('| br mcp');
    expect(copied).not.toMatch(/^\$ /m);
  });
});

test('the fonts requested are Jersey 10, JetBrains Mono and VT323 only', async ({ page }) => {
  const seen = new Set();
  await stubFonts(page, seen);
  await stubGitHub(page);
  for (const route of ['/', '/docs/', '/docs/why/', '/404.html']) await page.goto(BASE + route);
  expect([...seen].sort()).toEqual(['Jersey 10', 'JetBrains Mono', 'VT323']);
});

test('the 404 page says Lost underground and links home', async ({ page }) => {
  await stubFonts(page, new Set());
  await stubGitHub(page);
  await page.goto(`${BASE}/404.html`);
  await expect(page.locator('h1')).toContainText('Lost underground');
  await expect(page.locator('main a.key').first()).toHaveAttribute('href', `${BASE}/`);
});
