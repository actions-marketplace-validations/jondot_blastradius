import test from 'node:test';
import assert from 'node:assert/strict';
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import remarkRehype from 'remark-rehype';
import rehypeStringify from 'rehype-stringify';
import rehypeGame, { rewriteHref, rewriteSrc, classify, isShell } from '../../src/lib/game-markdown.mjs';

async function render(md, path = '/repo/docs/page.md', options = {}) {
  const file = await unified()
    .use(remarkParse).use(remarkGfm).use(remarkRehype)
    .use(rehypeGame, { base: '/blastradius', ...options })
    .use(rehypeStringify)
    .process({ value: md, path });
  return { html: String(file), fm: file.data.astro.frontmatter };
}

const sections = html => [...html.matchAll(/<section([^>]*)>/g)].map(m => m[1]);

test('splits at each H2, takes the title and lede out, and gives the intro its own section', async () => {
  const { html, fm } = await render('# Title\n\nThe lede.\n\nIntro text.\n\n## One\n\na\n\n## Two\n\nb\n');
  assert.equal(fm.title, 'Title');
  assert.equal(fm.ledeText, 'The lede.');
  assert.deepEqual(fm.toc, [{ id: 'one', text: 'One' }, { id: 'two', text: 'Two' }]);
  const s = sections(html);
  assert.equal(s.length, 3);
  assert.match(s[0], /data-zone="topsoil"/);
  assert.match(s[0], /data-level="TITLE · INTRO"/);
  assert.match(s[1], /id="one"/);
  assert.match(s[1], /data-level="TITLE · ONE"/);
  assert.match(html, /<p class="tag">Part 1<\/p><h2 id="one-heading">One <a class="anchor" href="#one"/);
  assert.doesNotMatch(html, /<h1/);
  assert.doesNotMatch(html, /The lede/);
});

test('zones cycle and the last section is always core', async () => {
  const md = '# T\n\n' + Array.from({ length: 8 }, (_, i) => `## S${i}\n\nx\n`).join('\n');
  const zones = sections((await render(md)).html).map(s => /data-zone="(\w+)"/.exec(s)[1]);
  assert.deepEqual(zones, ['topsoil', 'clay', 'stone', 'deep', 'bedrock', 'topsoil', 'clay', 'core']);
  const one = sections((await render('# T\n\n## Only\n\nx\n')).html);
  assert.match(one[0], /data-zone="core"/);
});

test('long titles and headings are truncated in the level', async () => {
  const { html } = await render('# A very long page title that goes on\n\n## A very long heading that keeps going and going\n\nx\n');
  const level = /data-level="([^"]+)"/.exec(html)[1];
  const [a, b] = level.split(' · ');
  assert.ok(a.length <= 24 && a.endsWith('…'));
  assert.ok(b.length <= 28 && b.endsWith('…'));
});

test('relative links between docs become site routes', () => {
  const o = { base: '/blastradius' };
  assert.equal(rewriteHref('action.md', 'why.md', o), '/blastradius/docs/action/');
  assert.equal(rewriteHref('action.md#sarif', 'why.md', o), '/blastradius/docs/action/#sarif');
  assert.equal(rewriteHref('playbooks/ciso.md', 'why.md', o), '/blastradius/docs/playbooks/ciso/');
  assert.equal(rewriteHref('../action.md', 'playbooks/ciso.md', o), '/blastradius/docs/action/');
  assert.equal(rewriteHref('README.md', 'playbooks/ciso.md', o), '/blastradius/docs/playbooks/');
  assert.equal(rewriteHref('ciso.md', 'playbooks/README.md', o), '/blastradius/docs/playbooks/ciso/');
});

test('other relative links go to GitHub; absolute links and anchors stay', () => {
  const o = { base: '/blastradius' };
  assert.equal(rewriteHref('../action.yml', 'why.md', o), 'https://github.com/jondot/blastradius/blob/main/action.yml');
  assert.equal(rewriteHref('../../action.yml', 'playbooks/ciso.md', o), 'https://github.com/jondot/blastradius/blob/main/action.yml');
  assert.equal(rewriteHref('../../../x', 'playbooks/ciso.md', o), '../../../x');
  assert.equal(rewriteHref('../src/ctx.rs#L3', 'why.md', { base: '' }), 'https://github.com/jondot/blastradius/blob/main/src/ctx.rs#L3');
  assert.equal(rewriteHref('../../src/ctx.rs', 'playbooks/x.md', o), 'https://github.com/jondot/blastradius/blob/main/src/ctx.rs');
  assert.equal(rewriteHref('img/', 'why.md', o), 'https://github.com/jondot/blastradius/tree/main/docs/img');
  assert.equal(rewriteHref('https://example.com/a', 'why.md', o), 'https://example.com/a');
  assert.equal(rewriteHref('#top', 'why.md', o), '#top');
});

test('docs/img png uses the site webp when there is one, else the GitHub raw file', () => {
  const o = { base: '/blastradius', hasImage: n => n === 'hero.webp' };
  assert.equal(rewriteSrc('img/hero.png', 'why.md', o), '/blastradius/img/hero.webp');
  assert.equal(rewriteSrc('img/other.png', 'why.md', o), 'https://raw.githubusercontent.com/jondot/blastradius/main/docs/img/other.png');
  assert.equal(rewriteSrc('../img/hero.png', 'playbooks/a.md', o), '/blastradius/img/hero.webp');
});

test('links in rendered markdown are rewritten using the file path', async () => {
  const { html } = await render('# T\n\n## S\n\nSee [the action](../action.md) and [the file](../../action.yml).\n', '/repo/docs/playbooks/ciso.md');
  assert.match(html, /href="\/blastradius\/docs\/action\/"/);
  assert.match(html, /href="https:\/\/github.com\/jondot\/blastradius\/blob\/main\/action.yml"/);
});

test('shell blocks: prompts, output, comments and continuation lines', async () => {
  const md = '# T\n\n## S\n\n```\n# first, check\n$ br demo status   # how fresh\nline one of output\n\n$ br hunt \\\n  --advisory X\nmore output\n```\n';
  const { html } = await render(md);
  assert.equal((html.match(/<span class="p">\$<\/span>/g) || []).length, 2);
  assert.match(html, /<span class="m"># first, check<\/span>/);
  assert.match(html, /<span class="p">\$<\/span> br demo status/);
  assert.match(html, /<span class="m"># how fresh<\/span>/);
  assert.match(html, /<span class="out">line one of output/);
  assert.match(html, /<span class="out">more output/);
  assert.match(html, /br hunt \\\n  --advisory X\n/);
  assert.doesNotMatch(html, /\$ \$/);
  assert.match(html, /<span>shell<\/span><button class="copy" type="button">Copy<\/button>/);
});

test('blocks without prompts: every line is a command, never a double prompt', async () => {
  const items = classify(['br init', '# note', 'br scan \\', '  --stale', 'br hunt   # why']);
  assert.deepEqual(items.map(i => i.type), ['cmd', 'comment', 'cmd', 'cont', 'cmd']);
  const { html } = await render('# T\n\n## S\n\n```\n$ br demo\n```\n');
  assert.equal((html.match(/class="p"/g) || []).length, 1);
  assert.doesNotMatch(html, /\$ \$/);
});

test('indented code and non-shell languages become terminals too', async () => {
  const { html } = await render('# T\n\n## S\n\n    $ br demo\n\n```json\n{"a": 1}\n```\n');
  assert.equal((html.match(/<div class="code">/g) || []).length, 2);
  assert.match(html, /<span>json<\/span>/);
  assert.match(html, /<pre>\{"a": 1\}<\/pre>/);
});

test('a block is shell by its language or its $ prompts, never by guessing from the words', async () => {
  assert.equal(isShell('sh', ['anything']), true);
  assert.equal(isShell('yaml', ['$ br demo']), false);
  assert.equal(isShell('', ['$ br demo', 'output']), true);
  assert.equal(isShell('', ['br hunt x', 'npm:a@1']), false);
  const { html } = await render('# T\n\n## S\n\n```\nnpm:a@1.2.3\n```\n');
  assert.match(html, /<span>text<\/span>/);
  assert.doesNotMatch(html, /class="p"/);
});

test('tables sit in a scrolling wrapper', async () => {
  const { html } = await render('# T\n\n## S\n\n| a | b |\n|---|---|\n| 1 | 2 |\n');
  assert.match(html, /<div class="tbl"><table>\s*<thead>\s*<tr>\s*<th scope="col">a<\/th>/);
});
