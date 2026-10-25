// A rehype plugin that gives any markdown the look of the game: each H2 becomes a zone with a window,
// fenced and indented code become the terminal with a Copy button, tables scroll sideways inside a
// wrapper, and relative links are pointed at site routes (or at GitHub for files the site does not have).
//
// It also takes the page title (the H1) and the lede (the first paragraph) out of the body and leaves
// them, with the list of H2s, in file.data.astro.frontmatter for the page layout to use.
import GithubSlugger from 'github-slugger';
import { toString } from 'hast-util-to-string';
import { toHtml } from 'hast-util-to-html';
import path from 'node:path';

/** Zones for the sections in the middle of a page; the last section is always `core`. */
export const ZONES = ['topsoil', 'clay', 'stone', 'deep', 'bedrock'];
export const LAST_ZONE = 'core';

const SHELL_LANGS = new Set(['sh', 'bash', 'shell', 'zsh', 'fish', 'console', 'shellsession', 'terminal']);

const h = (tagName, properties = {}, children = []) => ({ type: 'element', tagName, properties, children });
const text = value => ({ type: 'text', value });

// ---------- shell blocks ----------

/** Split `cmd   # note` into the command, the gap and the comment. A `#` inside quotes is not a comment. */
export function splitComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) { if (c === quote) quote = null; else if (c === '\\' && quote === '"') i++; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === '#' && i > 0 && /\s/.test(line[i - 1]) && (i + 1 === line.length || /\s/.test(line[i + 1]))) {
      const code = line.slice(0, i).replace(/\s+$/, '');
      return { code, gap: line.slice(code.length, i), comment: line.slice(i) };
    }
  }
  return { code: line, gap: '', comment: '' };
}

const continues = code => /\\\s*$/.test(code);

/** Is this block a shell session? A shell language says so; with no language, only a `$ ` prompt line does. */
export function isShell(lang, lines) {
  if (lang) return SHELL_LANGS.has(lang.toLowerCase());
  return lines.some(l => l.startsWith('$ '));
}

/**
 * Classify the lines of a shell block.
 * - A line that starts with `$ ` is a command; everything after it is output until the next `$ ` line.
 * - In a block with no `$ ` line, every line that is not blank and not a `#` comment is a command.
 * - A command that ends with a backslash continues on the next line, which is part of the command.
 * Each item is {type: 'cmd'|'cont'|'out'|'comment'|'blank', code, gap, comment}.
 */
export function classify(lines) {
  const hasPrompt = lines.some(l => l.startsWith('$ '));
  const items = [];
  let cont = false, state = 'idle';
  for (const line of lines) {
    if (cont) {
      const s = splitComment(line);
      items.push({ type: 'cont', ...s });
      cont = continues(s.code);
      continue;
    }
    if (!line.trim()) { items.push({ type: 'blank', code: line, gap: '', comment: '' }); continue; }
    if (hasPrompt) {
      if (line.startsWith('$ ')) {
        const s = splitComment(line.slice(2));
        items.push({ type: 'cmd', ...s });
        cont = continues(s.code); state = 'cmd';
      } else if (state === 'idle' && line.trim().startsWith('#')) {
        items.push({ type: 'comment', code: line, gap: '', comment: '' });
      } else {
        items.push({ type: 'out', code: line, gap: '', comment: '' }); state = 'out';
      }
    } else if (line.trim().startsWith('#')) {
      items.push({ type: 'comment', code: line, gap: '', comment: '' });
    } else {
      const s = splitComment(line.replace(/^\s+/, ''));
      items.push({ type: 'cmd', ...s });
      cont = continues(s.code);
    }
  }
  return items;
}

function shellNodes(lines) {
  const items = classify(lines);
  const nodes = [];
  const nl = k => (k < items.length - 1 ? '\n' : '');
  const m = code => h('span', { className: ['m'] }, [text(code)]);
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    if (it.type === 'out') {
      // One span for the whole run of output, blank lines inside it included.
      let j = i, last = i;
      while (j < items.length && (items[j].type === 'out' || items[j].type === 'blank')) { if (items[j].type === 'out') last = j; j++; }
      nodes.push(h('span', { className: ['out'] }, [text(items.slice(i, last + 1).map(x => x.code).join('\n'))]));
      if (last < items.length - 1) nodes.push(text('\n'));
      i = last;
    } else if (it.type === 'cmd' || it.type === 'cont') {
      if (it.type === 'cmd') nodes.push(h('span', { className: ['p'] }, [text('$')]), text(' ' + it.code));
      else nodes.push(text(it.code));
      if (it.comment) nodes.push(text(it.gap), m(it.comment));
      if (nl(i)) nodes.push(text('\n'));
    } else if (it.type === 'comment') {
      nodes.push(m(it.code));
      if (nl(i)) nodes.push(text('\n'));
    } else {
      nodes.push(text(it.code + nl(i)));
    }
  }
  return nodes;
}

export function codeBlock(lang, source) {
  const lines = source.replace(/\n+$/, '').split('\n');
  const shell = isShell(lang, lines);
  const label = shell ? 'shell' : lang || 'text';
  const body = shell ? shellNodes(lines) : [text(lines.join('\n'))];
  return h('div', { className: ['code'] }, [
    h('div', { className: ['bar'] }, [h('span', {}, [text(label)]), h('button', { className: ['copy'], type: 'button' }, [text('Copy')])]),
    h('pre', {}, body),
  ]);
}

// ---------- links ----------

const SCHEME = /^[a-z][a-z0-9+.-]*:/i;

/** Where a relative link in docs/<sourcePath> should go. Anything with a scheme, or a bare anchor, is left alone. */
export function rewriteHref(href, sourcePath, { base = '', repo = 'jondot/blastradius', branch = 'main' } = {}) {
  if (!href || SCHEME.test(href) || href.startsWith('//') || href.startsWith('#')) return href;
  const hashAt = href.indexOf('#');
  const hash = hashAt >= 0 ? href.slice(hashAt) : '';
  const rel = hashAt >= 0 ? href.slice(0, hashAt) : href;
  const q = rel.indexOf('?');
  const target = q >= 0 ? rel.slice(0, q) : rel;
  if (!target) return href;
  const dir = path.posix.dirname(sourcePath);
  const joined = target.startsWith('/') ? target.slice(1) : path.posix.join('docs', dir, target);
  const resolved = path.posix.normalize(joined);
  if (resolved.startsWith('..')) return href;
  const clean = resolved.replace(/\/+$/, '');
  if (clean === 'docs') return `${base}/docs/${hash}`;
  if (clean === 'docs/playbooks') return `${base}/docs/playbooks/${hash}`;
  const m = /^docs\/(playbooks\/)?([^/]+)\.md$/i.exec(clean);
  if (m) {
    const name = m[2].toLowerCase();
    if (m[1]) return name === 'readme' ? `${base}/docs/playbooks/${hash}` : `${base}/docs/playbooks/${name}/${hash}`;
    if (name !== 'readme') return `${base}/docs/${name}/${hash}`;
  }
  const kind = target.endsWith('/') ? 'tree' : 'blob';
  return `https://github.com/${repo}/${kind}/${branch}/${clean}${hash}`;
}

/** Images under docs/img/NAME.png use the site's img/NAME.webp when there is one, else the GitHub raw file. */
export function rewriteSrc(src, sourcePath, { base = '', repo = 'jondot/blastradius', branch = 'main', hasImage = () => false } = {}) {
  if (!src || SCHEME.test(src) || src.startsWith('//')) return src;
  const resolved = path.posix.normalize(src.startsWith('/') ? src.slice(1) : path.posix.join('docs', path.posix.dirname(sourcePath), src));
  const m = /^docs\/img\/([^/]+)\.[a-z0-9]+$/i.exec(resolved);
  if (m && hasImage(`${m[1]}.webp`)) return `${base}/img/${m[1]}.webp`;
  return `https://raw.githubusercontent.com/${repo}/${branch}/${resolved}`;
}

// ---------- the plugin ----------

const truncate = (s, n) => (s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s);
const blank = n => n.type === 'text' && !n.value.trim();
const classOf = n => (Array.isArray(n.properties?.className) ? n.properties.className : String(n.properties?.className || '').split(' '));

export default function rehypeGame(options = {}) {
  const { base = '', repo = 'jondot/blastradius', branch = 'main', hasImage, sourceOf } = options;

  return function transformer(tree, file) {
    const fullPath = String(file.path || file.history?.[0] || '').split(path.sep).join('/');
    const sourcePath = sourceOf ? sourceOf(fullPath) : (fullPath.includes('/docs/') ? fullPath.slice(fullPath.lastIndexOf('/docs/') + 6) : path.posix.basename(fullPath));
    const slugger = new GithubSlugger();

    // 1. Links, images, emphasis, tables and code, anywhere in the tree.
    const transform = node => {
      if (!node.children) return node;
      node.children = node.children.map(child => {
        if (child.type !== 'element') return child;
        if (child.tagName === 'pre') {
          const code = child.children.find(c => c.type === 'element' && c.tagName === 'code');
          if (code) {
            const lang = classOf(code).map(c => /^language-(.+)$/.exec(c)?.[1]).find(Boolean) || '';
            return codeBlock(lang, toString(code));
          }
        }
        if (child.tagName === 'table') {
          transform(child);
          for (const th of find(child, 'th')) th.properties = { ...th.properties, scope: 'col' };
          return h('div', { className: ['tbl'] }, [child]);
        }
        if (child.tagName === 'a' && typeof child.properties?.href === 'string') child.properties.href = rewriteHref(child.properties.href, sourcePath, { base, repo, branch });
        if (child.tagName === 'img' && typeof child.properties?.src === 'string') {
          child.properties.src = rewriteSrc(child.properties.src, sourcePath, { base, repo, branch, hasImage });
          child.properties.loading = 'lazy';
        }
        if (child.tagName === 'strong') child.tagName = 'b';
        return transform(child);
      });
      return node;
    };
    transform(tree);

    // 2. Title and lede come out of the body.
    const kids = tree.children;
    let title = '', lede = null;
    const h1 = kids.findIndex(n => n.type === 'element' && n.tagName === 'h1');
    if (h1 >= 0) {
      title = toString(kids[h1]).trim();
      slugger.slug(title);
      let p = h1 + 1;
      while (kids[p] && blank(kids[p])) p++;
      if (kids[p]?.type === 'element' && kids[p].tagName === 'p') { lede = kids[p]; kids.splice(h1, p - h1 + 1); } else kids.splice(h1, 1);
    }
    title ||= sourcePath.replace(/\.md$/i, '');

    // 3. Ids on the smaller headings, then split at each H2.
    const groups = [{ h2: null, body: [] }];
    for (const n of kids) {
      if (blank(n)) continue;
      if (n.type === 'element' && n.tagName === 'h2') { groups.push({ h2: n, body: [] }); continue; }
      if (n.type === 'element' && /^h[3-6]$/.test(n.tagName)) { n.properties = { ...n.properties, id: slugger.slug(toString(n)) }; }
      groups.at(-1).body.push(n);
    }
    if (!groups[0].body.length) groups.shift();

    const toc = [];
    const upperTitle = truncate(title.toUpperCase(), 24);
    const sections = groups.map((g, i) => {
      const last = i === groups.length - 1;
      const zone = last ? LAST_ZONE : ZONES[i % ZONES.length];
      if (!g.h2) {
        return h('section', { className: ['zone'], dataZone: zone, dataLevel: `${upperTitle} · INTRO` }, [
          h('div', { className: ['win', 'dim'] }, [h('p', { className: ['tag'] }, [text('Overview')]), ...g.body]),
        ]);
      }
      const label = toString(g.h2).trim();
      const id = slugger.slug(label);
      toc.push({ id, text: label });
      const n = toc.length;
      return h('section', { id, className: ['zone'], dataZone: zone, dataLevel: `${upperTitle} · ${truncate(label.toUpperCase(), 28)}` }, [
        h('div', { className: ['win', 'dim'] }, [
          h('p', { className: ['tag'] }, [text(`Part ${n}`)]),
          // The heading's own id is not the section's: Astro gives every heading without one the slug, which would repeat it.
          h('h2', { id: `${id}-heading` }, [...g.h2.children, text(' '), h('a', { className: ['anchor'], href: `#${id}`, ariaLabel: `Link to ${label}` }, [text('#')])]),
          ...g.body,
        ]),
      ]);
    });
    tree.children = sections;

    file.data.astro ??= {};
    file.data.astro.frontmatter ??= {};
    Object.assign(file.data.astro.frontmatter, {
      title,
      ledeHtml: lede ? toHtml(lede.children) : '',
      ledeText: lede ? toString(lede).replace(/\s+/g, ' ').trim() : '',
      toc,
    });
  };
}

function find(node, tagName, out = []) {
  for (const c of node.children || []) { if (c.type === 'element') { if (c.tagName === tagName) out.push(c); find(c, tagName, out); } }
  return out;
}
