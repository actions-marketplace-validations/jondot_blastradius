import { getCollection, render } from 'astro:content';
import { oneLine, url, GITHUB } from './site';

export interface DocPage {
  /** 'manual' for /docs/, else the route below /docs/ without slashes at the ends ('why', 'playbooks', 'playbooks/ciso'). */
  key: string;
  href: string;
  title: string;
  /** The short name used in the sidebar and in prev/next. */
  nav: string;
  description: string;
  kind: 'manual' | 'guide' | 'playbooks' | 'playbook';
  /** The markdown file in the repo, for the edit link. */
  source?: string;
  entry?: Awaited<ReturnType<typeof getCollection<'docs'>>>[number];
}

export const MANUAL_DESCRIPTION =
  'How to install and use br (blastradius): build the index, hunt, indicators, laptops, CI, exit codes and evidence.';

const GUIDE_NAMES: Record<string, string> = { why: 'Why br', action: 'CI and the Action', mcp: 'MCP for agents' };
const GUIDE_ORDER = ['why', 'action', 'mcp'];
// The order of the table in docs/playbooks/README.md; a playbook added later follows, in name order.
const PLAYBOOK_ORDER = ['appsec-oncall', 'platform-eng', 'team-lead', 'ciso', 'auditor', 'ir-consultant', 'soc-analyst', 'startup-cto', 'claimcheck'];

const rank = (order: string[], name: string) => (order.includes(name) ? order.indexOf(name) : order.length);
const byOrder = (order: string[]) => (a: string, b: string) => rank(order, a) - rank(order, b) || a.localeCompare(b);

/** The route of a collection entry: 'why', 'playbooks' (its README) or 'playbooks/ciso'. */
export function routeOf(id: string): string {
  const clean = id.replace(/\.md$/i, '').toLowerCase();
  return clean === 'playbooks/readme' ? 'playbooks' : clean;
}

export interface Rendered {
  page: DocPage;
  Content: any;
  title: string;
  ledeHtml: string;
  ledeText: string;
  toc: { id: string; text: string }[];
}

let cache: Promise<Rendered[]> | undefined;

/** Every generated page, rendered once: the guides, then the playbooks index, then each playbook. */
export function loadDocs(): Promise<Rendered[]> {
  cache ??= (async () => {
    const entries = await getCollection('docs');
    const out: Rendered[] = [];
    for (const entry of entries) {
      const key = routeOf(entry.id);
      const { Content, remarkPluginFrontmatter: fm } = await render(entry);
      const kind: DocPage['kind'] = key === 'playbooks' ? 'playbooks' : key.startsWith('playbooks/') ? 'playbook' : 'guide';
      const name = key.split('/').pop()!;
      const title = String(fm.title);
      out.push({
        page: {
          key, href: url(`/docs/${key}/`), title, entry, kind,
          nav: kind === 'guide' ? GUIDE_NAMES[name] ?? title : kind === 'playbooks' ? 'Playbooks' : title,
          description: oneLine(String(fm.ledeText || title)),
          source: String(entry.filePath ?? `docs/${entry.id}.md`).replace(/^(\.\.\/)+/, ''),
        },
        Content, title, ledeHtml: String(fm.ledeHtml), ledeText: String(fm.ledeText), toc: fm.toc,
      });
    }
    const group = (r: Rendered) => ({ guide: 0, playbooks: 1, playbook: 2, manual: -1 })[r.page.kind];
    out.sort((a, b) => group(a) - group(b) || byOrder(a.page.kind === 'guide' ? GUIDE_ORDER : PLAYBOOK_ORDER)(a.page.key.split('/').pop()!, b.page.key.split('/').pop()!));
    return out;
  })();
  return cache;
}

export const MANUAL: DocPage = {
  key: 'manual', href: url('/docs/'), title: 'Using br', nav: 'Using br', description: MANUAL_DESCRIPTION, kind: 'manual',
  source: undefined,
};

/** All pages in reading order, the manual first. */
export async function allPages(): Promise<DocPage[]> {
  return [MANUAL, ...(await loadDocs()).map(r => r.page)];
}

export const editUrl = (source: string) => `${GITHUB}/edit/main/${source}`;

/** The sidebar groups of the manual page. Each link is an anchor on /docs/. */
export const MANUAL_GROUPS: { label: string; links: [string, string][] }[] = [
  { label: 'Get started', links: [['install', 'Install'], ['try', 'Try it with no token'], ['index', 'Build the index'], ['hunt', 'Your first hunt']] },
  { label: 'Use', links: [['indicators', 'Indicators'], ['incidents', 'Runtimes, certs, secrets'], ['after', 'After the hunt'], ['laptops', 'Laptops and hosts'], ['ci', 'CI and agents'], ['commands', 'All commands']] },
  { label: 'Trust', links: [['exit', 'Answers and exit codes'], ['reads', 'What it reads'], ['evidence', 'Evidence']] },
  { label: 'More', links: [['playbooks', 'Playbooks by role']] },
];
