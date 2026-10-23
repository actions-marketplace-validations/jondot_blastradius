import type { APIRoute } from 'astro';
import { allPages, MANUAL_DESCRIPTION } from '../lib/docs';
import { absolute, GITHUB, SITE, oneLine } from '../lib/site';

// A plain-text map of the site for an agent: every page's title, URL and one line about it.
export const GET: APIRoute = async () => {
  const pages = await allPages();
  const line = (title: string, href: string, about: string) => (about && about !== title ? `- [${title}](${href}): ${about}` : `- [${title}](${href})`);
  const body = [
    '# blastradius',
    '',
    '> When something you depend on goes bad, br tells you everywhere it is: repos, CI runs, caches, images and laptops, with the owner of each. Read-only.',
    '',
    `Source: ${GITHUB}`,
    '',
    '## Pages',
    '',
    line('blastradius', absolute('/'), 'What br does, with real output on a sample org, and how to install it.'),
    ...pages.map(p => line(p.title, absolute(new URL(p.href, SITE).pathname.replace(/^\/blastradius/, '')), oneLine(p.key === 'manual' ? MANUAL_DESCRIPTION : p.description))),
    '',
  ].join('\n');
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
