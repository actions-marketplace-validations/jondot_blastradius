export const SITE = 'https://jondot.github.io';
export const GITHUB = 'https://github.com/jondot/blastradius';

/** An internal URL under the site's base, always with a trailing slash for pages. */
export function url(path = '/'): string {
  const base = import.meta.env.BASE_URL.replace(/\/+$/, '');
  return base + (path.startsWith('/') ? path : '/' + path);
}

/** An absolute URL, for Open Graph, the sitemap and llms.txt. */
export function absolute(path = '/'): string {
  return SITE + url(path);
}

/** One line from a paragraph: its first sentence, cut at a word if it is still long. */
export function oneLine(text: string, max = 200): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  const m = /^(.+?[.!?])(\s|$)/.exec(flat);
  const sentence = m ? m[1] : flat;
  if (sentence.length <= max) return sentence;
  return sentence.slice(0, max - 1).replace(/\s+\S*$/, '') + '…';
}
