import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import rehypeGame from './src/lib/game-markdown.mjs';

const base = '/blastradius';
const publicImg = name => existsSync(fileURLToPath(new URL(`./public/img/${name}`, import.meta.url)));

export default defineConfig({
  site: 'https://jondot.github.io',
  base,
  trailingSlash: 'always',
  output: 'static',
  integrations: [sitemap()],
  markdown: {
    // The design has its own code styling, and straight quotes and dashes are what the repo's markdown says.
    syntaxHighlight: false,
    smartypants: false,
    rehypePlugins: [[rehypeGame, { base, hasImage: publicImg }]],
  },
});
