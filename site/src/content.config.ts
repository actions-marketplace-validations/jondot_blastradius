import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';

// The generated pages come from the repo's own markdown, so the docs cannot drift from the tool.
// Only these patterns are read; anything else under docs/ (briefs, img) is never a page.
const docs = defineCollection({
  loader: glob({ pattern: ['*.md', 'playbooks/*.md'], base: '../docs' }),
});

export const collections = { docs };
