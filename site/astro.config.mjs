// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Project page → https://ivanwng97.github.io/ratchet/. If a custom domain is added,
// set base to '/' and add a CNAME. The playground fetches the engine via
// import.meta.env.BASE_URL so it resolves under the /ratchet prefix.
export default defineConfig({
  site: 'https://ivanwng97.github.io',
  base: '/ratchet',
  trailingSlash: 'ignore',
  integrations: [
    starlight({
      title: 'ratchet',
      description:
        'A Definition-of-Done gate for AI coding agents. Blocks the corner-cuts an agent takes to look done — over facts it can never fake.',
      logo: { src: './src/assets/logo.svg', alt: 'ratchet' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/IvanWng97/ratchet' }],
      customCss: ['./src/styles/custom.css'],
      lastUpdated: true,
      sidebar: [
        {
          label: 'Tutorial',
          items: [
            { label: 'What it catches', slug: 'what-it-catches' },
            { label: 'Try it live', slug: 'try-it' },
            { label: 'Install', slug: 'install' },
            { label: 'Recipes', slug: 'recipes' },
            { label: 'Concepts', slug: 'concepts' },
          ],
        },
      ],
    }),
  ],
});
