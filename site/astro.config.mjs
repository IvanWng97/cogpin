// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Project page → https://ivanwng97.github.io/ratchet/. If a custom domain is added,
// set base to '/' and add a CNAME. The playground fetches the engine via
// import.meta.env.BASE_URL so it resolves under the /ratchet prefix.
export default defineConfig({
  site: 'https://ivanwng97.github.io',
  // Trailing slash is load-bearing: import.meta.env.BASE_URL is this value verbatim,
  // and the .mdx/Playground links concatenate `${base}path` — without it you get
  // `/ratchetwhat-it-catches` (missing the separator). Keep the slash.
  base: '/ratchet/',
  trailingSlash: 'ignore',
  integrations: [
    starlight({
      title: 'ratchet',
      description:
        'A Definition-of-Done gate for AI coding agents. Blocks the corner-cuts an agent takes to look done — over facts it can never fake.',
      logo: { src: './src/assets/logo.svg', alt: 'ratchet' },
      // Syntax highlighting for fenced code: a crisp dark/light pair that flips
      // with the theme, rounded to match the site's cards.
      expressiveCode: {
        themes: ['github-dark-default', 'github-light-default'],
        styleOverrides: { borderRadius: '0.6rem', frames: { shadowColor: 'transparent' } },
      },
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
