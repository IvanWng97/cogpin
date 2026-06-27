// Vendor the REAL engine + glue + diagrams into public/ so the Pyodide playground
// loads the exact ratchet.py that ships (never a stale fork) and the README SVGs
// render on the site. Run automatically by predev/prebuild. A CI `engine-sync`
// check asserts public/ratchet.py byte-matches the repo-root ratchet.py.
import { copyFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const root = (p) => here('../../' + p); // site/scripts → repo root

mkdirSync(here('../public/assets'), { recursive: true });

const files = [
  [root('ratchet.py'), here('../public/ratchet.py')],
  [here('../src/playground/glue.py'), here('../public/glue.py')],
];
for (const [from, to] of files) {
  if (!existsSync(from)) throw new Error('sync-engine: missing source ' + from);
  copyFileSync(from, to);
  console.log('synced', to.split('/site/')[1]);
}

const assetsDir = root('assets');
for (const f of readdirSync(assetsDir)) {
  if (f.endsWith('.svg')) copyFileSync(assetsDir + '/' + f, here('../public/assets/' + f));
}
console.log('synced public/assets/*.svg');
