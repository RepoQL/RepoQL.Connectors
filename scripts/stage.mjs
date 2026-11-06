// Stages a connector for an rql that does not yet read a manifest's package block: copies the connector's folder to
// another folder, without the package block, and prints the block as JSON so it can be passed as flags.
//
//   node scripts/stage.mjs connectors/cve /tmp/cve
//   {"id":"RepoQL.Connectors.Cve","version":"1.0.0","authors":"RepoQL"}
//
// Delete this script, and call rql on the connector's own folder, once the released rql reads the package block.
import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [from, to] = process.argv.slice(2);
if (!from || !to) {
  console.error('Usage: node scripts/stage.mjs <connector folder> <staged folder>');
  process.exit(2);
}

const lines = readFileSync(join(from, 'manifest.yaml'), 'utf8').split('\n');
const start = lines.findIndex(line => line === 'package:');
if (start < 0) {
  console.error(`${from}/manifest.yaml has no package block: add package: with id, version and authors.`);
  process.exit(1);
}
let end = start + 1;
const identity = {};
for (; end < lines.length && /^\s+\S/.test(lines[end]); end++) {
  const field = /^\s+(id|version|authors):\s*(\S.*?)\s*$/.exec(lines[end]);
  if (!field) {
    console.error(`${from}/manifest.yaml: the package block holds '${lines[end].trim()}'; it takes id, version and authors.`);
    process.exit(1);
  }
  identity[field[1]] = field[2];
}
for (const field of ['id', 'version', 'authors']) {
  if (!identity[field]) {
    console.error(`${from}/manifest.yaml: the package block has no ${field}.`);
    process.exit(1);
  }
}

cpSync(from, to, { recursive: true });
// The comment lines just above the block describe it, so they go with it.
let first = start;
while (first > 0 && lines[first - 1].startsWith('#')) first--;
writeFileSync(join(to, 'manifest.yaml'), [...lines.slice(0, first), ...lines.slice(end)].join('\n'));
console.log(JSON.stringify(identity));
