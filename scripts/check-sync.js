#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function walk(dir, base = dir) {
  const entries = [];
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      entries.push(...walk(full, base));
    } else if (stat.isFile()) {
      entries.push(path.relative(base, full));
    }
  }
  return entries;
}

function hashFile(p) {
  const data = fs.readFileSync(p);
  return crypto.createHash('sha256').update(data).digest('hex');
}

function main() {
  const repoRoot = process.cwd();
  const publicDir = path.join(repoRoot, 'public');
  const wrapperBase = path.join(repoRoot, 'android-wrapper', 'www', 'app');

  if (!fs.existsSync(publicDir)) {
    console.error('public/ directory not found — nothing to check.');
    process.exit(0);
  }

  const publicFiles = walk(publicDir);
  const diffs = [];

  for (const rel of publicFiles) {
    const pubPath = path.join(publicDir, rel);
    const wrapPath = path.join(wrapperBase, rel);

    if (!fs.existsSync(wrapPath)) {
      diffs.push({ type: 'missing', file: rel });
      continue;
    }

    const pubHash = hashFile(pubPath);
    const wrapHash = hashFile(wrapPath);
    if (pubHash !== wrapHash) {
      diffs.push({ type: 'mismatch', file: rel });
    }
  }

  if (diffs.length > 0) {
    console.error('\nSync check failed — differences found between public/ and android-wrapper/www/app/:\n');
    for (const d of diffs) {
      console.error(` - ${d.type.toUpperCase()}: ${d.file}`);
    }
    console.error('\nIf these changes are expected, sync the files into the wrapper or update the workflow to accept the differences.');
    process.exit(1);
  }

  console.log('Sync check passed: all files in public/ are present and identical in android-wrapper/www/app/');
}

main();
