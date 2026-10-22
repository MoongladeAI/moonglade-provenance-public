// Runs the REAL browser canonicalizeBytes (canonicalize.ts) and the REAL Obsidian
// ProvenanceEngine.canonicalize body (engine.ts) over inputs read from stdin.
// stdin: JSON [{"filename": str, "hex": str}, ...]; stdout: JSON [{"browser": hex, "obsidian": hex}, ...]
// Nothing from the consumer repos is copied: both files are read at run time.
// Usage: node js_profiles.mjs <canonicalize.ts> <engine.ts> < in.json > out.json
import fs from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';

const [tsPath, enginePath] = process.argv.slice(2);

const js = stripTypeScriptTypes(fs.readFileSync(tsPath, 'utf8'));
const mod = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));

// engine.ts imports crypto/fs/path/child_process and enum-bearing ./types, so it cannot be
// loaded as a module here. Extract the body of `static canonicalize(content: string): Buffer`
// verbatim and run it.
const engineSrc = fs.readFileSync(enginePath, 'utf8');
const m = engineSrc.match(/static canonicalize\(content: string\): Buffer \{([\s\S]*?)\n  \}/);
if (!m) throw new Error('ProvenanceEngine.canonicalize not found');
const obsidianCanon = new Function('content', 'Buffer', m[1]);

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const out = input.map(({ filename, hex }) => {
  const raw = Buffer.from(hex, 'hex');
  const browser = Buffer.from(mod.canonicalizeBytes(filename, new Uint8Array(raw))).toString('hex');
  // Obsidian hands engine.ts a string; the UTF-8 decode is Node's `utf8` (as fs.readFileSync(p,'utf8')).
  const obsidian = Buffer.from(obsidianCanon(raw.toString('utf8'), Buffer)).toString('hex');
  return { browser, obsidian };
});
process.stdout.write(JSON.stringify(out));
