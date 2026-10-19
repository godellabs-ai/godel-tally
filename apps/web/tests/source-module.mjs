import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInThisContext } from "node:vm";
import ts from "typescript";

// Load app TypeScript (and its extensionless relative imports) without starting Next.js.
const require = createRequire(import.meta.url), cache = new Map();
export function sourceModule(name) {
  const path = resolve(dirname(fileURLToPath(import.meta.url)), "..", name);
  if (cache.has(path)) return cache.get(path).exports;
  const loaded = { exports: {} }; cache.set(path, loaded);
  const code = ts.transpileModule(readFileSync(path, "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  runInThisContext(`(function(require,module,exports){${code}\n})`)(specifier => specifier.startsWith(".") ? sourceModule(resolve(dirname(path), `${specifier}.ts`)) : require(specifier), loaded, loaded.exports);
  return loaded.exports;
}
