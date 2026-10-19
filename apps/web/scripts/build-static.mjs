// Build in isolation: dev proxies and the running Next.js watcher remain untouched.
import { cp, mkdir, mkdtemp, rename, rm, symlink } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
await mkdir(join(root, ".tally-export"), { recursive: true });
const stage = await mkdtemp(join(root, ".tally-export/build-"));
try {
  for (const name of ["app", "components", "lib", "public", "package.json", "tsconfig.json", "next.config.ts", "postcss.config.mjs"]) {
    await cp(join(root, name), join(stage, name), {
      recursive: true,
      filter: path => path !== join(root, "app/api"),
    });
  }
  await symlink(join(root, "node_modules"), join(stage, "node_modules"), "dir");
  const result = spawnSync(process.execPath, [join(root, "node_modules/next/dist/bin/next"), "build", "--webpack"], {
    cwd: stage, stdio: "inherit",
    env: { ...process.env, TALLY_STATIC_EXPORT: "1", NEXT_TELEMETRY_DISABLED: "1", NEXT_PUBLIC_TALLY_API_URL: "" },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Static UI build failed (${result.status})`);
  await rm(join(root, "out"), { recursive: true, force: true });
  await rename(join(stage, "out"), join(root, "out"));
} finally {
  await rm(stage, { recursive: true, force: true });
}
