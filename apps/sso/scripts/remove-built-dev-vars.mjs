import { readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

async function removeDevVars(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }

  await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return removeDevVars(path);
      if (entry.name === ".dev.vars" || entry.name.startsWith(".dev.vars.")) {
        await rm(path, { force: true });
      }
    }),
  );
}

await removeDevVars(fileURLToPath(new URL("../dist", import.meta.url)));
