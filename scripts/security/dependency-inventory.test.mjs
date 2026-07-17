import assert from "node:assert/strict";
import test from "node:test";

import { createDependencyInventory } from "./dependency-inventory.mjs";

const runtime = {
  MIT: [{ name: "runtime", versions: ["1.0.0"], license: "MIT", paths: ["/private/path"] }],
};
const all = {
  ...runtime,
  "Apache-2.0": [
    { name: "build-tool", versions: ["2.0.0"], license: "Apache-2.0", paths: ["/private/path"] },
  ],
};

test("creates a sorted path-free production/development inventory", () => {
  assert.deepEqual(createDependencyInventory(all, runtime), [
    { name: "build-tool", version: "2.0.0", license: "Apache-2.0", scope: "development" },
    { name: "runtime", version: "1.0.0", license: "MIT", scope: "production" },
  ]);
});

test("rejects missing license metadata", () => {
  assert.throws(
    () =>
      createDependencyInventory(
        { UNKNOWN: [{ name: "mystery", versions: ["1.0.0"], paths: [] }] },
        {},
      ),
    /no usable license metadata/,
  );
});
