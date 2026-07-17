import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { runRedactedCommand } from "./secret-scan.mjs";

test("captures scanner stdout and stderr on failure", () => {
  const token = ["xoxb", "019283746501928374650192"].join("-");
  assert.throws(
    () =>
      runRedactedCommand(
        process.execPath,
        [
          "--eval",
          "process.stdout.write(process.env.SCANNER_TEST_TOKEN); process.stderr.write(process.env.SCANNER_TEST_TOKEN); process.exit(1)",
        ],
        {
          environment: { ...process.env, SCANNER_TEST_TOKEN: token },
          label: "test scanner",
        },
      ),
    (error) => {
      assert.equal(error.message, "test scanner reported findings; subprocess output is redacted");
      assert.ok(!error.message.includes(token));
      return true;
    },
  );
});

test("keeps scanner output out of combined parent stdout and stderr", () => {
  const token = ["xoxb", "918273645091827364509182"].join("-");
  const moduleUrl = new URL("./secret-scan.mjs", import.meta.url).href;
  const program = `
    import { runRedactedCommand } from ${JSON.stringify(moduleUrl)};
    try {
      runRedactedCommand(
        process.execPath,
        ["--eval", "process.stdout.write(process.env.SCANNER_TEST_TOKEN); process.stderr.write(process.env.SCANNER_TEST_TOKEN); process.exit(1)"],
        { environment: process.env, label: "test scanner" },
      );
    } catch (error) {
      console.log(error.message);
      console.error(error.message);
      process.exitCode = 1;
    }
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", program], {
    encoding: "utf8",
    env: { ...process.env, SCANNER_TEST_TOKEN: token },
  });
  assert.equal(result.status, 1);
  const combined = `${result.stdout}${result.stderr}`;
  assert.match(combined, /subprocess output is redacted/);
  assert.ok(!combined.includes(token));
});
