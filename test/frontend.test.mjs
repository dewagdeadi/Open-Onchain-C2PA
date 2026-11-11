// The browser scripts must at least parse: a syntax error here takes the whole site down.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";

for (const f of ["public/app.js", "public/js/c2pa-reader.mjs"]) {
  test(`${f} parses as a module`, () => {
    const copy = `/tmp/syntax-check-${f.replace(/\W/g, "_")}.mjs`;
    fs.copyFileSync(f, copy);
    assert.doesNotThrow(() => execFileSync(process.execPath, ["--check", copy], { stdio: "pipe" }));
  });
}

test("index.html references only files that exist", () => {
  const html = fs.readFileSync("public/index.html", "utf8");
  for (const [, src] of html.matchAll(/(?:src|href)="\/([^"#]+)"/g)) assert.ok(fs.existsSync(`public/${src}`), src);
});
