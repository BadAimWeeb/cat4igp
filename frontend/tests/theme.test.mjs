import assert from "node:assert/strict";
import { preferredMode } from "../src/theme/index.ts";

for (const dark of [false, true]) {
  for (const saved of [null, "invalid", "light", "dark"]) {
    assert.equal(
      preferredMode({ getItem: () => saved }, dark),
      saved === "light" || saved === "dark" ? saved : dark ? "dark" : "light",
    );
  }
  assert.equal(
    preferredMode(
      {
        getItem() {
          throw Error("denied");
        },
      },
      dark,
    ),
    dark ? "dark" : "light",
  );
}
console.log(
  "PASS theme preference: explicit, system, invalid and denied storage",
);
