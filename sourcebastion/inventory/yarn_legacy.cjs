"use strict";
// Trusted standalone upstream grammar; no project module search or Yarn runtime.
const parse = require("./vendor/yarn-syml/syml.js").parse;
const LIMIT = 64 * 1024 * 1024;
let bytes = 0;
const chunks = [];
process.stdin.on("data", chunk => {
  bytes += chunk.length;
  if (bytes > 16 * 1024 * 1024) {
    process.stderr.write("yarn-input-budget-exceeded\n");
    process.exit(2);
  }
  chunks.push(chunk);
});
process.stdin.on("end", () => {
  try {
    const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (request.schema_version !== "sourcebastion.yarn-legacy/1" ||
        Object.keys(request).sort().join(",") !== "schema_version,source" ||
        typeof request.source !== "string" || Buffer.byteLength(request.source) > 2 * 1024 * 1024)
      throw Error("invalid-input");
    // The unmodified generated grammar uses Object.assign for every mapping.
    // Narrow that operation while parsing to reject overwritten/unsafe keys.
    // Restore it before validation and serialization. No customer code runs.
    const assign = Object.assign;
    let document;
    try {
      Object.assign = function(target, ...sources) {
        const keys = new Set(Object.keys(target));
        for (const source of sources) for (const key of Object.keys(source)) {
          if (keys.has(key) || ["__proto__", "constructor", "prototype"].includes(key))
            throw Error("duplicate-or-unsafe-key");
          keys.add(key);
        }
        return assign(target, ...sources);
      };
      document = parse(request.source.endsWith("\n") ? request.source : request.source + "\n");
    } finally {
      Object.assign = assign;
    }
    // Group only identities shared by the upstream parser for one source
    // entry's alias keys. Equal record contents never merge separate entries.
    const groups = new Map();
    const entries = [];
    for (const [key, record] of Object.entries(document)) {
      if (record === null || typeof record !== "object" || Array.isArray(record))
        throw Error("unsupported-entry");
      let entry = groups.get(record);
      if (!entry) {
        entry = {keys: [], record};
        groups.set(record, entry);
        entries.push(entry);
      }
      entry.keys.push(key);
    }
    let reserved = 128, nodes = 0;
    const pending = [[entries, 0]];
    while (pending.length) {
      const [value, depth] = pending.pop();
      if (++nodes > 2000000 || depth > 32) throw Error("output-budget");
      reserved += 24;
      if (typeof value === "string") {
        if (value.length > 2 * 1024 * 1024) throw Error("output-budget");
        for (const character of value) {
          const code = character.codePointAt(0);
          if (code >= 0xD800 && code <= 0xDFFF) throw Error("invalid-unicode");
        }
        reserved += value.length * 12;
      } else if (value !== null && typeof value === "object") {
        for (const [key, child] of Object.entries(value)) {
          for (const character of key) {
            const code = character.codePointAt(0);
            if (code >= 0xD800 && code <= 0xDFFF) throw Error("invalid-unicode");
          }
          reserved += 12 * key.length + 4;
          if (reserved > LIMIT || pending.length >= 2000000) throw Error("output-budget");
          pending.push([child, depth + 1]);
        }
      } else if (value !== null && typeof value !== "boolean") {
        throw Error("unsupported-output");
      }
      if (reserved > LIMIT) throw Error("output-budget");
    }
    const response = JSON.stringify({schema_version:"sourcebastion.yarn-legacy-result/1", entries});
    if (Buffer.byteLength(response) > LIMIT) throw Error("output-budget");
    process.stdout.write(response);
  } catch (_) {
    process.stderr.write("yarn-legacy-parse-refused\n");
    process.exitCode = 2;
  }
});
