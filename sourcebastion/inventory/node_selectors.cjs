'use strict'

// Trusted parser entry point. Customer bytes are strings in JSON, never module
// paths, JavaScript source, package scripts, configuration or install requests.
const fs = require('node:fs')
const semver = require('./vendor/npm-semver/index.js')
const MAX_BYTES = 64 * 1024 * 1024

function execute () {
  let size = 0
  const chunks = []
  const block = Buffer.alloc(65536)
  while (true) {
    const length = fs.readSync(0, block, 0, block.length, null)
    if (!length) break
    size += length
    if (size > MAX_BYTES) throw new Error('input-budget')
    chunks.push(Buffer.from(block.subarray(0, length)))
  }
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).sort().join(',') !== 'queries,schema_version' ||
      input.schema_version !== 'sourcebastion.npm-selectors/1' ||
      !Array.isArray(input.queries) || input.queries.length > 100000) throw new Error('invalid-input')
  const result = []
  for (const query of input.queries) {
    if (!Array.isArray(query) || query.length !== 2 || typeof query[0] !== 'string' || typeof query[1] !== 'string' ||
        query[0].length > 256 || query[1].length > 16384 ||
        /[\x00-\x1f\x7f-\x9f]/.test(query[0] + query[1]) ||
        /\d{129,}/.test(query[0] + query[1]) || query[1].split(/\s+|\|\|/).length > 128) throw new Error('query-budget')
    // Use npm's default prerelease policy and strict grammar. No coercion,
    // includePrerelease override, project resolver or network enrichment.
    const parsed = semver.parse(query[0], { loose: false })
    const canonical = parsed && parsed.version + (parsed.build.length ? '+' + parsed.build.join('.') : '')
    if (canonical !== query[0]) {
      result.push('invalid-version')
    } else if (semver.validRange(query[1], { loose: false }) === null) {
      result.push('invalid-range')
    } else {
      result.push(semver.satisfies(query[0], query[1], { loose: false }) ? 'match' : 'nonmatch')
    }
  }
  const output = JSON.stringify({ schema_version: 'sourcebastion.npm-selector-results/1', results: result })
  if (Buffer.byteLength(output) > MAX_BYTES) throw new Error('output-budget')
  fs.writeSync(1, output)
}

try {
  execute()
} catch (_) {
  // Dependency/JSON errors may carry customer strings. Publish a fixed code.
  fs.writeSync(2, 'npm-selectors-refused\n')
  process.exitCode = 2
}
