// Module hooks that load test/rr/*.js for their validRecords without running
// them: node:test and test/base.js are swapped for stubs, and the base stub's
// suite() hands each record list to globalThis.__interopRecords.
import fs from 'node:fs'

const here = new URL('./', import.meta.url).href
const BASE_STUB = 'interop:base-stub'

export async function resolve(specifier, context, next) {
  if (context.parentURL?.includes('/test/rr/')) {
    if (specifier === 'node:test') return { url: `${here}node-test-stub.js`, shortCircuit: true }
    if (specifier === '../base.js') return { url: BASE_STUB, shortCircuit: true }
  }
  return next(specifier, context)
}

export async function load(url, context, next) {
  if (url !== BASE_STUB) return next(url, context)

  // Stub every export of the real base.js, so a new helper there cannot break the import.
  const base = fs.readFileSync(new URL('../test/base.js', import.meta.url), 'utf8')
  const names = [...base.matchAll(/^export function (\w+)/gm)].map((m) => m[1])
  const source = names
    .map((name) =>
      name === 'suite'
        ? `export function suite(type, { valid = [] }) {
  const all = (globalThis.__interopRecords ??= new Map())
  all.set(type, [...(all.get(type) ?? []), ...valid])
}`
        : `export function ${name}() {}`,
    )
    .join('\n')
  return { format: 'module', source, shortCircuit: true }
}
