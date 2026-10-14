import fs from 'node:fs'
import { register } from 'node:module'

import * as RR from '../index.js'

const FIXTURE_KEYS = ['testB', 'testT', 'testW', 'testM', 'msg']

// Every validRecords entry in test/rr/*.js, plus each type's canonical record.
export async function collectRecords() {
  register('./hooks.js', import.meta.url)
  const dir = new URL('../test/rr/', import.meta.url)
  for (const file of fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.js'))
    .sort()) {
    await import(new URL(file, dir).href)
  }

  const records = []
  for (const [type, list] of globalThis.__interopRecords ?? []) {
    for (const rec of list)
      records.push({ type: type.typeName, source: 'validRecords', rec: withoutFixtures(rec) })
  }
  for (const Type of Object.values(RR)) {
    if (typeof Type !== 'function' || Type.typeId === undefined || !Type.typeName) continue
    records.push({ type: Type.typeName, source: 'canonical', rec: new Type(null).getCanonical() })
  }
  return records
}

function withoutFixtures(rec) {
  return Object.fromEntries(Object.entries(rec).filter(([k]) => !FIXTURE_KEYS.includes(k)))
}
