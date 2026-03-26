#!/usr/bin/env node
// Regenerates the Supported Records table in README.md using getTags() from each RR class.

import { readFileSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

import * as RR from '../index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

const tagToGroup = {
  common: 'Common',
  security: 'Security',
  dnssec: 'DNSSEC',
  deprecated: 'Deprecated',
  obsolete: 'Obsolete',
}

const groupOrder = ['Common', 'Less Common', 'Security', 'DNSSEC', 'Deprecated', 'Obsolete']

function getGroup(instance) {
  const tags = instance.getTags()
  for (const [tag, group] of Object.entries(tagToGroup)) {
    if (tags.includes(tag)) return group
  }
  return 'Less Common'
}

const groups = {}
for (const name of groupOrder) groups[name] = []

for (const [name, cls] of Object.entries(RR)) {
  if (name === 'typeMap' || name === 'default') continue
  if (typeof cls !== 'function') continue
  const instance = new cls(null)
  const group = getGroup(instance)
  groups[group].push(name)
}

const check = ':white_check_mark:'
const rows = []
for (const groupName of groupOrder) {
  const names = groups[groupName]
  if (!names.length) continue
  rows.push(`| *${groupName}* |`)
  for (const name of names.sort()) {
    const cls = RR[name]
    const hasToBind = typeof cls.prototype.toBind === 'function'
    const hasFromBind = typeof cls.prototype.fromBind === 'function'
    const hasToTinydns = typeof cls.prototype.toTinydns === 'function'
    const hasFromTinydns = typeof cls.prototype.fromTinydns === 'function'

    const bind = hasToBind && hasFromBind ? check : ''
    const tinydns = hasToTinydns && hasFromTinydns ? check : ''

    rows.push(`| **${name}** | ${bind} | ${tinydns} |`)
  }
}

const table = [
  `|     **RR**     |  **BIND / RFC 1035**  |     **Tinydns**     |`,
  `| :------------: | :-------------------: | :-----------------: |`,
  ...rows,
].join('\n')

const readmePath = join(__dirname, '..', 'README.md')
const readme = readFileSync(readmePath, 'utf-8')

// Replace from the table header line up to (but not including) the ## TIPS section
const tableHeaderMarker = '\n|     **RR**     |'
const tipsSectionMarker = '\n\n## TIPS'

const tableStart = readme.indexOf(tableHeaderMarker)
const tipsStart = readme.indexOf(tipsSectionMarker)

if (tableStart === -1 || tipsStart === -1) {
  console.error('Could not locate table boundaries in README.md')
  process.exit(1)
}

const newReadme = readme.slice(0, tableStart + 1) + table + '\n' + readme.slice(tipsStart)
writeFileSync(readmePath, newReadme)
console.log('README.md updated successfully')
