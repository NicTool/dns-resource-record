// RFC 1035 §5.1: in a presentation name, \. is a dot inside a label and
// \DDD is one octet. Splitting on '.' would break both.
export function nameToLabels(name) {
  if (name === '.') return []
  const enc = new TextEncoder()
  const labels = []
  let label = []
  for (let i = 0; i < name.length; i++) {
    const c = name[i]
    if (c === '.') {
      if (!label.length) throw new Error(`DNS name has an empty label: ${name}`)
      labels.push(Uint8Array.from(label))
      label = []
      continue
    }
    if (c === '\\') {
      if (++i === name.length) throw new Error(`DNS name ends in an incomplete escape: ${name}`)
      const decimal = name.slice(i, i + 3)
      if (/^[0-9]{3}$/.test(decimal) && Number(decimal) <= 255) {
        label.push(Number(decimal))
        i += 2
        continue
      }
      if (/[0-9]/.test(name[i])) throw new Error(`DNS name has an invalid decimal escape: ${name}`)
    }
    const char = String.fromCodePoint(name.codePointAt(i))
    label.push(...enc.encode(char))
    i += char.length - 1
  }
  if (label.length) labels.push(Uint8Array.from(label))
  for (const b of labels) {
    if (b.length > 63) throw new Error(`DNS label exceeds 63 bytes: ${name}`)
  }
  return labels
}

// A bare `*` is the RFC 4592 wildcard label; inside a longer label it is escaped.
export function labelToPresentation(bytes) {
  if (bytes.length === 1 && bytes[0] === 0x2a) return '*'
  let out = ''
  for (const b of bytes) {
    const c = String.fromCharCode(b)
    if (c === '.' || c === '\\') out += `\\${c}`
    else if (/[A-Za-z0-9\-_/]/.test(c)) out += c
    else out += `\\${String(b).padStart(3, '0')}`
  }
  return out
}

// RFC 1035 §5.1: \DDD is one octet and \X is X; other text is UTF-8.
export function presentationBytes(text) {
  const enc = new TextEncoder()
  const bytes = []
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\\') {
      if (++i === text.length) throw new Error(`incomplete escape: ${text}`)
      if (/[0-9]/.test(text[i])) {
        const decimal = text.slice(i, i + 3)
        if (!/^[0-9]{3}$/.test(decimal) || Number(decimal) > 255)
          throw new Error(`invalid decimal escape: \\${decimal}`)
        bytes.push(Number(decimal))
        i += 2
        continue
      }
    }
    const char = String.fromCodePoint(text.codePointAt(i))
    bytes.push(...enc.encode(char))
    i += char.length - 1
  }
  return Uint8Array.from(bytes)
}

// RFC 4343: only ASCII A-Z fold, and an escaped octet (\X or \DDD) stands for
// the exact byte written.
export function lowercaseName(name) {
  return name.replace(/\\(?:[0-9]{3}|.)|[A-Z]+/gs, (m) => (m[0] === '\\' ? m : m.toLowerCase()))
}
