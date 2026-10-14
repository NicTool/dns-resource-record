// RFC 1035 §5.1: in a presentation name, \. is a dot inside a label and
// \DDD is one octet. Splitting on '.' would break both.
export function nameToLabels(name) {
  if (name === '.') return []
  const texts = []
  let start = 0
  for (let i = 0; i < name.length; i++) {
    if (name[i] === '\\') i++
    else if (name[i] === '.') {
      texts.push(name.slice(start, i))
      start = i + 1
    }
  }
  if (start < name.length) texts.push(name.slice(start))
  return texts.map((text) => {
    if (!text) throw new Error(`DNS name has an empty label: ${name}`)
    let label
    try {
      label = presentationBytes(text)
    } catch (e) {
      throw new Error(`DNS name has an ${e.message}`, { cause: e })
    }
    if (label.length > 63) throw new Error(`DNS label exceeds 63 bytes: ${name}`)
    return label
  })
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

// A final \. is a dot inside the last label, unless the backslash is itself escaped.
export function endsWithRoot(name) {
  return /(?:^|[^\\])(?:\\\\)*\.$/.test(name)
}

// RFC 4343: only ASCII A-Z fold, and an escaped octet (\X or \DDD) stands for
// the exact byte written.
export function lowercaseName(name) {
  return name.replace(/\\(?:[0-9]{3}|.)|[A-Z]+/gs, (m) => (m[0] === '\\' ? m : m.toLowerCase()))
}
