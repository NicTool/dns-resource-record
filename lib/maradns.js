// csv2(5) and csv2_txt(5): text inside '...' is literal, so ', |, ~, # and
// controls are written outside the quotes as \xNN escapes.
export function quoteCharString(str) {
  let out = ''
  let quoted = false
  for (const c of String(str)) {
    const code = c.codePointAt(0)
    const escaped = code < 0x20 || code === 0x7f || "'|~#".includes(c)
    if (escaped === quoted) {
      out += "'"
      quoted = !quoted
    }
    out += escaped ? `\\x${code.toString(16).padStart(2, '0')}` : c
  }
  if (quoted) out += "'"
  return out || "''"
}
