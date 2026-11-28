// Generates the API pages (doc/api/*.md) from the Doxygen comments of the PF_RING headers
// (replaces the Doxygen + Breathe step of the old Sphinx build).  Usage: node tools/gen-api.mjs  (npm run api)
import { readFileSync, writeFileSync } from 'node:fs'

const PAGES = [
  { out: 'api/pfring_k.md', header: '../kernel/linux/pf_ring.h' },
  { out: 'api/pfring.md', header: '../userland/lib/pfring.h' },
  { out: 'api/pfring_zc.md', header: '../userland/lib/pfring_zc.h' },
  { out: 'api/pfring_ft.md', header: '../userland/lib/pfring_ft.h' },
]
const MAX_DECLARATION_LINES = 80

// "/** ... */" blocks (not the "/**<" trailing member comments) with the declaration that follows
function parse(source) {
  const lines = source.split('\n')
  const items = []
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*\/\*\*(?!<)/.test(lines[i])) continue
    const comment = []
    let j = i
    for (; j < lines.length; j++) {
      comment.push(lines[j])
      if (lines[j].includes('*/')) break
    }
    const text = comment.join('\n').replace(/^\s*\/\*\*+/, '').replace(/\*+\/\s*$/, '').split('\n')
      .map((l) => l.replace(/^\s*\*\s?/, '')).join('\n').replace(/\\@/g, '@').trim()
    let k = j + 1
    while (k < lines.length && !lines[k].trim()) k++
    const declaration = []
    let depth = 0
    for (; k < lines.length && declaration.length < MAX_DECLARATION_LINES; k++) {
      declaration.push(lines[k])
      depth += (lines[k].match(/{/g) || []).length - (lines[k].match(/}/g) || []).length
      if (depth <= 0 && /[;}]\s*$|^\s*#define/.test(lines[k]) && !lines[k].trimEnd().endsWith('\\')) break
    }
    items.push({ text, declaration: declaration.join('\n').trimEnd() })
    i = j
  }
  return items
}

function nameOf(declaration) {
  const first = declaration.split('\n')[0]
  return (first.match(/^#define\s+(\w+)/) || first.match(/(\w+)\s*\(/) || declaration.match(/}\s*(\w+)\s*;/)
    || first.match(/(?:struct|enum|union)\s+(\w+)/) || first.match(/(\w+)\s*;/) || [, first.trim()])[1]
}

// Doxygen text -> Markdown: tags and the parameter table
function render(text) {
  const params = []
  let returns = ''
  const body = []
  let brief = ''
  for (const line of text.split('\n')) {
    let m
    if ((m = line.match(/^@param(?:\[\w+\])?\s+(\S+)\s*(.*)$/))) params.push([m[1], m[2]])
    else if ((m = line.match(/^@(?:return|returns)\s*(.*)$/))) returns = m[1]
    else if ((m = line.match(/^@brief\s*(.*)$/))) brief = m[1]
    else if ((m = line.match(/^@(?:details|note|warning)\s*(.*)$/))) body.push(m[1])
    else if (/^@(file|mainpage|defgroup)\b/.test(line)) continue
    else if (params.length && line.trim() && !/^[-*]|^\d+\./.test(line.trim())) params[params.length - 1][1] += ' ' + line.trim()
    else if (returns && line.trim()) returns += ' ' + line.trim()
    else body.push(line)
  }
  const out = []
  if (brief) out.push(brief, '')
  out.push(body.join('\n').trim())
  if (params.length) {
    out.push('', '| Parameter | Description |', '|---|---|')
    for (const [name, description] of params) out.push(`| \`${name}\` | ${description.replace(/\|/g, '\\|')} |`)
  }
  if (returns) out.push('', `**Returns:** ${returns}`)
  return out.join('\n').trim()
}

for (const page of PAGES) {
  const items = parse(readFileSync(page.header, 'utf8'))
  const file = items.find((it) => /^@file\b/m.test(it.text))
  const out = readFileSync(page.out, 'utf8')
  const front = out.match(/^---\n[\s\S]*?\n---\n/)[0]
  const title = front.match(/title: "(.*)"/)[1]
  const brief = file ? (file.text.match(/^@brief\s*(.*)$/m) || [, ''])[1] : ''
  const parts = [front.replace(/description: ".*"/, `description: "${brief}"`) + `# ${title}\n`, file ? render(file.text) : '']
  const seen = new Set()
  for (const item of items) {
    if (!item.declaration || item === file || item.declaration.trimStart().startsWith('/*')) continue
    const name = nameOf(item.declaration)
    if (seen.has(name)) continue
    seen.add(name)
    parts.push(`## ${name}\n\n\`\`\`c\n${item.declaration}\n\`\`\`\n\n${render(item.text)}`)
  }
  writeFileSync(page.out, parts.filter(Boolean).join('\n\n') + '\n')
  console.log(`${page.out}: ${seen.size} symbols from ${page.header}`)
}
