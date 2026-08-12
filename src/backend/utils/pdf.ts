/**
 * Minimal PDF writer.
 *
 * Produces a valid single- or multi-page PDF 1.4 document using the base-14
 * Helvetica font, with no external dependency. Enough for tabular reports,
 * which is all this application exports.
 */

const PAGE_WIDTH = 842 // A4 landscape, points
const PAGE_HEIGHT = 595
const MARGIN = 36
const LINE_HEIGHT = 12
const FONT_SIZE = 8
const TITLE_SIZE = 14

function escapeText(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')
}

/** Drops characters WinAnsi cannot represent, so the file never breaks. */
function toWinAnsi(value: string): string {
  let out = ''
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0
    out += code >= 32 && code <= 255 ? char : '?'
  }
  return out
}

export interface PdfTable {
  title: string
  subtitle?: string
  columns: string[]
  rows: string[][]
}

export function renderTablePdf(table: PdfTable): Buffer {
  const usableWidth = PAGE_WIDTH - MARGIN * 2
  const columnWidth = usableWidth / Math.max(table.columns.length, 1)
  const charsPerColumn = Math.max(4, Math.floor(columnWidth / (FONT_SIZE * 0.5)))
  const rowsPerPage = Math.floor((PAGE_HEIGHT - MARGIN * 2 - 48) / LINE_HEIGHT)

  const cell = (value: string): string => {
    const clean = toWinAnsi(value ?? '')
    return clean.length > charsPerColumn ? `${clean.slice(0, charsPerColumn - 1)}~` : clean
  }

  const pages: string[][] = []
  for (let i = 0; i < Math.max(table.rows.length, 1); i += rowsPerPage) {
    pages.push([])
    const slice = table.rows.slice(i, i + rowsPerPage)
    for (const row of slice) {
      pages[pages.length - 1].push(
        table.columns.map((_, index) => cell(row[index] ?? '').padEnd(charsPerColumn)).join(' ')
      )
    }
  }

  const headerLine = table.columns.map((c) => cell(c).padEnd(charsPerColumn)).join(' ')
  const objects: string[] = []
  const pageIds: number[] = []

  // Object numbering: 1 = catalog, 2 = pages, 3 = font, then per page a page
  // object and its content stream.
  let nextId = 4
  const contents: Array<{ pageId: number; contentId: number; body: string }> = []

  for (let p = 0; p < pages.length; p++) {
    const pageId = nextId++
    const contentId = nextId++
    pageIds.push(pageId)

    const lines: string[] = []
    lines.push('BT', `/F1 ${TITLE_SIZE} Tf`, `1 0 0 1 ${MARGIN} ${PAGE_HEIGHT - MARGIN} Tm`)
    lines.push(`(${escapeText(toWinAnsi(table.title))}) Tj`)
    lines.push('ET')

    lines.push('BT', `/F1 ${FONT_SIZE} Tf`, `1 0 0 1 ${MARGIN} ${PAGE_HEIGHT - MARGIN - 18} Tm`)
    const subtitle = `${table.subtitle ?? ''}  —  page ${p + 1} of ${pages.length}`
    lines.push(`(${escapeText(toWinAnsi(subtitle))}) Tj`)
    lines.push('ET')

    let y = PAGE_HEIGHT - MARGIN - 40
    lines.push('BT', `/F1 ${FONT_SIZE} Tf`, `1 0 0 1 ${MARGIN} ${y} Tm`, `(${escapeText(headerLine)}) Tj`, 'ET')
    y -= LINE_HEIGHT

    for (const line of pages[p]) {
      lines.push('BT', `/F1 ${FONT_SIZE} Tf`, `1 0 0 1 ${MARGIN} ${y} Tm`, `(${escapeText(line)}) Tj`, 'ET')
      y -= LINE_HEIGHT
    }

    contents.push({ pageId, contentId, body: lines.join('\n') })
  }

  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>'
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'

  for (const { pageId, contentId, body } of contents) {
    objects[pageId] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
      `/Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`
    objects[contentId] = `<< /Length ${Buffer.byteLength(body, 'latin1')} >>\nstream\n${body}\nendstream`
  }

  const chunks: Buffer[] = []
  let offset = 0
  const push = (text: string): void => {
    const buf = Buffer.from(text, 'latin1')
    chunks.push(buf)
    offset += buf.length
  }

  push('%PDF-1.4\n')
  const offsets: number[] = []
  for (let id = 1; id < objects.length; id++) {
    offsets[id] = offset
    push(`${id} 0 obj\n${objects[id]}\nendobj\n`)
  }

  const xrefStart = offset
  const count = objects.length
  let xref = `xref\n0 ${count}\n0000000000 65535 f \n`
  for (let id = 1; id < count; id++) {
    xref += `${String(offsets[id] ?? 0).padStart(10, '0')} 00000 n \n`
  }
  push(xref)
  push(`trailer\n<< /Size ${count} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`)

  return Buffer.concat(chunks)
}
