// Regenerates build/icon.png (512 px) and branding/logo-512.png from
// branding/logo.svg. electron-builder turns build/icon.png into the Windows
// .ico. Only needed when the logo changes; the outputs are committed.
// Run: npm i --no-save playwright && node scripts/make-icon.mjs
// (CHROMIUM_PATH picks an existing Chromium instead of Playwright's download.)
import { readFileSync, writeFileSync } from 'node:fs'
import { chromium } from 'playwright'

const svg = readFileSync(new URL('../branding/logo.svg', import.meta.url), 'utf8')
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {})
const page = await browser.newPage({ viewport: { width: 512, height: 512 } })
await page.setContent(`<html><body style="margin:0;background:transparent">${svg}</body></html>`)
const png = await page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: 512, height: 512 } })
await browser.close()

writeFileSync(new URL('../build/icon.png', import.meta.url), png)
writeFileSync(new URL('../branding/logo-512.png', import.meta.url), png)
console.log('build/icon.png and branding/logo-512.png written')
