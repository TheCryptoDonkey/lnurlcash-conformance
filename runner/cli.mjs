#!/usr/bin/env node
import {createReport, gradeMint, gradeNote, parseAdvertisedMintFee, resolveMint} from './index.mjs'

const args = process.argv.slice(2)
const flags = new Set(args.filter(a => a.startsWith('--')))
const positional = args.filter(a => !a.startsWith('--'))
const noteArg = args.find(a => a.startsWith('--note='))?.slice('--note='.length)

if (positional.length === 0 && !noteArg) {
  console.error(`lnurlcash-conform - grade an LNURLcash service against LUD-25

  lnurlcash-conform <mint>              read-only checks
  lnurlcash-conform <mint> --note=<url> --spend   full checks

<mint> may be a Lightning Address (mint@example.com), a bare domain, or a
payRequest URL.

The note checks SPEND: they burn the note given and leave its value in a
fresh note printed at the end. Use a small note, and pass --spend to
confirm you meant it.`)
  process.exit(2)
}

const report = createReport()

let pay
if (positional[0]) {
  const payUrl = resolveMint(positional[0])
  console.log(`grading ${payUrl}\n`)
  pay = await gradeMint(payUrl, report)
}

let finished
if (noteArg) {
  if (!flags.has('--spend')) {
    report.skip('note checks', 'pass --spend to run them - they burn the note')
  } else {
    console.log('running the mutating checks - this spends the note given\n')
    // knowing the advertised fee makes the conservation checks exact
    const options =
      pay && typeof pay.metadata === 'string' ? {mintFee: parseAdvertisedMintFee(pay.metadata)} : {}
    finished = await gradeNote(noteArg, report, options)
  }
}

const symbol = {pass: '  ok  ', fail: ' FAIL ', warn: ' warn ', skip: ' skip '}
for (const r of report.results) {
  console.log(`${symbol[r.status]} ${r.name}${r.detail ? ` - ${r.detail}` : ''}`)
}

const counts = report.results.reduce((acc, r) => {
  acc[r.status] = (acc[r.status] ?? 0) + 1
  return acc
}, {})
console.log(
  `\n${counts.pass ?? 0} passed, ${counts.fail ?? 0} failed, ${counts.warn ?? 0} warnings, ${counts.skip ?? 0} skipped`
)

if (finished) {
  console.log(`\nthe value now lives in:\n  ${finished.noteUrl}`)
}

process.exit(report.failed > 0 ? 1 : 0)
