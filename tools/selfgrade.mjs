// The grader grades itself: a compliant mock mint must pass clean, and a
// deliberately broken one must be caught. This is the local twin of CI's
// 'grader' job, so the pre-push gate runs what CI would have run - in
// process, no ports or log scraping.

import {bytesToHex, randomBytes} from '@noble/hashes/utils.js'
import {createMockMint} from '../mock-mint/index.mjs'
import {
  createReport,
  gradeMint,
  gradeMintedValue,
  gradeNote,
  parseAdvertisedMintFee
} from '../runner/index.mjs'

const grade = async mockOptions => {
  const mint = await createMockMint(mockOptions)
  try {
    const k1 = bytesToHex(randomBytes(32))
    mint.state.creditNote(k1, 21_000)
    const report = createReport()
    const pay = await gradeMint(`${mint.url}/.well-known/lnurlp/mint`, report)
    const options =
      pay && typeof pay.metadata === 'string'
        ? {mintFee: parseAdvertisedMintFee(pay.metadata)}
        : {}
    await gradeNote(`${mint.url}/w?k1=${k1}&amount=21000`, report, options)
    return report
  } finally {
    await mint.close()
  }
}

const good = await grade({})
if (good.failed > 0) {
  console.error('a COMPLIANT mint failed grading:')
  for (const r of good.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
console.log(`ok   compliant mock passes (${good.results.length} checks)`)

// The other legal spelling of withdrawLink: the lnurlw:// scheme form. The
// grader must take both, and say which it saw.
const plain = await grade({withdrawLinkForm: 'lnurlw'})
if (plain.failed > 0) {
  console.error('a mint with an lnurlw:// withdrawLink failed grading:')
  for (const r of plain.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
const forms = [good, plain].map(
  r => r.results.find(x => x.name.startsWith('advertises a withdrawLink'))?.detail ?? ''
)
if (!forms[0].includes('plain URL form') || !forms[1].includes('lnurlw:// form')) {
  console.error(`the grader did not report the withdrawLink form: ${JSON.stringify(forms)}`)
  process.exit(1)
}
console.log('ok   lnurlw:// withdrawLink passes, and both forms are named in the report')

const bad = await grade({echoWrongK1: true})
if (bad.failed === 0) {
  console.error('a mint echoing the wrong k1 PASSED - the grader is blind')
  process.exit(1)
}
console.log(`ok   broken mock caught (${bad.failed} failing check${bad.failed === 1 ? '' : 's'})`)

// The minted-value check: pay a mint invoice (via the test hooks - the mock
// invents its invoices), then compare the note against the fee formula.
const gradeMintFlow = async mockOptions => {
  const mint = await createMockMint({
    testHooks: true,
    baseFeeMsat: 1000,
    feePpm: 1000,
    ...mockOptions
  })
  try {
    const gross = 500_000
    const quote = await (await fetch(`${mint.url}/p/cb?amount=${gross}`)).json()
    const paymentHash = quote.verify.split('/').pop()
    await fetch(`${mint.url}/_test/settle?payment_hash=${paymentHash}`)
    const k1 = mint.state.invoices.get(paymentHash).preimage
    const report = createReport()
    await gradeMintedValue(`${mint.url}/w?k1=${k1}`, report, {
      mintFee: {baseFeeMsat: 1000, feePpm: 1000},
      paidMsat: gross
    })
    return report
  } finally {
    await mint.close()
  }
}

const exact = await gradeMintFlow({})
if (exact.failed > 0) {
  console.error('a formula-exact mint FAILED the minted-value check:')
  for (const r of exact.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
console.log('ok   formula-exact mint passes the minted-value check')

// The reference mint ceilings its fee to a whole sat on purpose, and the
// draft does not say whether that is right. Grading it as a failure would
// be this repo picking a side, so the check takes a band - but the band
// has to have a far edge, or it grades nothing at all.
const rounded = await gradeMintFlow({roundFeeToSat: true})
if (rounded.failed > 0) {
  console.error('a mint ceilinging its fee to a whole sat FAILED - that is what the reference does:')
  for (const r of rounded.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
console.log('ok   sat-ceilinged fee accepted, as the reference mint charges it')

const greedy = await gradeMintFlow({roundFeeToSat: true, extraFeeMsat: 1})
if (greedy.failed === 0) {
  console.error('a mint taking a msat beyond the ceilinged fee PASSED - the band grades nothing')
  process.exit(1)
}
console.log('ok   a msat past the band still caught')

const generous = await gradeMintFlow({extraFeeMsat: -1})
if (generous.failed === 0) {
  console.error('a mint crediting more than it advertised PASSED - the band has no near edge')
  process.exit(1)
}
console.log('ok   crediting more than the formula still caught')

// The two split refusals LUD-25 spells out. Both need a fee-advertising
// mint to bite at all, so they are graded against one, and each must name
// its own check rather than merely pushing the failure count up.
const caughtBy = (report, name) =>
  report.results.some(r => r.status === 'fail' && r.name === name)

const looseH2 = await grade({acceptsMissingH2: true, baseFeeMsat: 1000, feePpm: 1000})
if (!caughtBy(looseH2, 'refuses a split with no h2')) {
  console.error('a mint generating the change secret itself PASSED - the grader is blind')
  process.exit(1)
}
console.log('ok   split with no h2 caught')

const looseFee = await grade({splitIgnoresBaseFee: true, baseFeeMsat: 1000, feePpm: 1000})
if (!caughtBy(looseFee, 'refuses a split whose change cannot cover the base fee')) {
  console.error('a mint splitting past its own base fee PASSED - the grader is blind')
  process.exit(1)
}
console.log('ok   split past the base fee caught')

const leaky = await grade({verifyLeaksEarly: true})
if (leaky.failed === 0) {
  console.error('a mint serving preimages before settlement PASSED - the grader is blind')
  process.exit(1)
}
console.log('ok   pre-settlement verify leak caught')
