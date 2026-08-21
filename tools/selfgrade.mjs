// The grader grades itself: a compliant mock mint must pass clean, and a
// deliberately broken one must be caught. This is the local twin of CI's
// 'grader' job, so the pre-push gate runs what CI would have run - in
// process, no ports or log scraping.

import {bech32} from '@scure/base'
import {bytesToHex, randomBytes} from '@noble/hashes/utils.js'
import {createMockMint} from '../mock-mint/index.mjs'
import {
  createReport,
  gradeMint,
  gradeMintedValue,
  gradeNote,
  parseAdvertisedMintFee
} from '../runner/index.mjs'

const grade = async (mockOptions, {previousPubkeys} = {}) => {
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
    // What the CLI does: carry the keys the mint publishes into the note
    // checks, so a note issued before a signing-key rotation still
    // verifies. A caller can override to prove the acceptance is doing
    // work rather than waving everything through.
    const published = previousPubkeys ?? pay?.mintAddress?.previousPubkeys
    if (Array.isArray(published)) options.previousPubkeys = published
    await gradeNote(`${mint.url}/w?k1=${k1}&amount=21000`, report, options)
    return report
  } finally {
    await mint.close()
  }
}

const statusOf = (report, name) => report.results.find(r => r.name === name)?.status
const detailOf = (report, name) => report.results.find(r => r.name === name)?.detail ?? ''
const die = message => {
  console.error(message)
  process.exit(1)
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

// ---- the optional extensions -------------------------------------------
//
// Mint info, liabilities and signing-key rotation are all outside LUD-25
// and all optional. The grader has to say something useful when they are
// published and nothing at all when they are not, so both directions are
// proved here.

const MINT_INFO_CHECK = 'publishes a mint address (experimental, optional)'
const LIABILITIES_CHECK = 'publishes liabilities (optional)'
const SIGNATURE_CHECK = 'signs the notes it issues (optional)'

// a real npub, decoded rather than pattern-matched by the grader
const npub = bech32.encode('npub', bech32.toWords(new Uint8Array(32).fill(2)), 200)
const PREVIOUS_KEY = '3'.repeat(64)

const bare = await grade({})
if (statusOf(bare, LIABILITIES_CHECK) !== 'warn') {
  die(`a mint publishing no liabilities did not warn: ${statusOf(bare, LIABILITIES_CHECK)}`)
}
if (statusOf(bare, MINT_INFO_CHECK) !== 'pass') {
  die(`a mint publishing no info stopped passing the mint address check: ${detailOf(bare, MINT_INFO_CHECK)}`)
}
console.log('ok   a mint publishing none of the optional extensions is not graded down')

const dressed = await grade({
  name: 'Mock Mint',
  description: 'a mint that exists to be graded',
  contact: {nostr: npub, email: 'operator@example.com', url: 'https://mint.example/contact'},
  tosUrl: 'https://mint.example/terms',
  motd: 'fees change on the first',
  version: '0.2.0',
  previousPrivateKey: PREVIOUS_KEY,
  stats: true,
  baseFeeMsat: 1000,
  feePpm: 1000
})
if (dressed.failed > 0) {
  console.error('a mint publishing the optional extensions FAILED grading:')
  for (const r of dressed.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (statusOf(dressed, MINT_INFO_CHECK) !== 'pass') {
  die(`well-formed mint info did not pass: ${detailOf(dressed, MINT_INFO_CHECK)}`)
}
for (const field of ['name', 'contact', 'tosUrl', 'motd', 'fees', 'previousPubkeys']) {
  if (!detailOf(dressed, MINT_INFO_CHECK).includes(field)) {
    die(`the report does not name the published ${field}: ${detailOf(dressed, MINT_INFO_CHECK)}`)
  }
}
if (statusOf(dressed, LIABILITIES_CHECK) !== 'pass') {
  die(`a well-covered mint's liabilities did not pass: ${detailOf(dressed, LIABILITIES_CHECK)}`)
}
if (!/coverage/.test(detailOf(dressed, LIABILITIES_CHECK))) {
  die(`the liabilities report does not name the coverage: ${detailOf(dressed, LIABILITIES_CHECK)}`)
}
console.log('ok   mint info and liabilities pass and are named in the report')

// A published field of the wrong shape is a warning, never a failure: it
// is worth saying out loud, because a wallet will try to render it.
const malformed = await grade({contact: {nostr: 'npub1notarealkey'}})
if (statusOf(malformed, MINT_INFO_CHECK) !== 'warn') {
  die(`a contact.nostr that is not an npub did not warn: ${statusOf(malformed, MINT_INFO_CHECK)}`)
}
if (malformed.failed > 0) die('a malformed optional field FAILED the grade - it must only warn')
console.log('ok   a malformed optional field warns and never fails')

// Under-coverage is the operator's business to disclose. A mint that
// publishes an uncomfortable number is behaving better than one that
// publishes nothing, so it warns.
const thin = await grade({stats: true, localBalanceMsat: 1})
if (statusOf(thin, LIABILITIES_CHECK) !== 'warn') {
  die(`an under-covered mint did not warn: ${statusOf(thin, LIABILITIES_CHECK)}`)
}
if (thin.failed > 0) die('an under-covered mint FAILED the grade - it must only warn')
console.log('ok   an under-covered mint warns and never fails')

// A mint whose advertisement has rotated ahead of its signer: notes come
// out under the old key, which the mint still publishes.
const rotated = await grade({previousPrivateKey: PREVIOUS_KEY, signWithPreviousKey: true})
if (rotated.failed > 0) {
  console.error('a mint signing under a published previous key FAILED grading:')
  for (const r of rotated.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (!/previous signing key/.test(detailOf(rotated, SIGNATURE_CHECK))) {
  die(`the report does not say the note was signed under a previous key: ${detailOf(rotated, SIGNATURE_CHECK)}`)
}
console.log('ok   a signature under a published previous key is accepted, and named as one')

// ... and the acceptance has to be doing work. The same mint, graded
// without the keys it publishes, must be caught.
const unpublished = await grade(
  {previousPrivateKey: PREVIOUS_KEY, signWithPreviousKey: true},
  {previousPubkeys: []}
)
if (statusOf(unpublished, SIGNATURE_CHECK) !== 'fail') {
  die('a signature under a key the mint never published PASSED - the grader is blind')
}
console.log('ok   a signature under an unpublished key still caught')
