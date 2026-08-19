// The grader grades itself: a compliant mock mint must pass clean, and a
// deliberately broken one must be caught. This is the local twin of CI's
// 'grader' job, so the pre-push gate runs what CI would have run - in
// process, no ports or log scraping.

import {bytesToHex, randomBytes} from '@noble/hashes/utils.js'
import {createMockMint} from '../mock-mint/index.mjs'
import {createReport, gradeMint, gradeNote, parseAdvertisedMintFee} from '../runner/index.mjs'

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

const bad = await grade({echoWrongK1: true})
if (bad.failed === 0) {
  console.error('a mint echoing the wrong k1 PASSED - the grader is blind')
  process.exit(1)
}
console.log(`ok   broken mock caught (${bad.failed} failing check${bad.failed === 1 ? '' : 's'})`)
