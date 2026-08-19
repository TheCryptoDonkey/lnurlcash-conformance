// Checks the vectors against themselves.
//
// A vector file is only useful if it is right, and "right" here means
// internally consistent: every digest recomputes, every valid signature
// verifies, every fee expectation follows from the formula, every declared
// round trip round-trips. This catches a hand-edited expectation before an
// implementation inherits it as gospel.

import {readdirSync, readFileSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {bech32} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors')
const load = name => JSON.parse(readFileSync(join(VECTORS, name), 'utf8'))

let failures = 0
const check = (name, fn) => {
  try {
    fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    failures++
    console.log(` FAIL  ${name}\n         ${err.message}`)
  }
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg)
}

// ---- the manifest ----

const index = load('index.json')
check('every file in the manifest exists and parses', () => {
  for (const name of index.files) load(name)
})
check('every vector file is in the manifest', () => {
  const onDisk = readdirSync(VECTORS).filter(f => f.endsWith('.json') && f !== 'index.json')
  const missing = onDisk.filter(f => !index.files.includes(f))
  assert(missing.length === 0, `not listed in index.json: ${missing.join(', ')}`)
})
check('every vector file declares a version and a spec', () => {
  for (const name of index.files) {
    const v = load(name)
    assert(v.version === index.version, `${name}: version ${v.version}`)
    assert(typeof v.spec === 'string' && v.spec, `${name}: no spec`)
    assert(typeof v.description === 'string' && v.description, `${name}: no description`)
  }
})

// ---- signatures ----

const sig = load('signature.json')
const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))
const digestOf = (k1, amountMsat) =>
  sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes('Lightning Signed Message:'),
        ...utf8ToBytes(`LNURLcash:${amountMsat}:${noteId(k1)}`)
      ])
    )
  )

check('every signature case recomputes its own message and digest', () => {
  for (const c of sig.cases) {
    if (c.message === null) continue
    assert(
      c.message === `LNURLcash:${c.amountMsat}:${noteId(c.k1)}`,
      `${c.name}: message does not match`
    )
    assert(c.noteId === noteId(c.k1), `${c.name}: noteId does not match`)
    assert(
      c.digest === bytesToHex(digestOf(c.k1, c.amountMsat)),
      `${c.name}: digest does not match`
    )
  }
})

check('every signature case verifies exactly as declared', () => {
  const verify = (k1, amountMsat, sigHex, pubHex) => {
    let bytes
    try {
      bytes = hexToBytes(sigHex)
    } catch {
      return false
    }
    if (bytes.length !== 65) return false
    let digest
    try {
      digest = digestOf(k1, amountMsat)
    } catch {
      return false
    }
    const leading = new Uint8Array([bytes[64], ...bytes.subarray(0, 64)])
    for (const candidate of [leading, bytes]) {
      try {
        if (bytesToHex(secp256k1.recoverPublicKey(candidate, digest, {prehash: false})) === pubHex.toLowerCase()) {
          return true
        }
      } catch {
        // wrong ordering
      }
    }
    return false
  }
  for (const c of sig.cases) {
    assert(
      verify(c.k1, c.amountMsat, c.signature, c.mintPubkey) === c.valid,
      `${c.name}: expected valid=${c.valid}`
    )
  }
})

check('the signature set covers both recovery-id orderings and refusal cases', () => {
  assert(sig.cases.some(c => c.valid && /trailing/.test(c.name)), 'no trailing case')
  assert(sig.cases.some(c => c.valid && /leading/.test(c.name)), 'no leading case')
  assert(sig.cases.filter(c => !c.valid).length >= 6, 'too few refusal cases')
})

// ---- bech32 ----

const b32 = load('bech32.json')
check('every bech32 encoding round-trips', () => {
  for (const c of b32.encode) {
    const encoded = bech32
      .encode('lnurl', bech32.toWords(utf8ToBytes(c.url)), 2048)
      .toUpperCase()
    assert(encoded === c.lnurl, `${c.url}: encoding does not match`)
    const decoded = new TextDecoder().decode(
      bech32.fromWords(bech32.decode(c.lnurl.toLowerCase(), 2048).words)
    )
    assert(decoded === c.url, `${c.url}: decoding does not round-trip`)
  }
})

check('every invalid bech32 input really is invalid', () => {
  for (const c of b32.decodeInvalid) {
    let decoded = null
    try {
      const safe = c.input.trim().toUpperCase()
      if (safe.startsWith('LNURL1')) {
        decoded = new TextDecoder().decode(
          bech32.fromWords(bech32.decode(safe.toLowerCase(), 2048).words)
        )
      }
    } catch {
      decoded = null
    }
    assert(decoded === null, `${c.input}: decoded to ${decoded}`)
  }
})

// ---- fees ----

const fees = load('fees.json')
const proportional = (g, ppm) =>
  Math.floor(g / 1e6) * ppm + Math.floor(((g % 1e6) * ppm) / 1e6)
const applyFee = (g, f) => Math.max(0, g - f.baseFeeMsat - proportional(g, f.feePpm))
const grossUp = (net, f) => {
  if (net <= 0) return 0
  let hi = net + f.baseFeeMsat
  while (applyFee(hi, f) < net) hi *= 2
  let lo = 0
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2)
    if (applyFee(mid, f) >= net) hi = mid
    else lo = mid + 1
  }
  return lo
}

check('every apply expectation follows from the formula', () => {
  for (const c of fees.apply) {
    assert(
      applyFee(c.grossMsat, c.fee) === c.expect,
      `${c.grossMsat} with ${JSON.stringify(c.fee)}: expected ${c.expect}, formula gives ${applyFee(c.grossMsat, c.fee)}`
    )
  }
})

check('every gross-up expectation is the true minimum', () => {
  for (const c of fees.grossUp) {
    assert(grossUp(c.netMsat, c.fee) === c.expect, `${c.netMsat}: expected ${c.expect}`)
    if (c.netMsat > 0) {
      assert(applyFee(c.expect, c.fee) === c.netMsat, `${c.netMsat}: does not net back`)
      assert(applyFee(c.expect - 1, c.fee) < c.netMsat, `${c.netMsat}: not minimal`)
    }
  }
})

check('the gross-up round trip holds for every listed fee and amount', () => {
  for (const fee of fees.grossUpRoundTrip.fees) {
    for (const net of fees.grossUpRoundTrip.netAmountsMsat) {
      const gross = grossUp(net, fee)
      assert(applyFee(gross, fee) === net, `${net} with ${JSON.stringify(fee)}: nets ${applyFee(gross, fee)}`)
      assert(applyFee(gross - 1, fee) < net, `${net} with ${JSON.stringify(fee)}: not minimal`)
    }
  }
})

check('the overflow case really does exceed a naive 64-bit multiply', () => {
  const big = fees.apply.find(c => c.grossMsat >= 1e15)
  assert(big, 'no large-amount case present')
  assert(
    big.grossMsat * big.fee.feePpm > Number.MAX_SAFE_INTEGER,
    'the large case does not actually stress the multiply'
  )
})

// ---- callbacks ----

const callbacks = load('callbacks.json')
check('every callback case is consistent with its declared parameters', () => {
  for (const c of callbacks.cases) {
    const query = c.expectQuery
    const k1s = query.filter(([k]) => k === 'k1').map(([, v]) => v)
    assert(
      JSON.stringify(k1s) === JSON.stringify(c.params.k1),
      `${c.name}: k1 list does not match`
    )
    if (c.params.h) {
      assert(query.some(([k, v]) => k === 'h' && v === c.params.h), `${c.name}: h missing`)
    }
    if (c.params.h2) {
      assert(query.some(([k, v]) => k === 'h2' && v === c.params.h2), `${c.name}: h2 missing`)
    }
    if (c.params.amountMsat !== undefined) {
      assert(
        query.some(([k, v]) => k === 'amount' && v === String(c.params.amountMsat)),
        `${c.name}: amount missing`
      )
    }
    if (c.params.pr) {
      assert(query.some(([k, v]) => k === 'pr' && v === c.params.pr), `${c.name}: pr missing`)
      assert(k1s.length === 1, `${c.name}: a melt names more than one k1`)
      assert(
        !query.some(([k]) => k === 'amount'),
        `${c.name}: a melt carries an amount`
      )
    }
  }
})

check('every rejected callback case states why', () => {
  for (const c of callbacks.rejected) {
    assert(typeof c.why === 'string' && c.why.length > 10, `${c.name}: no reason given`)
  }
})

// ---- responses ----

const responses = load('responses.json')
check('every response case declares a known outcome', () => {
  const known = Object.keys(responses.outcomes)
  for (const c of responses.cases) {
    assert(known.includes(c.expect), `${c.name}: unknown outcome ${c.expect}`)
  }
  for (const outcome of known) {
    assert(
      responses.cases.some(c => c.expect === outcome),
      `no case covers the ${outcome} outcome`
    )
  }
})

check('the pending case uses the exact reason string the spec names', () => {
  const pending = responses.cases.find(c => c.expect === 'pending')
  assert(pending.body.reason === 'pending', `reason was ${JSON.stringify(pending.body.reason)}`)
})

// ---- withdraw info and pay request ----

for (const name of ['withdraw-info.json', 'pay-request.json']) {
  const v = load(name)
  check(`${name} has both accepted and rejected cases`, () => {
    const groups = [
      [v.accepted, v.rejected],
      [v.invoice?.accepted, v.invoice?.rejected],
      [v.verify?.accepted, v.verify?.rejected]
    ].filter(([a]) => a)
    for (const [accepted, rejected] of groups) {
      assert(accepted.length > 0, 'no accepted cases')
      assert(rejected.length > 0, 'no rejected cases')
      for (const c of [...accepted, ...rejected]) {
        assert(typeof c.name === 'string' && c.name, 'a case has no name')
      }
    }
  })
}

// ---- lifecycle ----

const lifecycle = load('lifecycle.json')
check('every lifecycle scenario states a requirement', () => {
  for (const s of lifecycle.scenarios) {
    assert(Array.isArray(s.steps) && s.steps.length > 0, `${s.name}: no steps`)
    assert(
      typeof s.requirement === 'string' && s.requirement.length > 40,
      `${s.name}: no requirement`
    )
  }
})

console.log(
  failures === 0
    ? '\nvectors are self-consistent'
    : `\n${failures} check(s) failed`
)
process.exit(failures === 0 ? 0 : 1)
