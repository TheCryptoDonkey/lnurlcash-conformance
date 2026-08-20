// Generates the LNURLcash conformance vectors.
//
// Deliberately written against @noble/@scure directly rather than against
// any lnurlcash library: these vectors exist to catch an implementation
// disagreeing with the spec, which they cannot do if they were produced by
// one of the implementations under test. Every value here is derived from
// the LUD-25 draft text and the LUD-01/03/06/16/21 primitives it builds on.
//
// Deterministic by construction - fixed keys, fixed secrets, no randomness -
// so regenerating produces a byte-identical tree and a diff means a real
// change.

import {writeFileSync, mkdirSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {bech32} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const OUT = join(HERE, '..', 'vectors')
mkdirSync(OUT, {recursive: true})

const VERSION = 1
const SPEC = 'LUD-25 draft (lnurl/luds#301)'

const write = (name, body) => {
  const path = join(OUT, name)
  writeFileSync(path, JSON.stringify(body, null, 2) + '\n')
  return name
}

// ---- fixed test material -------------------------------------------------

// a mint's identity key. Fixed, obviously not secret, and never to be used
// for anything but producing these vectors.
const MINT_PRIV = hexToBytes(
  '1111111111111111111111111111111111111111111111111111111111111111'
)
const MINT_PUB = bytesToHex(secp256k1.getPublicKey(MINT_PRIV, true))
const OTHER_PRIV = hexToBytes(
  '2222222222222222222222222222222222222222222222222222222222222222'
)
const OTHER_PUB = bytesToHex(secp256k1.getPublicKey(OTHER_PRIV, true))

const K1_A = 'a'.repeat(64)
const K1_B = 'b'.repeat(64)
const K1_C = '0f'.repeat(32)

const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))

// ---- the signature scheme ------------------------------------------------

const LSM_PREFIX = 'Lightning Signed Message:'
const DOMAIN_TAG = 'LNURLcash'

const sigMessage = (k1, amountMsat) =>
  `${DOMAIN_TAG}:${amountMsat}:${noteId(k1)}`

const sigDigest = (k1, amountMsat) =>
  sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes(LSM_PREFIX),
        ...utf8ToBytes(sigMessage(k1, amountMsat))
      ])
    )
  )

// @noble's 'recovered' format is recovery-id-leading (recid || r || s).
// LUD-25's wire format is r || s || recid, matching a raw BOLT-11
// signature - so the canonical vector reorders, and the leading form is
// emitted separately as the interop case some mints have actually sent.
const signLeading = (priv, k1, amountMsat) =>
  secp256k1.sign(sigDigest(k1, amountMsat), priv, {
    format: 'recovered',
    prehash: false
  })

const signTrailing = (priv, k1, amountMsat) => {
  const lead = signLeading(priv, k1, amountMsat)
  return new Uint8Array([...lead.subarray(1), lead[0]])
}

// ---- vectors: signature --------------------------------------------------

const sigCase = (name, opts) => ({
  name,
  k1: opts.k1,
  noteId: noteId(opts.k1),
  amountMsat: opts.amountMsat,
  message: sigMessage(opts.k1, opts.amountMsat),
  digest: bytesToHex(sigDigest(opts.k1, opts.amountMsat)),
  signature: opts.signature,
  mintPubkey: opts.mintPubkey,
  valid: opts.valid,
  note: opts.note
})

const signature = {
  version: VERSION,
  spec: SPEC,
  description:
    'Offline verification of a note (LUD-25). A SERVICE signs (note id, amount) with its Lightning node identity key via the standard signmessage wrapping; a holder recovers the pubkey and compares it to mintPubkey without contacting the SERVICE.',
  scheme: {
    domainTag: DOMAIN_TAG,
    lightningSignedMessagePrefix: LSM_PREFIX,
    message: '"LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(sha256(k1))',
    digest: 'sha256(sha256(prefix_utf8 || message_utf8))',
    signature: '65 bytes, r || s || recovery_id, hex encoded',
    pubkey: '33-byte compressed secp256k1 point, hex encoded',
    verification:
      'recover the pubkey from digest with NO further hashing (prehash must be off) and compare to mintPubkey. A verifier MUST also accept recovery_id || r || s, which some SERVICEs emit; trying both is safe because the wrong ordering recovers an unrelated key that cannot match.'
  },
  mintPubkey: MINT_PUB,
  otherPubkey: OTHER_PUB,
  cases: [
    sigCase('valid, canonical trailing recovery id', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: true,
      note: 'the wire format LUD-25 specifies'
    }),
    sigCase('valid, leading recovery id (real-world interop)', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signLeading(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: true,
      note: 'lnurl-mint once forwarded its node signmessage output unreordered; a verifier must tolerate this layout'
    }),
    sigCase('valid, zero amount', {
      k1: K1_C,
      amountMsat: 0,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_C, 0)),
      mintPubkey: MINT_PUB,
      valid: true
    }),
    sigCase('valid, large amount', {
      k1: K1_B,
      amountMsat: 2100000000000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_B, 2100000000000)),
      mintPubkey: MINT_PUB,
      valid: true,
      note: 'above 2^32 msat - implementations must not truncate the amount to 32 bits'
    }),
    sigCase('invalid: amount does not match what was signed', {
      k1: K1_A,
      amountMsat: 21001,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false,
      note: 'the whole point of signing the amount: a note cannot be inflated after issuance'
    }),
    sigCase('invalid: different k1 than was signed', {
      k1: K1_B,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: signed by a different key', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(OTHER_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: signature is not hex', {
      k1: K1_A,
      amountMsat: 21000,
      signature: 'not-hex-at-all',
      mintPubkey: MINT_PUB,
      valid: false,
      note: 'must return false, never throw'
    }),
    sigCase('invalid: signature too short', {
      k1: K1_A,
      amountMsat: 21000,
      signature: 'ab'.repeat(10),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: signature too long', {
      k1: K1_A,
      amountMsat: 21000,
      signature: 'ab'.repeat(70),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: empty signature', {
      k1: K1_A,
      amountMsat: 21000,
      signature: '',
      mintPubkey: MINT_PUB,
      valid: false
    }),
    {
      name: 'invalid: k1 is not hex',
      k1: 'zzzz',
      noteId: null,
      amountMsat: 21000,
      message: null,
      digest: null,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false,
      note: 'a malformed stored k1 must verify as false rather than crash the caller'
    },
    sigCase('invalid: mintPubkey is not a point', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: 'ff'.repeat(33),
      valid: false
    })
  ]
}

// ---- vectors: bech32 (LUD-01) --------------------------------------------

const lnurlEncode = url =>
  bech32.encode('lnurl', bech32.toWords(utf8ToBytes(url)), 2048).toUpperCase()

const bech32Urls = [
  'https://mint.example/w?k1=' + K1_A,
  'https://mint.example/.well-known/lnurlp/mint',
  'https://mint.example/w?k1=' + K1_A + '&amount=21000',
  'http://localhost:8000/w?k1=' + K1_C
]

const bech32Vectors = {
  version: VERSION,
  spec: 'LUD-01',
  description:
    'bech32 encoding of LNURLs. The hrp is "lnurl"; the limit is raised well above bech32 default because a note URL carrying k1, amount and sig is long.',
  encode: bech32Urls.map(url => ({url, lnurl: lnurlEncode(url)})),
  decodeInvalid: [
    {input: '', why: 'empty'},
    {input: 'LNURL1', why: 'no data part'},
    {input: 'https://mint.example/w', why: 'not bech32 at all'},
    {
      input: lnurlEncode('https://mint.example/w').slice(0, -1) + 'q',
      why: 'checksum corrupted'
    },
    {input: 'LNBC1QQQQ', why: 'wrong hrp'}
  ],
  caseInsensitive: {
    note: 'bech32 is case-insensitive; a decoder must accept either casing and produce the same URL',
    lower: lnurlEncode('https://mint.example/w').toLowerCase(),
    upper: lnurlEncode('https://mint.example/w'),
    url: 'https://mint.example/w'
  }
}

// ---- vectors: URL admission ----------------------------------------------

const urlAdmission = {
  version: VERSION,
  spec: SPEC,
  description:
    'Which URLs an implementation may fetch. Applies to every URL, whether scanned/pasted by a user or handed over by a SERVICE in its own response (callback, verify, payLink). https always; http only for loopback and .onion. Anything else is refused, so a crafted note cannot answer its own informational GET (a data: URL carrying withdrawRequest JSON would otherwise mint a self-contained fake note) and a SERVICE cannot redirect a k1-bearing callback onto cleartext.',
  allowed: [
    'https://mint.example/w',
    'https://mint.example:8443/w?k1=' + K1_A,
    'http://localhost:8000/w',
    'http://127.0.0.1:8000/w',
    'http://0.0.0.0:8000/w',
    'http://mint.onion/w',
    'http://sub.domain.onion/w?k1=' + K1_A
  ],
  rejected: [
    {url: 'http://mint.example/w', why: 'cleartext to a clearnet host'},
    {url: 'data:application/json,{"tag":"withdrawRequest"}', why: 'data: URL - a note that answers itself'},
    {url: 'file:///etc/passwd', why: 'file: URL'},
    {url: 'javascript:alert(1)', why: 'javascript: URL'},
    {url: 'ftp://mint.example/w', why: 'unsupported scheme'},
    {url: 'not a url at all', why: 'unparseable'},
    {url: '', why: 'empty'}
  ]
}

// ---- vectors: input resolution -------------------------------------------

const inputResolution = {
  version: VERSION,
  spec: 'LUD-01, LUD-16, LUD-17, LUD-25',
  description:
    'Resolving user-supplied text down to a fetchable URL. Every branch that produces a URL must also pass the url-admission rules.',
  lnurl: [
    {input: 'https://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A},
    {input: 'lnurlw://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A},
    {input: 'LNURLW://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A, why: 'scheme is case-insensitive'},
    {input: 'lnurlp://mint.example/p', expect: 'https://mint.example/p'},
    {input: 'lnurlw://localhost:8000/w', expect: 'http://localhost:8000/w', why: 'loopback resolves to http'},
    {input: 'lnurlw://mint.onion/w', expect: 'http://mint.onion/w'},
    {input: lnurlEncode('https://mint.example/w'), expect: 'https://mint.example/w'},
    {input: '  https://mint.example/w  ', expect: 'https://mint.example/w', why: 'surrounding whitespace trimmed'},
    {input: 'mint@mint.example', expect: 'https://mint.example/.well-known/lnurlp/mint'},
    {input: 'http://mint.example/w', expect: null, why: 'cleartext clearnet'},
    {input: '', expect: null},
    {input: 'gibberish', expect: null}
  ],
  mint: [
    {input: 'mint@mint.example', expect: 'https://mint.example/.well-known/lnurlp/mint'},
    {input: 'alice@mint.example', expect: 'https://mint.example/.well-known/lnurlp/alice'},
    {input: '_@mint.example', expect: 'https://mint.example/.well-known/lnurlp/_', why: 'LUD-16 bare-domain reserved name'},
    {input: 'mint@localhost:8000', expect: 'http://localhost:8000/.well-known/lnurlp/mint'},
    {input: lnurlEncode('https://mint.example/.well-known/lnurlp/mint'), expect: 'https://mint.example/.well-known/lnurlp/mint'},
    {input: 'https://mint.example/w?k1=' + K1_A, expect: null, why: 'a raw URL is not a mint address'},
    {input: '', expect: null}
  ],
  note: [
    {input: 'lnurlw://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A},
    {input: 'https://mint.example/w?k1=' + K1_A.toUpperCase(), expect: 'https://mint.example/w?k1=' + K1_A.toUpperCase(), why: 'resolution preserves the URL; k1 casing is normalised on extraction, not here'},
    {input: 'https://mint.example/w', expect: null, why: 'no k1 - not a note'},
    {input: 'https://mint.example/w?k1=short', expect: null, why: 'k1 must be 32 bytes hex'},
    {input: 'https://mint.example/w?k1=' + 'z'.repeat(64), expect: null, why: 'k1 must be hex'},
    {input: lnurlEncode('https://mint.example/w?k1=' + K1_A), expect: 'https://mint.example/w?k1=' + K1_A}
  ],
  mintAddressUrl: [
    {payUrl: 'https://mint.example/.well-known/lnurlp/mint', expect: 'https://mint.example/.well-known/lnurlw/mint'},
    {payUrl: 'https://mint.example/.well-known/lnurlp/_', expect: 'https://mint.example/.well-known/lnurlw/_'},
    {payUrl: 'https://mint.example/p', expect: null, why: 'not at the conventional well-known path'}
  ],
  lightningAddressUsername: [
    {payUrl: 'https://mint.example/.well-known/lnurlp/mint', expect: 'mint'},
    {payUrl: 'https://mint.example/.well-known/lnurlp/_', expect: '_'},
    {payUrl: 'https://mint.example/p', expect: null}
  ]
}

// ---- vectors: note URLs --------------------------------------------------

const noteUrl = {
  version: VERSION,
  spec: SPEC,
  description:
    'A note is an ordinary LUD-03 withdrawRequest URL whose k1 IS the asset. `amount` alongside it is only a claim by whoever encoded the note - the authoritative value is always maxWithdrawable from an informational GET. `sig` is the optional offline-verification signature.',
  parse: [
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000',
      k1: K1_A,
      declaredAmountMsat: 21000,
      signature: null
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A.toUpperCase(),
      k1: K1_A,
      declaredAmountMsat: null,
      signature: null,
      why: 'k1 is bytes, not text: normalise to lowercase so the same secret in two casings is one note'
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000&sig=' + 'ab'.repeat(65),
      k1: K1_A,
      declaredAmountMsat: 21000,
      signature: 'ab'.repeat(65)
    },
    {
      url: 'https://mint.example/w',
      k1: null,
      declaredAmountMsat: null,
      signature: null
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=notanumber',
      k1: K1_A,
      declaredAmountMsat: null,
      signature: null,
      why: 'an unparseable declared amount is absent, not zero'
    },
    {
      url: 'not a url',
      k1: null,
      declaredAmountMsat: null,
      signature: null
    }
  ],
  build: [
    {
      withdrawLink: 'lnurlw://mint.example/w',
      k1: K1_A,
      amountMsat: 21000,
      expect: 'https://mint.example/w?k1=' + K1_A + '&amount=21000'
    },
    {
      withdrawLink: 'https://mint.example/w',
      k1: K1_A.toUpperCase(),
      amountMsat: null,
      expect: 'https://mint.example/w?k1=' + K1_A,
      why: 'omit amount entirely when the real value is not known yet; some SERVICEs validate it strictly rather than ignoring it'
    },
    {
      withdrawLink: 'lnurlw://localhost:8000/w',
      k1: K1_C,
      amountMsat: 1000,
      expect: 'http://localhost:8000/w?k1=' + K1_C + '&amount=1000'
    }
  ],
  withNewK1: [
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000&sig=' + 'ab'.repeat(65),
      k1: K1_B,
      amountMsat: 5000,
      signature: null,
      expect: 'https://mint.example/w?k1=' + K1_B + '&amount=5000',
      why: 'a stale signature must be dropped: it no longer matches the new secret'
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000',
      k1: K1_B,
      amountMsat: 5000,
      signature: 'cd'.repeat(65),
      expect: 'https://mint.example/w?k1=' + K1_B + '&amount=5000&sig=' + 'cd'.repeat(65)
    }
  ],
  withoutK1: [
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000&sig=' + 'ab'.repeat(65),
      amountMsat: 5000,
      signature: null,
      expect: 'https://mint.example/w?amount=5000',
      why: 'a device-backed note keeps the URL template but never the secret'
    }
  ]
}

// ---- vectors: mint fees --------------------------------------------------

const meta = entries => JSON.stringify(entries)

// The normative formula, straight from the LUD-25 text:
//   note value = amount - base_fee_msat - amount * fee_percent_ppm / 1_000_000
// floored, since msat are integers, and never negative.
//
// The proportional term is split rather than computed as (g * ppm) / 1e6,
// because that product overflows 64-bit unsigned at realistic amounts: 21M
// BTC is 2.1e15 msat, and 2.1e15 * 999_999 is about 2.1e21, well past
// 1.8e19. Splitting keeps both halves small: the quotient half reaches at
// most 2.1e15, the remainder half at most 1e12. Implementations in Go and
// Rust that multiply naively pass every small vector and then silently
// mangle a large one, which is exactly what the large case below catches.
const proportional = (g, ppm) =>
  Math.floor(g / 1e6) * ppm + Math.floor(((g % 1e6) * ppm) / 1e6)

const applyFee = (g, f) => Math.max(0, g - f.baseFeeMsat - proportional(g, f.feePpm))

// The inverse: the SMALLEST gross amount that nets `net` after the fee.
//
// applyFee is non-decreasing in gross with per-msat steps of 0 or 1 (the
// proportional term grows by at most 1 per msat, since ppm < 1_000_000), so
// the minimal such gross exists and binary search finds it exactly. The
// obvious alternative - estimate linearly, then walk one msat at a time -
// is what the reference wallet does, and it is both unbounded and wrong at
// the edge: for a 99.9999% fee the walk is around a million steps, so any
// sane guard trips and returns a non-minimal answer. A SERVICE can advertise
// such a fee, so the walk is a hostile-input hazard as well as an accuracy
// one. Binary search has neither problem.
const grossUpFee = (net, f) => {
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

const FEE_A = {baseFeeMsat: 1000, feePpm: 2000}
const FEE_FREE = {baseFeeMsat: 0, feePpm: 0}
const FEE_FLAT = {baseFeeMsat: 2000, feePpm: 0}
const FEE_TINY = {baseFeeMsat: 0, feePpm: 1}
const FEE_PCT = {baseFeeMsat: 0, feePpm: 10000}
const FEE_HOSTILE = {baseFeeMsat: 3, feePpm: 999999}
// the whole-sat trap: a gross where msat-exact and round-to-sat fees differ
const FEE_SAT_TRAP = {baseFeeMsat: 1000, feePpm: 1000}

const applyCase = (grossMsat, fee, why) => ({
  grossMsat,
  fee,
  expect: applyFee(grossMsat, fee),
  why
})

const grossUpCase = (netMsat, fee, why) => ({
  netMsat,
  fee,
  expect: grossUpFee(netMsat, fee),
  why
})

const fees = {
  version: VERSION,
  spec: SPEC,
  description:
    'Optional mint fees (LUD-25). A SERVICE advertises what it withholds on minting via an extra ["text/plain", "Mint fees: <base_fee_msat>,<fee_percent_ppm>"] entry in the payRequest metadata, so a WALLET can warn the payer that the note it ends up holding is worth less than the invoice it paid. A SERVICE that omits the entry is fee-free, not unknown.',
  formula: {
    apply: 'max(0, gross - base_fee_msat - floor(gross * fee_percent_ppm / 1_000_000))',
    grossUp: 'the smallest gross for which apply(gross) == net',
    overflowWarning:
      'compute the proportional term as floor(gross/1e6)*ppm + floor((gross%1e6)*ppm/1e6). A direct gross*ppm overflows 64-bit unsigned at realistic amounts (2.1e15 msat is 21M BTC; times 999999 ppm is ~2.1e21, past the 1.8e19 limit).',
    minimality:
      'grossUp must return the exact minimum. A linear estimate followed by a one-msat walk is unbounded for a near-100% fee - about a million steps at 999999 ppm - so any guard on that walk yields a non-minimal answer on input a hostile SERVICE can choose. Use binary search: apply is non-decreasing with steps of 0 or 1.'
  },
  parse: [
    {
      metadata: meta([['text/plain', 'a mint'], ['text/plain', 'Mint fees: 1000,2000']]),
      expect: FEE_A
    },
    {
      metadata: meta([['text/plain', 'Mint fees:1000,2000']]),
      expect: FEE_A,
      why: 'whitespace after the colon is optional'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000 , 2000 ']]),
      expect: FEE_A
    },
    {
      metadata: meta([['text/plain', 'a mint']]),
      expect: null,
      why: 'no fee entry - read as fee-free'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,0']]),
      expect: null,
      why: 'an explicit zero fee is identical to no fee; callers should not have to special-case it'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,1000000']]),
      expect: null,
      why: 'a fee of 100% or more can never net anything, and would make a naive gross-up walk hang - refuse it as no valid entry'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,2000000']]),
      expect: null,
      why: 'above 100%'
    },
    {
      metadata: meta([['text/identifier', 'Mint fees: 1000,2000']]),
      expect: null,
      why: 'only text/plain entries carry the fee advertisement'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: -1,2000']]),
      expect: null,
      why: 'negative components are not a valid advertisement'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000']]),
      expect: null,
      why: 'both components are required'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000,2000,3000']]),
      expect: null,
      why: 'exactly two components'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 99999999999999999999,2000']]),
      expect: null,
      why: 'digits past 2^53 lose integer precision in most languages - refuse rather than estimate with a mangled fee'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000,99999999999999999999']]),
      expect: null,
      why: 'the same for the ppm component (a ppm this large fails the 100% rule regardless)'
    },
    {metadata: 'not json', expect: null},
    {metadata: '{}', expect: null, why: 'metadata must be an array'},
    {metadata: '[]', expect: null},
    {
      metadata: meta([['text/plain', 'Mint fees: 500,0']]),
      expect: {baseFeeMsat: 500, feePpm: 0}
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,5000']]),
      expect: {baseFeeMsat: 0, feePpm: 5000}
    },
    {
      metadata: meta([
        ['text/plain', 'Mint fees: 500,0'],
        ['text/plain', 'Mint fees: 1000,2000']
      ]),
      expect: {baseFeeMsat: 500, feePpm: 0},
      why: 'the first valid advertisement wins'
    }
  ],
  apply: [
    applyCase(100000, FEE_A),
    applyCase(100000, FEE_FREE),
    applyCase(1000, FEE_FLAT, 'never negative'),
    applyCase(1001, FEE_TINY, 'the proportional part floors to zero'),
    applyCase(2000000, FEE_TINY),
    applyCase(0, {baseFeeMsat: 0, feePpm: 1000}),
    applyCase(21000, FEE_PCT),
    applyCase(
      2100000000000000,
      FEE_HOSTILE,
      '21M BTC in msat at a 99.9999% fee: a naive gross*ppm multiply overflows 64-bit unsigned here and produces a wrong answer'
    ),
    applyCase(
      2100000000000000,
      FEE_TINY,
      'same magnitude, ordinary fee - still past the naive-multiply limit'
    ),
    applyCase(
      500000,
      FEE_SAT_TRAP,
      'nets 498500 msat. A fee implementation that works in whole sats rounds the withheld fee up to 2000 msat here and mints a 498000 msat note - half a sat short of conformant. The formula is msat-exact; a minted note is worth apply(gross) to the msat'
    )
  ],
  grossUp: [
    grossUpCase(98800, FEE_A),
    grossUpCase(100000, FEE_FREE),
    grossUpCase(1, {baseFeeMsat: 1000, feePpm: 0}),
    grossUpCase(10000, FEE_PCT),
    grossUpCase(21000, FEE_A),
    grossUpCase(
      1,
      FEE_HOSTILE,
      'a 99.9999% fee: the answer is far below the linear estimate, so an estimate-then-walk implementation returns a non-minimal gross unless its guard is around a million steps'
    ),
    grossUpCase(1000000, FEE_HOSTILE),
    grossUpCase(0, FEE_A, 'nothing to gross up')
  ],
  grossUpRoundTrip: {
    note: 'for every fee and net amount below, apply(grossUp(net, fee), fee) must equal net exactly, and apply(grossUp(net, fee) - 1, fee) must be strictly less than net - that is, the result is the true minimum, not merely sufficient',
    fees: [FEE_FREE, {baseFeeMsat: 1000, feePpm: 0}, {baseFeeMsat: 0, feePpm: 2000}, FEE_A, FEE_HOSTILE, FEE_TINY],
    netAmountsMsat: [1, 2, 999, 1000, 1001, 21000, 100000, 1000000, 123456789]
  },
  formatPercent: [
    {ppm: 2000, expect: '0.2'},
    {ppm: 10000, expect: '1'},
    {ppm: 1, expect: '0.0001'},
    {ppm: 0, expect: '0'},
    {ppm: 999999, expect: '99.9999'},
    {ppm: 12345, expect: '1.2345'}
  ]
}

// ---- vectors: bolt11 -----------------------------------------------------

const bolt11 = {
  version: VERSION,
  spec: 'BOLT-11',
  description:
    'Only what a WALLET needs to bind a SERVICE response to the payment it asked for: the amount out of the human-readable part, a loose shape check, and case-insensitive equality. No full TLV decode is required.',
  decodeAmountMsat: [
    {pr: 'lnbc210n1pjqrstuvwxyz', expect: 21000},
    {pr: 'lnbc1u1pjqrstuvwxyz', expect: 100000},
    {pr: 'lnbc1m1pjqrstuvwxyz', expect: 100000000},
    {pr: 'lnbc10p1pjqrstuvwxyz', expect: 1},
    {pr: 'lnbc1pjqrstuvwxyz', expect: null, why: 'amountless invoice'},
    {pr: 'lntb210n1pjqrstuvwxyz', expect: 21000, why: 'testnet prefix'},
    {pr: 'lnbcrt210n1pjqrstuvwxyz', expect: 21000, why: 'regtest prefix'},
    {pr: 'LNBC210N1PJQRSTUVWXYZ', expect: 21000, why: 'bech32 is case-insensitive'},
    {pr: 'lnbc1p1pjqrstuvwxyz', expect: null, why: '1 pico-BTC is 0.1 msat - not an integer number of msat'},
    {pr: 'not an invoice', expect: null},
    {pr: '', expect: null},
    {pr: 'lnurl1dp68gurn8ghj7', expect: null, why: 'an LNURL is not an invoice'}
  ],
  isInvoice: [
    {pr: 'lnbc210n1pjqrstuvwxyz', expect: true},
    {pr: 'lnbc1pjqrstuvwxyz', expect: true},
    {pr: 'lntb1pjqrstuvwxyz', expect: true},
    {pr: 'lnurl1dp68gurn8ghj7', expect: false, why: 'must not match a bech32 LNURL'},
    {pr: 'lnbc', expect: false},
    {pr: '', expect: false}
  ],
  sameInvoice: [
    {a: 'lnbc210n1pjq', b: 'LNBC210N1PJQ', expect: true},
    {a: ' lnbc210n1pjq ', b: 'lnbc210n1pjq', expect: true},
    {a: 'lnbc210n1pjq', b: 'lnbc220n1pjq', expect: false}
  ],
  isPreimage: [
    {value: K1_A, expect: true},
    {value: K1_A.toUpperCase(), expect: true},
    {value: 'z'.repeat(64), expect: false},
    {value: 'ab'.repeat(31), expect: false, why: '31 bytes'},
    {value: '', expect: false}
  ]
}

// ---- vectors: callback requests ------------------------------------------

const CB = 'https://mint.example/w/cb'

const callbacks = {
  version: VERSION,
  spec: SPEC,
  description:
    'The mutating callback. Every operation is a GET on the `callback` from the note\'s own withdrawRequest response. `h`/`h2` are hashes of secrets the WALLET generates - never the SERVICE - so the SERVICE never sees, generates or persists a replacement note\'s spend secret. Query parameter ORDER is not significant; the expected query below is one valid serialisation and implementations should compare parsed parameters, honouring repeats.',
  cases: [
    {
      name: 'melt',
      op: 'melt',
      callback: CB,
      params: {k1: [K1_A], pr: 'lnbc210n1pjqrstuvwxyz'},
      expectQuery: [['k1', K1_A], ['pr', 'lnbc210n1pjqrstuvwxyz']]
    },
    {
      name: 'rotate',
      op: 'rotate',
      callback: CB,
      params: {k1: [K1_A], h: noteId(K1_B)},
      expectQuery: [['k1', K1_A], ['h', noteId(K1_B)]]
    },
    {
      name: 'split one note',
      op: 'split',
      callback: CB,
      params: {k1: [K1_A], amountMsat: 5000, h: noteId(K1_B), h2: noteId(K1_C)},
      expectQuery: [['k1', K1_A], ['amount', '5000'], ['h', noteId(K1_B)], ['h2', noteId(K1_C)]]
    },
    {
      name: 'split several notes at once',
      op: 'split',
      callback: CB,
      params: {k1: [K1_A, K1_B], amountMsat: 5000, h: noteId(K1_C), h2: noteId(K1_A)},
      expectQuery: [['k1', K1_A], ['k1', K1_B], ['amount', '5000'], ['h', noteId(K1_C)], ['h2', noteId(K1_A)]],
      why: 'LUD-25 allows one or many k1 on a split - no prior merge required'
    },
    {
      name: 'merge',
      op: 'merge',
      callback: CB,
      params: {k1: [K1_A, K1_B, K1_C], h: noteId(K1_A)},
      expectQuery: [['k1', K1_A], ['k1', K1_B], ['k1', K1_C], ['h', noteId(K1_A)]],
      why: 'k1 repeats rather than being comma-joined: append, never set'
    },
    {
      name: 'callback that already carries query parameters',
      op: 'rotate',
      callback: 'https://mint.example/w/cb?token=abc',
      params: {k1: [K1_A], h: noteId(K1_B)},
      expectQuery: [['token', 'abc'], ['k1', K1_A], ['h', noteId(K1_B)]],
      why: 'existing parameters must be preserved, not overwritten'
    }
  ],
  rejected: [
    {
      name: 'melt with several k1',
      op: 'melt',
      params: {k1: [K1_A, K1_B], pr: 'lnbc210n1pjq'},
      why: 'LUD-25: pr MUST NOT be combined with multiple k1. Merge first, then melt.'
    },
    {
      name: 'melt with an amount',
      op: 'melt',
      params: {k1: [K1_A], pr: 'lnbc210n1pjq', amountMsat: 5000},
      why: 'LUD-25: pr MUST NOT be combined with amount'
    },
    {
      name: 'rotate without h',
      op: 'rotate',
      params: {k1: [K1_A]},
      why: 'h is required whenever pr is absent - a SERVICE must never generate the secret'
    },
    {
      name: 'split without h2',
      op: 'split',
      params: {k1: [K1_A], amountMsat: 5000, h: noteId(K1_B)},
      why: 'h2 is required whenever amount is present'
    },
    {
      name: 'no k1 at all',
      op: 'rotate',
      params: {k1: [], h: noteId(K1_B)},
      why: 'nothing to burn'
    }
  ]
}

// ---- vectors: responses --------------------------------------------------

const responses = {
  version: VERSION,
  spec: SPEC,
  description:
    'Classifying a SERVICE response. The distinction that matters for funds is definitive-rejection versus ambiguous-outcome: a parsed {"status":"ERROR"} means the request was processed and refused, while a transport failure, an unparseable body, or a 200 that does not confirm means the mutation MAY have landed - and for rotate/split/merge the WALLET-generated secrets are then the only copy of the outputs, so they must ride the error rather than be discarded.',
  outcomes: {
    ok: 'the operation is confirmed',
    pending: 'this k1 has another operation in flight (a melt); retry shortly',
    spent: 'the SERVICE is authoritative that the note is already burned; a holder may lock it as spent',
    unknown: 'the SERVICE does not recognise this note; surface it, do not silently lock it',
    error: 'definitively rejected for some other stated reason',
    ambiguous: 'the outcome is not known - preserve any fresh secrets'
  },
  cases: [
    {name: 'plain success', http: 200, body: {status: 'OK'}, expect: 'ok'},
    {
      name: 'success with an offline-verification signature',
      http: 200,
      body: {status: 'OK', sig: 'ab'.repeat(65)},
      expect: 'ok',
      signature: 'ab'.repeat(65)
    },
    {
      name: 'split success with both signatures',
      http: 200,
      body: {status: 'OK', sig: 'ab'.repeat(65), sig2: 'cd'.repeat(65)},
      expect: 'ok',
      signature: 'ab'.repeat(65),
      changeSignature: 'cd'.repeat(65)
    },
    {
      name: 'melt success with a LUD-21 style proof',
      http: 200,
      body: {status: 'OK', pr: 'lnbc210n1pjq', verify: 'https://mint.example/verify/abc'},
      expect: 'ok',
      why: 'OK on a melt means the payment is in flight, NOT that the note is confirmed spent'
    },
    {
      name: 'pending',
      http: 200,
      body: {status: 'ERROR', reason: 'pending'},
      expect: 'pending',
      why: 'the exact reason string LUD-25 specifies for a k1 mid-melt'
    },
    {
      name: 'already spent',
      http: 200,
      body: {status: 'ERROR', reason: 'Note already spent.'},
      expect: 'spent'
    },
    {
      name: 'unknown note',
      http: 200,
      body: {status: 'ERROR', reason: 'Unknown note.'},
      expect: 'unknown'
    },
    {
      name: 'not found wording',
      http: 200,
      body: {status: 'ERROR', reason: 'k1 not found'},
      expect: 'unknown'
    },
    {
      name: 'ambiguous callback wording is treated as spent',
      http: 200,
      body: {status: 'ERROR', reason: 'Invalid or already spent k1.'},
      expect: 'spent',
      why: 'an atomic multi-k1 callback cannot say which k1 failed; the spent reading is the safe one'
    },
    {
      name: 'some other refusal',
      http: 200,
      body: {status: 'ERROR', reason: 'This mint is sunsetting - splits are disabled.'},
      expect: 'error'
    },
    {
      name: 'error with no reason',
      http: 200,
      body: {status: 'ERROR'},
      expect: 'error'
    },
    {
      name: '200 with neither OK nor ERROR',
      http: 200,
      body: {something: 'else'},
      expect: 'ambiguous',
      why: 'the mutation was not confirmed and may still have landed'
    },
    {
      name: 'unparseable body',
      http: 200,
      bodyRaw: 'not json at all',
      expect: 'ambiguous'
    },
    {
      name: 'server error',
      http: 500,
      bodyRaw: 'upstream failure',
      expect: 'ambiguous'
    },
    {
      name: 'transport failure',
      transportError: true,
      expect: 'ambiguous'
    },
    {
      name: 'timeout',
      timeout: true,
      expect: 'ambiguous'
    }
  ]
}

// ---- vectors: withdrawRequest info ---------------------------------------

const withdrawInfo = {
  version: VERSION,
  spec: 'LUD-03, LUD-25',
  description:
    'The informational GET on a note. Never burns, rotates or alters it. maxWithdrawable is the ONLY authoritative statement of what a note is worth - the URL\'s own `amount` is a claim and the SERVICE ignores it here. The response\'s k1 MUST be the bearer secret itself, never a derived or opaque id.',
  queriedUrl: 'https://mint.example/w?k1=' + K1_A + '&amount=99999&sig=' + 'ab'.repeat(65),
  requestMustNotSend: ['sig'],
  requestMustSendUnchanged: ['k1'],
  accepted: [
    {
      name: 'minimal valid',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, minWithdrawable: 0, maxWithdrawable: 21000},
      maxWithdrawable: 21000
    },
    {
      name: 'with a mint pubkey for offline verification',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, minWithdrawable: 0, maxWithdrawable: 21000, mintPubkey: MINT_PUB},
      maxWithdrawable: 21000
    },
    {
      name: 'minWithdrawable omitted',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000},
      maxWithdrawable: 21000
    },
    {
      name: 'echoed k1 in a different casing',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A.toUpperCase(), maxWithdrawable: 21000},
      maxWithdrawable: 21000,
      why: 'k1 is bytes; casing carries no meaning'
    },
    {
      name: 'zero value note',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 0},
      maxWithdrawable: 0
    }
  ],
  rejected: [
    {name: 'wrong tag', body: {tag: 'payRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000}},
    {name: 'no callback', body: {tag: 'withdrawRequest', k1: K1_A, maxWithdrawable: 21000}},
    {name: 'no k1', body: {tag: 'withdrawRequest', callback: CB, maxWithdrawable: 21000}},
    {name: 'no maxWithdrawable', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A}},
    {name: 'maxWithdrawable is a string', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: '21000'}},
    {name: 'negative maxWithdrawable', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: -1}},
    {
      name: 'fractional maxWithdrawable',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000.5},
      why: 'msat are integers'
    },
    {
      name: 'maxWithdrawable past 2^63',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 2 ** 64},
      why: 'no common integer type holds it and a double rounds it - refuse rather than guess the amount'
    },
    {name: 'minWithdrawable above maxWithdrawable', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, minWithdrawable: 30000, maxWithdrawable: 21000}},
    {
      name: 'echoed a different k1 than queried',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_B, maxWithdrawable: 21000},
      why: 'spec MUST: the response k1 is the bearer secret itself. A SERVICE returning something else is non-compliant, or the note was rotated by someone else'
    }
  ]
}

// ---- vectors: payRequest -------------------------------------------------

const payRequest = {
  version: VERSION,
  spec: 'LUD-06, LUD-11, LUD-16, LUD-21, LUD-25',
  description:
    'Minting. A LUD-06 payRequest MAY advertise `withdrawLink`, the raw LUD-17 URL of the withdraw endpoint: the payment preimage of its paid invoice becomes a valid k1 there. A WALLET MUST rotate immediately after claiming, because the SERVICE necessarily saw that preimage.',
  accepted: [
    {
      name: 'a minting payRequest',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint'], ['text/identifier', 'mint@mint.example']]),
        withdrawLink: 'lnurlw://mint.example/w'
      },
      withdrawLink: 'lnurlw://mint.example/w',
      mintFee: null
    },
    {
      name: 'withdrawLink in plain URL form',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint'], ['text/identifier', 'mint@mint.example']]),
        withdrawLink: 'https://mint.example/w'
      },
      withdrawLink: 'https://mint.example/w',
      mintFee: null,
      why: 'LUD-25 says a raw, non-bech32 URL "as described in LUD-17", and LUD-17 describes both the lnurlw:// scheme and the plain URL it stands for. lnurl-mint, and the spec diagram, use this form; moneyer uses lnurlw://. A WALLET MUST accept either, unchanged, and resolve it through the same LUD-17 rule as any other input'
    },
    {
      name: 'withdrawLink on an onion service',
      body: {
        tag: 'payRequest',
        callback: 'http://mintmintmintmintmintmintmintmintmintmintmintmintmintmi.onion/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint']]),
        withdrawLink: 'lnurlw://mintmintmintmintmintmintmintmintmintmintmintmintmintmi.onion/w'
      },
      withdrawLink: 'lnurlw://mintmintmintmintmintmintmintmintmintmintmintmintmintmi.onion/w',
      mintFee: null,
      why: 'the parser passes the link through; resolution to http:// happens when a note is built from it (see note-url.json build)'
    },
    {
      name: 'with an advertised fee',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint'], ['text/plain', 'Mint fees: 1000,2000']]),
        withdrawLink: 'lnurlw://mint.example/w'
      },
      withdrawLink: 'lnurlw://mint.example/w',
      mintFee: {baseFeeMsat: 1000, feePpm: 2000}
    },
    {
      name: 'an ordinary payRequest with no minting',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'not a mint']])
      },
      withdrawLink: null,
      mintFee: null
    }
  ],
  rejected: [
    {name: 'wrong tag', body: {tag: 'withdrawRequest', callback: 'https://mint.example/p/cb'}},
    {name: 'no callback', body: {tag: 'payRequest', minSendable: 1000, maxSendable: 1000}}
  ],
  invoice: {
    accepted: [
      {
        name: 'invoice for the amount requested',
        requestedMsat: 21000,
        body: {pr: 'lnbc210n1pjqrstuvwxyz'},
        disposable: true,
        why: 'LUD-11: disposable absent MUST be read as true'
      },
      {
        name: 'explicitly reusable address',
        requestedMsat: 21000,
        body: {pr: 'lnbc210n1pjqrstuvwxyz', disposable: false},
        disposable: false
      },
      {
        name: 'with a LUD-21 verify url',
        requestedMsat: 21000,
        body: {pr: 'lnbc210n1pjqrstuvwxyz', verify: 'https://mint.example/verify/abc'},
        disposable: true,
        verify: 'https://mint.example/verify/abc'
      },
      {
        name: 'amountless invoice passes through',
        requestedMsat: 21000,
        body: {pr: 'lnbc1pjqrstuvwxyz'},
        disposable: true,
        why: 'nothing to check it against here; the SERVICE judges it later'
      }
    ],
    rejected: [
      {
        name: 'invoice for a different amount',
        requestedMsat: 21000,
        body: {pr: 'lnbc220n1pjqrstuvwxyz'},
        why: 'a SERVICE answering with an invoice for another amount is broken or hostile'
      },
      {name: 'no invoice', requestedMsat: 21000, body: {}}
    ]
  },
  verify: {
    accepted: [
      {
        name: 'settled, preimage disclosed',
        body: {status: 'OK', settled: true, preimage: K1_A, pr: 'lnbc210n1pjq'},
        settled: true,
        preimage: K1_A,
        why: 'for LNURLcash this preimage IS the bearer secret - rotate immediately, and never treat verify as having closed the exposure'
      },
      {
        name: 'settled, preimage withheld',
        body: {status: 'OK', settled: true, preimage: null, pr: 'lnbc210n1pjq'},
        settled: true,
        preimage: null
      },
      {
        name: 'not yet settled',
        body: {status: 'OK', settled: false, preimage: null, pr: 'lnbc210n1pjq'},
        settled: false,
        preimage: null
      }
    ],
    rejected: [
      {name: 'no settled field', body: {status: 'OK', pr: 'lnbc210n1pjq'}},
      {name: 'settled is a string', body: {status: 'OK', settled: 'true', pr: 'lnbc210n1pjq'}},
      {name: 'no pr to bind the result to', body: {status: 'OK', settled: true}}
    ]
  }
}

// ---- vectors: note lifecycle ---------------------------------------------

const lifecycle = {
  version: VERSION,
  spec: SPEC,
  description:
    'The state machine a holder must implement, and the transitions that are fund-critical. These are behavioural requirements rather than pure functions, so they are expressed as scenarios the mock mint can drive.',
  states: ['pending', 'confirmed', 'spent'],
  scenarios: [
    {
      name: 'mint then rotate',
      steps: ['pay the payRequest invoice', 'the preimage is the k1', 'rotate immediately'],
      requirement:
        'a WALLET MUST rotate straight after claiming a minted note: the SERVICE generated that preimage and is a permanent prior holder of it. Anyone who saw the unpaid invoice can poll LUD-21 verify and race for it.'
    },
    {
      name: 'melt is not settlement',
      steps: ['melt', 'receive OK', 'observe the note still reserved'],
      requirement:
        'OK on a melt means the payment is in flight. The note MUST NOT be treated as confirmed spent until settlement, and a failed payment restores it to outstanding. A holder locking it optimistically must be able to unlock on a confirmed failure.'
    },
    {
      name: 'pending lockout',
      steps: ['melt k1', 'attempt a rotate on the same k1 before settlement'],
      requirement: 'the second call fails with reason "pending" and MUST be retried, never read as spent'
    },
    {
      name: 'ambiguous rotate',
      steps: ['rotate', 'the connection drops before a response'],
      requirement:
        'the fresh secret MUST be preserved, because the SERVICE may have minted it. Probe the input k1 with an informational GET: still live means the request never landed and the secret can be dropped; spent or unknown means the burn landed and the preserved secret is the only remaining money; a failed probe means keep everything.'
    },
    {
      name: 'ambiguous split',
      steps: ['split', 'the response is unparseable'],
      requirement: 'BOTH fresh secrets must be preserved, in output order: the split-off note first, then the change'
    },
    {
      name: 'a retried mutation',
      steps: [
        'rotate',
        'the connection drops after the SERVICE applied it',
        'the HTTP stack silently resends the identical request'
      ],
      requirement:
        'a WALLET MUST ensure its HTTP stack does not retry a mutating callback. Every mutation is a GET, HTTP treats GET as idempotent, and an LNURLcash mutation is not: the first attempt burns the input. A retried mutation is answered "invalid or already spent k1", which classifies as a DEFINITIVE rejection - so the WALLET concludes nothing happened and discards the fresh secret that was the only copy of the note the SERVICE just minted. This is not hypothetical: it was found in two independent implementations during this suite\'s own development. Java\'s java.net.http.HttpClient retries idempotent GETs on a mid-flight connection reset and cannot be configured out of it (use a client that can); Go\'s net/http retries when the request went over a REUSED connection, and a client with no explicit Transport shares a process-wide pool, so the behaviour depends on what unrelated code did first (disable keep-alives). Browsers retry on a stale pooled connection for the same reason. Test this deliberately: the mock mint\'s dropAfterMutation mode reproduces it.'
    },
    {
      name: 'settle a merge or split output',
      steps: ['merge', 'informational GET on the new note', 'rotate'],
      requirement:
        'neither response carries the output amount, and a fee-charging SERVICE may have deducted from a split\'s change or refunded into a merge\'s result. The authoritative value comes from the informational GET, and that GET puts k1 on the wire, so a rotate should follow.'
    },
    {
      name: 'a duplicated k1',
      steps: ['merge with the same k1 given twice', 'observe the refusal'],
      requirement:
        'a SERVICE MUST refuse a mutation that names the same k1 more than once, atomically and before burning anything - counting one note\'s value twice into a merge or split output creates money from nothing. The reference mint refuses (inside its transaction, the second burn of a duplicate finds the first already spent it, and everything rolls back); a SERVICE that instead deduplicates and proceeds at the note\'s true value conserves funds only by accident, and the grader marks it with a warning rather than a pass.'
    },
    {
      name: 'an output hash already in use',
      steps: [
        'rotate with h set to the id of an existing note, or to the payment hash of an invoice the SERVICE issued',
        'observe the refusal'
      ],
      requirement:
        'a SERVICE MUST refuse h/h2 values that collide with any note id it has ever minted or any invoice payment hash it has ever issued, before burning anything. Minting over an existing id hands the output to whoever already knows that id\'s preimage - for a pending mint invoice that is its future payer, and for a burned note it is every previous holder - or it bricks a paid mint whose settlement can no longer register under that key. A WALLET drawing fresh 32-byte secrets never collides honestly, so a collision is always adversarial. Refuse with the same reason as any dead k1: which table the id collided with is an oracle nobody is owed.'
    },
    {
      name: 'a split into the same hash twice',
      steps: ['split with h2 equal to h', 'observe the refusal'],
      requirement:
        'a SERVICE MUST refuse a split whose two output hashes are equal - one id cannot carry two notes, so accepting it either destroys the change or double-mints a single id.'
    }
  ]
}

// ---- vectors: threat suite -------------------------------------------------

// Not conformance data in the usual sense: the transport/exposure scorecard
// from the LUD-25 design debate, written down as scenarios so candidate spec
// changes are measured against the same attacks instead of argued about in
// the abstract. NON-NORMATIVE - every option but A is a proposal, and rows
// pinning today's vulnerable behavior exist to be INVERTED by the PR that
// lands the named option. The executable twin of this file is lnurl-mint's
// tests/test_bearer_threat_suite_poc.py (dni/lnurl-mint#22).

// T10's merge-budget arithmetic, computed against the same example callback
// the callback vectors use, so the scenario's numbers recompute rather than
// being asserted.
const URL_BUDGET = 2000 // the practical GET budget LUD-12 itself notes
const ENCRYPTED_K1_BYTES = 33 + 12 + 32 + 16 // ephemeral pubkey + nonce + ciphertext + tag
const ENCRYPTED_K1_B64_CHARS = 4 * Math.ceil(ENCRYPTED_K1_BYTES / 3)
const mergeUrl = (param, secretChars, n) =>
  CB +
  '?' +
  Array.from({length: n}, () => `${param}=${'a'.repeat(secretChars)}`).join('&') +
  '&h=' +
  'a'.repeat(64)
const mergeCapacity = (param, secretChars) => {
  let n = 0
  while (mergeUrl(param, secretChars, n + 1).length <= URL_BUDGET) n++
  return n
}

const threatSuite = {
  version: VERSION,
  spec: SPEC,
  description:
    'The transport/exposure scorecard from the LUD-25 design debate: candidate spec options measured against a fixed set of attacks, so proposed changes are argued against the same scenarios instead of in the abstract. NON-NORMATIVE - option A is the current draft and every other option is a proposal, marked as such below; only rows with status "pins-current" describe behavior the draft already requires, and rows pinning today\'s vulnerable behavior exist to be INVERTED by the PR landing the named option. The executable twin of this file is lnurl-mint\'s tests/test_bearer_threat_suite_poc.py (dni/lnurl-mint#22).',
  options: {
    A: {name: 'status quo', status: 'current-draft', summary: 'lnurl/luds#301 as drafted'},
    B: {
      name: 'comment-secret',
      status: 'proposal',
      summary:
        'A + a secret the WALLET attaches to the payRequest (LUD-12 comment), encrypted to the mint; the note\'s k1 becomes "<secret>:<preimage>" and the public LUD-21 preimage alone no longer redeems'
    },
    C: {
      name: '?p= everywhere',
      status: 'proposal',
      summary: 'every k1 replaced in transport by that k1 encrypted to the mint'
    },
    D: {
      name: 'hash-keyed informational GET',
      status: 'proposal',
      summary: 'A + poll /w by sha256(k1), never k1'
    },
    E: {name: 'blinded signatures', status: 'proposal', summary: 'the chaumian model'},
    F: {name: 'B + D', status: 'proposal', summary: 'comment-secret plus the hash-keyed informational GET'},
    G: {
      name: 'locked notes',
      status: 'proposal',
      summary:
        'a second asset class, not a bearer variant: redemption requires an LUD-04 signature from the LUD-05/LUD-13 linkingKey registered at mint/rotate time, over the FULL redemption request (k1, h/h2, amount/pr), so logged signatures are not replayable. Scored separately per scenario as lockedNotes, because the trades differ by note type'
    }
  },
  policy: {
    redGreen:
      'Scenarios asserting today\'s vulnerable behavior are pins that must be INVERTED by the PR landing the named option, mirroring the INVERTS WHEN policy in this file\'s executable companion, lnurl-mint\'s tests/test_bearer_threat_suite_poc.py (dni/lnurl-mint#22): that PR flips the pin red and forces the assertion to be rewritten against the fixed behavior. Controls (T4, T5) assert behavior that must never change.',
    coreTheorem:
      'Re-encrypting a bearer credential to the party that redeems it never shrinks its exposure set: the mint honors the ciphertext, so the ciphertext IS the note. The only encryption that helps is encrypting to the holder, which kills bearer-ness - option G takes that trade deliberately, via signatures rather than ciphertext.',
    seedRecoverableNotes:
      'A WALLET deriving note secrets deterministically (BIP85, or an LUD-05-style HMAC path plus a counter) can restore outstanding notes from the seed via hash-keyed lookup - option D doubles as the restore API. Restore covers device loss, NOT theft: anyone who copied a circulating note may have spent it long before the restore runs. One derivation convention must be pinned in the spec, or wallets fragment and restores silently miss notes.'
  },
  scenarios: [
    {
      id: 'T1',
      name: 'verify race',
      kind: 'attack',
      adversary: 'anyone who saw the unpaid mint invoice - the payment hash travels inside it',
      steps: [
        'observe an unpaid mint invoice and extract its payment hash',
        'poll the LUD-21 verify endpoint until the invoice settles',
        'take the disclosed preimage the moment it settles',
        'rotate the note before the payer does'
      ],
      currentBehavior: 'succeeds when verify is on',
      options: {
        closedBy: ['B', 'F'],
        notClosedBy: ['C', 'E'],
        lockedNotes: 'closed - the note is locked to its linkingKey from birth, so a racer holding only P cannot redeem'
      },
      status: 'inverts-when-option-B',
      notes:
        'C does not close it: encrypting to the mint is a public operation (mintPubkey is advertised), so the racer wraps the leaked preimage himself and replays. E does not either: the race becomes "whoever presents P plus a blinded B first gets the signature".'
    },
    {
      id: 'T2',
      name: 'routing-node race',
      kind: 'attack',
      adversary: 'every routing hop on the mint payment\'s path - each learns the preimage as the HTLC settles',
      steps: [
        'sit on the payment path of a mint invoice',
        'learn the preimage as the settling HTLC propagates back',
        'rotate before the payer'
      ],
      currentBehavior: 'succeeds even with VERIFY_ENABLED=false - no spec endpoint is involved',
      options: {
        closedBy: ['B', 'F'],
        lockedNotes: 'closed for locked notes only'
      },
      status: 'inverts-when-option-B',
      notes:
        'The same outcome as T1 with no verify at all: the preimage leaks from the payment protocol itself, not from any endpoint.'
    },
    {
      id: 'T3',
      name: 'poll-log replay',
      kind: 'attack',
      adversary: 'anyone reading whatever retains request URLs - a proxy, an access log, browser history',
      steps: [
        'the holder polls the informational GET /w?k1=<live note>',
        'the poll burns nothing, so the SPENDABLE k1 is left in the log',
        'the reader replays it into a rotate'
      ],
      currentBehavior: 'succeeds - every value poll leaves the SPENDABLE k1 in whatever retains request URLs',
      options: {
        closedBy: ['D', 'F'],
        notClosedBy: ['C'],
        lockedNotes: 'closed - a logged k1 is useless without the key'
      },
      status: 'inverts-when-option-D',
      notes:
        'D leaves only a harmless hash in those logs. C does not close it: a logged p redeems exactly like a logged k1 - the mint honors the ciphertext, so the ciphertext IS the note.'
    },
    {
      id: 'T4',
      name: 'callback-log replay',
      kind: 'control',
      adversary: 'anyone reading a logged mutating callback URL',
      steps: [
        'a k1 is captured from a MUTATING callback URL',
        'the request it rode in on already burned it',
        'replay it later'
      ],
      currentBehavior:
        'fails with "Invalid or already spent k1." - the burn from the original request is the protection',
      options: {holdsUnder: ['A', 'B', 'C', 'D', 'E', 'F', 'G']},
      status: 'pins-current',
      notes:
        'Must hold under every option. A replay landing in the same millisecond as the original is a plain race, not a logging problem.'
    },
    {
      id: 'T5',
      name: 'note at rest',
      kind: 'control',
      adversary: 'whoever finds the note URL - chat history, a screenshot, a printed QR',
      steps: ['find a note URL at rest', 'spend it'],
      currentBehavior: 'the finder spends it - a note URL at rest IS the money',
      options: {
        notClosedBy: ['A', 'B', 'C', 'D', 'E', 'F'],
        lockedNotes: 'beaten - the only option that beats the at-rest axiom, precisely because it surrenders bearer-ness'
      },
      status: 'pins-current',
      notes:
        'The bearer axiom: every bearer option "fails" this by design, and the all-minus row is deliberate. Any future option claiming to fix at-rest exposure has to answer this scenario first.'
    },
    {
      id: 'T6',
      name: 'operator correlation',
      kind: 'property',
      adversary: 'the mint operator',
      steps: [
        'at rotate, the WALLET discloses h = sha256(new_k1)',
        'the mint keys its storage by h',
        'a later spend of new_k1 matches the recorded h'
      ],
      currentBehavior: 'issuance links to redemption - a full transaction graph at the operator',
      options: {
        closedBy: ['E'],
        notClosedBy: ['A', 'B', 'C', 'D', 'F'],
        lockedNotes: 'open - the operator knows exactly which key owns which notes'
      },
      status: 'privacy-axis',
      notes:
        'h-preimages give log confidentiality (T4) but not unlinkability from the operator; only blinded issuance closes this.'
    },
    {
      id: 'T7',
      name: 'legacy LUD-03 melt',
      kind: 'property',
      adversary: 'none - a compatibility property',
      steps: ['a wallet that knows nothing of LNURLcash melts a note to a BOLT-11 pr, as plain LUD-03'],
      currentBehavior: 'works - the note melts to a BOLT-11 pr as plain LUD-03',
      options: {
        preservedBy: ['A', 'B', 'D', 'E', 'F'],
        brokenBy: ['C'],
        lockedNotes: 'broken - a plain LUD-03 wallet cannot lnurl-auth, so locked notes have no legacy story'
      },
      status: 'pins-current',
      notes:
        'C breaks it because legacy wallets cannot encrypt - unless mixed mode re-admits plaintext k1, which voids C\'s only claim.'
    },
    {
      id: 'T8',
      name: 'first-contact offline verify',
      kind: 'gap',
      adversary: 'an attacker who self-signs a note and supplies their own key',
      steps: [
        'a recipient who has never interacted with this mint receives a note',
        'it has no mintPubkey on record, so it cannot verify the note\'s sig offline',
        'embedding the pubkey in the note URL proves nothing - an attacker self-signs and supplies their own key'
      ],
      currentBehavior: 'no offline verification on first contact - a spec-level gap, no endpoint to hit',
      options: {closedBy: []},
      status: 'spec-gap',
      notes:
        'No option on the scorecard addresses this; it needs a key-distribution story, not a transport change.'
    },
    {
      id: 'T9',
      name: 'comment silently ignored',
      kind: 'gap',
      adversary: 'none - a silent downgrade hazard, not an attacker',
      steps: [
        'a wallet already sending a LUD-12 comment calls the payRequest callback',
        'the callback takes no comment param and unknown query params are dropped silently',
        'the wallet gets a bare k1=P note with verify advertised anyway'
      ],
      currentBehavior: 'a silent downgrade with no signal to the wallet',
      options: {closedBy: ['B', 'F']},
      status: 'inverts-when-option-B',
      notes:
        'Option B must define semantics - fail-closed (reject the callback) or fallback (k1=P, no verify for that invoice) - never silent.'
    },
    {
      id: 'T10',
      name: 'merge URL budget',
      kind: 'property',
      adversary: 'none - pure URL arithmetic',
      steps: [
        'build a merge callback carrying one k1 per input note plus h for the result',
        'compare its length against the ~2000-character practical GET budget LUD-12 itself notes'
      ],
      currentBehavior: 'a merge of 25 notes fits in plaintext hex k1s (64 chars each)',
      options: {
        preservedBy: ['A', 'B', 'D', 'E', 'F'],
        brokenBy: ['C']
      },
      arithmetic: {
        budgetChars: URL_BUDGET,
        exampleCallback: CB,
        plaintextK1Chars: 64,
        encryptedK1: {
          layout: '33-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag',
          bytes: ENCRYPTED_K1_BYTES,
          base64Chars: ENCRYPTED_K1_B64_CHARS
        },
        mergeOf25: {
          plaintextChars: mergeUrl('k1', 64, 25).length,
          plaintextFits: mergeUrl('k1', 64, 25).length <= URL_BUDGET,
          encryptedChars: mergeUrl('p', ENCRYPTED_K1_B64_CHARS, 25).length,
          encryptedFits: mergeUrl('p', ENCRYPTED_K1_B64_CHARS, 25).length <= URL_BUDGET
        },
        mergeCapacity: {
          plaintext: mergeCapacity('k1', 64),
          encrypted: mergeCapacity('p', ENCRYPTED_K1_B64_CHARS),
          advertisedMaxK1s: 100
        }
      },
      status: 'arithmetic',
      notes:
        'The same merge with every k1 swapped for an encrypted-to-the-mint blob (option C) does not fit. max_k1s=100 is unreachable in BOTH variants under the budget - plaintext caps at 28, blobs at 15 - so C would halve the merge ceiling in exchange for nothing, per T1/T2/T3.'
    },
    {
      id: 'T11',
      name: 'offline handoff',
      kind: 'property',
      adversary: 'none - the bearer property itself',
      steps: ['hand a bearer note to its next holder with no mint contact at handoff time'],
      currentBehavior: 'works - the spec\'s Offline circulation section',
      options: {
        preservedBy: ['A', 'B', 'C', 'D', 'E', 'F'],
        lockedNotes: 'lost - transfer requires an online re-lock via the mint'
      },
      status: 'pins-current',
      notes:
        'Structural, no endpoint. Locked notes are registered claims, not cash; the bearer core and locked notes are complements, not competitors.'
    }
  ]
}

// ---- write ---------------------------------------------------------------

const files = [
  write('signature.json', signature),
  write('bech32.json', bech32Vectors),
  write('url-admission.json', urlAdmission),
  write('input-resolution.json', inputResolution),
  write('note-url.json', noteUrl),
  write('fees.json', fees),
  write('bolt11.json', bolt11),
  write('callbacks.json', callbacks),
  write('responses.json', responses),
  write('withdraw-info.json', withdrawInfo),
  write('pay-request.json', payRequest),
  write('lifecycle.json', lifecycle),
  write('threat-suite.json', threatSuite)
]

write('index.json', {
  version: VERSION,
  spec: SPEC,
  generatedBy: 'tools/generate.mjs',
  description:
    'Language-neutral conformance vectors for LNURLcash (LUD-25). Every implementation is expected to load these files directly rather than transcribe them.',
  files: files.filter(f => f !== 'index.json')
})

console.log(`wrote ${files.length + 1} vector files to vectors/`)
