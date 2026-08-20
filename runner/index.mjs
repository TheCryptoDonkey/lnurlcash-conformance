// Grades a live LNURLcash SERVICE against the spec.
//
// Deliberately written with nothing but fetch and @noble - no lnurlcash
// library of any kind. A conformance runner that shared an implementation
// with the thing it grades would agree with that implementation's mistakes,
// which is the one thing it must never do.

import {sha256} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {randomBytes} from 'node:crypto'

const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))

const verifySignature = (k1, amountMsat, signatureHex, pubkeyHex) => {
  let sig
  try {
    sig = hexToBytes(signatureHex)
  } catch {
    return false
  }
  if (sig.length !== 65) return false
  const digest = sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes('Lightning Signed Message:'),
        ...utf8ToBytes(`LNURLcash:${amountMsat}:${noteId(k1)}`)
      ])
    )
  )
  const leading = new Uint8Array([sig[64], ...sig.subarray(0, 64)])
  for (const candidate of [leading, sig]) {
    try {
      const recovered = secp256k1.recoverPublicKey(candidate, digest, {
        prehash: false
      })
      if (bytesToHex(recovered) === pubkeyHex.toLowerCase()) return true
    } catch {
      // wrong ordering - try the other
    }
  }
  return false
}

// LUD-17: lnurlw://host/path is https://host/path, or http:// when the host
// is an onion service (the spec) or loopback (development). A plain
// https:// or http:// URL passes through untouched, so a caller can hand
// this either form a SERVICE emits.
export const fromLud17 = value => {
  const v = String(value).trim()
  if (!/^lnurl[wpc]:\/\//i.test(v)) return v
  const rest = v.slice(v.indexOf('://') + 3)
  const host = rest.split(/[/?#]/, 1)[0].replace(/:\d+$/, '').toLowerCase()
  const plain = ['localhost', '127.0.0.1', '0.0.0.0'].includes(host) || host.endsWith('.onion')
  return (plain ? 'http://' : 'https://') + rest
}

const isAllowedUrl = value => {
  let url
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol === 'https:') return true
  if (url.protocol !== 'http:') return false
  const host = url.hostname
  return (
    ['127.0.0.1', '0.0.0.0', 'localhost'].includes(host) || host.endsWith('.onion')
  )
}

const get = async (url, timeoutMs = 15_000) => {
  const res = await fetch(url.toString(), {signal: AbortSignal.timeout(timeoutMs)})
  const text = await res.text()
  let body
  try {
    body = JSON.parse(text)
  } catch {
    throw new Error(`response was not JSON: ${text.slice(0, 120)}`)
  }
  return body
}

export const createReport = () => {
  const results = []
  return {
    results,
    pass: (name, detail) => results.push({status: 'pass', name, detail}),
    fail: (name, detail) => results.push({status: 'fail', name, detail}),
    warn: (name, detail) => results.push({status: 'warn', name, detail}),
    skip: (name, detail) => results.push({status: 'skip', name, detail}),
    async check(name, fn) {
      try {
        const detail = await fn()
        results.push({status: 'pass', name, detail})
      } catch (err) {
        results.push({
          status: err.warning ? 'warn' : 'fail',
          name,
          detail: err.message
        })
      }
    },
    get failed() {
      return results.filter(r => r.status === 'fail').length
    }
  }
}

const soft = message => {
  const err = new Error(message)
  err.warning = true
  return err
}

const assert = (condition, message) => {
  if (!condition) throw new Error(message)
}

// The msat amount encoded in a bolt11 invoice's human-readable part, or
// null when the invoice carries none (or none expressible in whole msat).
export const invoiceAmountMsat = pr => {
  if (typeof pr !== 'string') return null
  const lower = pr.toLowerCase()
  const sep = lower.lastIndexOf('1')
  if (sep < 0) return null
  const m = lower.slice(0, sep).match(/^ln(?:bc|tb|bcrt|tbs|sb)(\d+)?([munp])?$/)
  if (!m?.[1]) return null
  const per = {'': 1e11, m: 1e8, u: 1e5, n: 100, p: 0.1}[m[2] || '']
  const msat = Number(m[1]) * per
  return Number.isInteger(msat) ? msat : null
}

// The LUD-25 fee formula, msat-exact. The proportional term is split so it
// cannot overflow at realistic amounts - see the fees vectors.
const proportionalFee = (gross, ppm) =>
  Math.floor(gross / 1e6) * ppm + Math.floor(((gross % 1e6) * ppm) / 1e6)
export const applyMintFee = (gross, fee) =>
  Math.max(0, gross - (fee?.baseFeeMsat ?? 0) - proportionalFee(gross, fee?.feePpm ?? 0))

// The LUD-25 fee advertisement, parsed from payRequest metadata: null for
// a fee-free (or silent) mint. The grader needs it because the spec's fee
// algebra changes what a compliant split and merge return.
export const parseAdvertisedMintFee = metadata => {
  let entries
  try {
    entries = JSON.parse(metadata)
  } catch {
    return null
  }
  if (!Array.isArray(entries)) return null
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry[0] !== 'text/plain') continue
    const match = typeof entry[1] === 'string' && entry[1].match(/^Mint fees:\s*(\d+)\s*,\s*(\d+)\s*$/)
    if (!match) continue
    const baseFeeMsat = Number(match[1])
    const feePpm = Number(match[2])
    if (baseFeeMsat === 0 && feePpm === 0) return null
    return {baseFeeMsat, feePpm}
  }
  return null
}

// Resolves what the user typed - a Lightning Address, a bare domain, or a
// URL - to the payRequest URL to grade.
export const resolveMint = input => {
  const trimmed = input.trim().replace(/^@/, '')
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  const [name, domain] = trimmed.includes('@')
    ? trimmed.split('@')
    : ['mint', trimmed]
  const host = domain.split(':')[0]
  const scheme =
    ['127.0.0.1', '0.0.0.0', 'localhost'].includes(host) || host.endsWith('.onion')
      ? 'http'
      : 'https'
  return `${scheme}://${domain}/.well-known/lnurlp/${name}`
}

// ---- read-only checks -----------------------------------------------------

export const gradeMint = async (payUrl, report) => {
  let pay
  await report.check('payRequest resolves and is well-formed', async () => {
    pay = await get(payUrl)
    assert(pay.tag === 'payRequest', `tag was ${JSON.stringify(pay.tag)}`)
    assert(typeof pay.callback === 'string', 'no callback')
    assert(isAllowedUrl(pay.callback), `callback is not a fetchable URL: ${pay.callback}`)
    assert(typeof pay.metadata === 'string', 'no metadata')
    assert(Number.isFinite(pay.minSendable), 'no minSendable')
    assert(Number.isFinite(pay.maxSendable), 'no maxSendable')
    assert(pay.minSendable <= pay.maxSendable, 'minSendable exceeds maxSendable')
    return `${pay.minSendable}-${pay.maxSendable} msat`
  })
  if (!pay) return

  await report.check('advertises a withdrawLink (LUD-25)', async () => {
    assert(
      typeof pay.withdrawLink === 'string',
      'no withdrawLink - this is an ordinary payRequest, not an LNURLcash mint'
    )
    const link = pay.withdrawLink.trim()
    assert(
      !/^lnurl1/i.test(link),
      'withdrawLink is bech32-encoded - LUD-25 wants the raw URL, not an LNURL'
    )
    // Both forms are in the wild: lnurl-mint emits the plain https:// URL
    // (as the spec's own diagram does), moneyer the lnurlw:// LUD-17 form.
    // Either is a raw, non-bech32 URL; a WALLET has to take both.
    const form = /^lnurlw:\/\//i.test(link) ? 'lnurlw:// form' : 'plain URL form'
    assert(
      /^(lnurlw|https?):\/\//i.test(link),
      `withdrawLink has an unexpected scheme: ${link}`
    )
    assert(isAllowedUrl(fromLud17(link)), `withdrawLink is not fetchable: ${link}`)
    return `${link} (${form})`
  })

  await report.check('metadata parses, and any fee advertisement is valid', async () => {
    const entries = JSON.parse(pay.metadata)
    assert(Array.isArray(entries), 'metadata is not an array')
    const fee = entries.find(
      e => Array.isArray(e) && e[0] === 'text/plain' && /^Mint fees:/.test(e[1] ?? '')
    )
    if (!fee) return 'no fee advertised (fee-free)'
    const match = fee[1].match(/^Mint fees:\s*(\d+)\s*,\s*(\d+)\s*$/)
    assert(match, `malformed fee entry: ${JSON.stringify(fee[1])}`)
    assert(
      Number(match[2]) < 1_000_000,
      `fee of ${match[2]} ppm is 100% or more - no amount can ever net anything`
    )
    return `${match[1]} msat + ${match[2]} ppm`
  })

  let verifyUrl
  await report.check('issues an invoice for the amount requested', async () => {
    const amount = Math.max(pay.minSendable, 1000)
    const url = new URL(pay.callback)
    url.searchParams.set('amount', String(amount))
    const body = await get(url)
    assert(body.status !== 'ERROR', `refused: ${body.reason}`)
    assert(typeof body.pr === 'string', 'no pr in the response')
    const invoiced = invoiceAmountMsat(body.pr)
    if (invoiced !== null) {
      assert(
        invoiced === amount,
        `asked for ${amount} msat, invoiced ${invoiced} msat`
      )
    }
    if (body.verify) {
      assert(isAllowedUrl(body.verify), `verify URL is not fetchable: ${body.verify}`)
      verifyUrl = body.verify
    }
    return `${amount} msat${body.verify ? ', with LUD-21 verify' : ''}`
  })

  await report.check('verify serves no secret before settlement', async () => {
    // On a mint the invoice preimage IS the bearer secret of the note the
    // payment will create, and everyone on the payment's route learns the
    // payment hash. A verify endpoint that answers the hash with the
    // preimage before settlement hands the note to whoever polls first.
    if (!verifyUrl) throw soft('no LUD-21 verify URL to probe')
    const body = await get(verifyUrl)
    assert(body.status !== 'ERROR', `refused its own verify URL: ${body.reason}`)
    assert(
      body.settled === false,
      `an invoice nothing has paid reports settled: ${JSON.stringify(body.settled)}`
    )
    assert(
      body.preimage == null,
      'served a preimage before settlement - on a mint that value is the bearer secret itself'
    )
    return 'settled: false, no preimage'
  })

  await report.check('reports an unknown note distinguishably', async () => {
    const withdrawUrl = pay.withdrawLink ? fromLud17(pay.withdrawLink) : ''
    if (!withdrawUrl) throw soft('no withdrawLink to probe')
    const url = new URL(withdrawUrl)
    url.searchParams.set('k1', bytesToHex(randomBytes(32)))
    const body = await get(url)
    assert(body.status === 'ERROR', `a note that cannot exist was accepted: ${JSON.stringify(body).slice(0, 120)}`)
    assert(typeof body.reason === 'string' && body.reason.length > 0, 'ERROR carried no reason')
    assert(
      /unknown|not found/i.test(body.reason),
      `reason ${JSON.stringify(body.reason)} does not identify the note as unknown - a holder cannot tell this apart from "already spent"`
    )
    return body.reason
  })

  await report.check('publishes a mint address (experimental, optional)', async () => {
    const mirror = payUrl.replace('/.well-known/lnurlp/', '/.well-known/lnurlw/')
    let body
    try {
      body = await get(mirror)
    } catch {
      throw soft('not published - optional, and carries no LUD number')
    }
    if (body.status === 'ERROR') throw soft(`not published: ${body.reason}`)
    assert(body.tag === 'withdrawRequest', 'wrong tag')
    assert(typeof body.payLink === 'string', 'no payLink back to the payRequest')
    return body.mintPubkey ? `node ${body.mintPubkey.slice(0, 16)}...` : 'published'
  })

  return pay
}

// ---- the minted-value check ----------------------------------------------
//
// Read-only, but it needs something the runner cannot make on its own: a
// real payment. Given a freshly minted, not-yet-rotated note and the gross
// msat its mint invoice was paid at, checks the note is worth exactly what
// the LUD-25 formula says. This is where a fee implementation that works
// in whole sats - rounding the withheld fee up - shows itself: the note
// mints short of the formula and no other check can see it.
export const gradeMintedValue = async (noteUrl, report, {mintFee = null, paidMsat}) => {
  await report.check('a minted note is worth the amount paid minus the fee', async () => {
    assert(Number.isFinite(paidMsat) && paidMsat > 0, `paidMsat was ${paidMsat}`)
    const url = new URL(fromLud17(noteUrl))
    const info = await get(url)
    assert(info.status !== 'ERROR', `refused: ${info.reason}`)
    assert(Number.isFinite(info.maxWithdrawable), 'no maxWithdrawable')
    const expected = applyMintFee(paidMsat, mintFee)
    const feeText = mintFee
      ? `${mintFee.baseFeeMsat} msat + ${mintFee.feePpm} ppm`
      : 'no advertised fee'
    const satRounded = expected - (expected % 1000)
    assert(
      info.maxWithdrawable === expected,
      `paid ${paidMsat} msat against ${feeText}: the formula nets ${expected} msat, the note holds ${info.maxWithdrawable}` +
        (info.maxWithdrawable === satRounded && satRounded !== expected
          ? ' - consistent with the fee being rounded up to a whole sat, which the formula does not allow'
          : '')
    )
    return `${paidMsat} msat paid -> ${info.maxWithdrawable} msat note (${feeText})`
  })
}

// ---- mutating checks ------------------------------------------------------
//
// These SPEND. They burn the note they are given and leave the value in a
// fresh note the runner prints at the end.

// options.mintFee: the service's advertised fee ({baseFeeMsat, feePpm}),
// null for known-fee-free, or leave the key absent when unknown - the
// split/merge conservation checks are exact when the fee is known and
// bounded when it is not. LUD-25's fee algebra: base_fee_msat comes out of
// every split's change, and a merge of n notes refunds (n - 1) base fees.
export const gradeNote = async (noteUrl, report, options = {}) => {
  const knownBaseFee = 'mintFee' in options ? (options.mintFee?.baseFeeMsat ?? 0) : null
  const url = new URL(fromLud17(noteUrl))
  const k1 = url.searchParams.get('k1')?.toLowerCase()
  assert(k1 && /^[0-9a-f]{64}$/.test(k1), 'that note carries no 32-byte hex k1')

  let info
  await report.check('informational GET echoes the k1 it was queried with', async () => {
    info = await get(url)
    assert(info.status !== 'ERROR', `refused: ${info.reason}`)
    assert(info.tag === 'withdrawRequest', `tag was ${JSON.stringify(info.tag)}`)
    assert(typeof info.callback === 'string', 'no callback')
    assert(isAllowedUrl(info.callback), `callback is not fetchable: ${info.callback}`)
    assert(Number.isFinite(info.maxWithdrawable), 'no maxWithdrawable')
    assert(
      info.k1?.toLowerCase() === k1,
      'the response k1 differs from the one queried - it must be the bearer secret itself, never a derived id'
    )
    return `${info.maxWithdrawable} msat`
  })
  if (!info?.callback) return

  await report.check('the informational GET does not burn the note', async () => {
    const again = await get(url)
    assert(again.status !== 'ERROR', `the second GET was refused: ${again.reason}`)
    assert(
      again.maxWithdrawable === info.maxWithdrawable,
      `value changed between two informational GETs: ${info.maxWithdrawable} then ${again.maxWithdrawable}`
    )
    return 'idempotent'
  })

  await report.check('ignores the amount in the note URL', async () => {
    const lying = new URL(url)
    lying.searchParams.set('amount', String(info.maxWithdrawable * 100 + 1))
    const body = await get(lying)
    assert(body.status !== 'ERROR', `refused when amount was inflated: ${body.reason}`)
    assert(
      body.maxWithdrawable === info.maxWithdrawable,
      `the URL's own amount changed the reported value: ${body.maxWithdrawable}`
    )
    return 'maxWithdrawable is authoritative'
  })

  await report.check('refuses a rotate with no h', async () => {
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', k1)
    const body = await get(cb)
    assert(
      body.status === 'ERROR',
      'accepted a mutation with no h - a SERVICE must never generate the replacement secret'
    )
    return body.reason
  })

  let current = k1
  let currentSig = null
  await report.check('rotate mints a note the service never saw the secret of', async () => {
    const fresh = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('h', noteId(fresh))
    const body = await get(cb)
    assert(body.status === 'OK', `refused: ${body.reason}`)
    // Adopt the new secret BEFORE asserting anything about compliance. The
    // mutation has already happened, so a runner that throws first would
    // leave every later check pointed at a note this service just burned,
    // and report a pile of cascading failures that say nothing.
    current = fresh
    currentSig = body.sig ?? null
    assert(
      body.k1 === undefined && body.change === undefined,
      'the response carried a secret - a compliant SERVICE returns none, since it generated none'
    )

    const check = new URL(url)
    check.searchParams.set('k1', fresh)
    const after = await get(check)
    assert(after.status !== 'ERROR', `the rotated note is not spendable: ${after.reason}`)
    assert(
      after.maxWithdrawable === info.maxWithdrawable,
      `value changed across a rotate: ${info.maxWithdrawable} -> ${after.maxWithdrawable}`
    )

    const old = new URL(url)
    old.searchParams.set('k1', k1)
    const dead = await get(old)
    assert(dead.status === 'ERROR', 'the rotated-away secret is still spendable')
    return 'burned the old secret, minted the new'
  })

  await report.check('signs the notes it issues (optional)', async () => {
    if (!info.mintPubkey) throw soft('no mintPubkey advertised - offline verification unavailable')
    if (!currentSig) throw soft('mintPubkey advertised but no sig returned')
    assert(
      verifySignature(current, info.maxWithdrawable, currentSig, info.mintPubkey),
      'the signature does not verify against the advertised mintPubkey and amount'
    )
    return 'verified offline'
  })

  // The still-alive probe the three adversarial checks below share: a
  // compliant refusal is ATOMIC, so the note it refused to touch must
  // still be spendable afterwards.
  const assertStillLive = async () => {
    const check = new URL(url)
    check.searchParams.set('k1', current)
    const still = await get(check)
    assert(still.status !== 'ERROR', `the refusal burned the note anyway: ${still.reason}`)
  }

  await report.check('refuses a duplicated k1', async () => {
    // One note named twice in a merge-shaped request. Counting its value
    // twice into the output creates money from nothing.
    const fresh = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('h', noteId(fresh))
    const body = await get(cb)
    if (body.status === 'OK') {
      // the mutation landed - adopt the output first, so later checks keep
      // pointing at live money whatever the verdict
      current = fresh
      currentSig = body.sig ?? null
      const after = new URL(url)
      after.searchParams.set('k1', fresh)
      const output = await get(after)
      assert(
        output.maxWithdrawable !== info.maxWithdrawable * 2,
        'a duplicated k1 was counted twice - the output is worth double the note'
      )
      throw soft(
        `accepted a duplicated k1 (deduplicated to ${output.maxWithdrawable} msat) - an atomic refusal is the safer answer`
      )
    }
    await assertStillLive()
    return body.reason
  })

  await report.check('refuses an output hash that already names a note', async () => {
    // The original note's id is a known existing (burned) id. Minting over
    // an existing id hands the output to whoever knows its preimage - here,
    // every previous holder of the original note.
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('h', noteId(k1))
    const body = await get(cb)
    if (body.status === 'OK') {
      // the output's secret IS the original k1 - adopt it and say so
      current = k1
      currentSig = body.sig ?? null
      throw new Error(
        'minted over an existing note id - the output is spendable with a secret every previous holder already knows'
      )
    }
    await assertStillLive()
    return body.reason
  })

  await report.check('refuses a split whose h equals h2', async () => {
    const half = Math.floor(info.maxWithdrawable / 2)
    if (half < 1) throw soft('note too small to attempt')
    const twin = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('amount', String(half))
    cb.searchParams.append('h', noteId(twin))
    cb.searchParams.append('h2', noteId(twin))
    const body = await get(cb)
    if (body.status === 'OK') {
      current = twin
      currentSig = body.sig ?? null
      const after = new URL(url)
      after.searchParams.set('k1', twin)
      const output = await get(after)
      throw new Error(
        `accepted h2 equal to h - one id now carries ${output.maxWithdrawable ?? 'nothing'} msat of what should be two notes`
      )
    }
    await assertStillLive()
    return body.reason
  })

  await report.check('never mutates on a non-GET request', async () => {
    // LNURL endpoints are GETs. An OPTIONS preflight or a stray POST
    // carrying the callback's query string must leave the note untouched -
    // real HTTP stacks send both on their own initiative.
    for (const method of ['POST', 'OPTIONS']) {
      const fresh = bytesToHex(randomBytes(32))
      const cb = new URL(info.callback)
      cb.searchParams.append('k1', current)
      cb.searchParams.append('h', noteId(fresh))
      // the response - even an error - is not the assertion; the store is
      await fetch(cb.toString(), {method, signal: AbortSignal.timeout(15_000)})
        .then(res => res.arrayBuffer())
        .catch(() => {})
      const stillUrl = new URL(url)
      stillUrl.searchParams.set('k1', current)
      const still = await get(stillUrl)
      assert(still.status !== 'ERROR', `a ${method} request burned the note - the mutating callback must answer GET only`)
      const probe = new URL(url)
      probe.searchParams.set('k1', fresh)
      const output = await get(probe)
      assert(output.status === 'ERROR', `a ${method} request minted its output - the mutating callback must answer GET only`)
    }
    return 'POST and OPTIONS left the note untouched'
  })

  await report.check('split conserves value', async () => {
    const half = Math.floor(info.maxWithdrawable / 2)
    if (half < 1) throw soft('note too small to split')
    if (knownBaseFee !== null && info.maxWithdrawable - half < knownBaseFee + 1) {
      throw soft('note too small to split past the advertised base fee')
    }
    const a = bytesToHex(randomBytes(32))
    const b = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('amount', String(half))
    cb.searchParams.append('h', noteId(a))
    cb.searchParams.append('h2', noteId(b))
    const body = await get(cb)
    assert(body.status === 'OK', `refused: ${body.reason}`)

    const valueOf = async secret => {
      const u = new URL(url)
      u.searchParams.set('k1', secret)
      const r = await get(u)
      assert(r.status !== 'ERROR', `split output is not spendable: ${r.reason}`)
      return r.maxWithdrawable
    }
    const [va, vb] = [await valueOf(a), await valueOf(b)]
    assert(
      va === half,
      `asked to split off ${half}, got ${va} - any split fee comes out of change, never the requested amount`
    )
    if (knownBaseFee !== null) {
      const expectedChange = info.maxWithdrawable - half - knownBaseFee
      assert(
        vb === expectedChange,
        `change was ${vb} msat - LUD-25 says total minus amount minus the base fee, ${expectedChange}`
      )
    } else {
      assert(
        va + vb <= info.maxWithdrawable,
        `split created value: ${va} + ${vb} > ${info.maxWithdrawable}`
      )
    }

    // put it back together so the runner ends holding one note
    const merged = bytesToHex(randomBytes(32))
    const mcb = new URL(info.callback)
    mcb.searchParams.append('k1', a)
    mcb.searchParams.append('k1', b)
    mcb.searchParams.append('h', noteId(merged))
    const mbody = await get(mcb)
    assert(mbody.status === 'OK', `merge refused: ${mbody.reason}`)
    current = merged
    const total = await valueOf(merged)
    if (knownBaseFee !== null) {
      assert(
        total === va + vb + knownBaseFee,
        `a merge of 2 notes refunds one base fee per LUD-25: expected ${va + vb + knownBaseFee}, got ${total}`
      )
    } else {
      assert(
        total >= va + vb && total <= info.maxWithdrawable,
        `merge did not conserve value: ${va} + ${vb} became ${total}`
      )
    }
    return `${va} + ${vb}, merged back to ${total}`
  })

  await report.check('refuses a replayed burn', async () => {
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', k1)
    cb.searchParams.append('h', noteId(bytesToHex(randomBytes(32))))
    const body = await get(cb)
    assert(body.status === 'ERROR', 'a secret burned earlier was accepted again')
    return body.reason
  })

  return {finalSecret: current, noteUrl: (() => {
    const u = new URL(url)
    u.searchParams.set('k1', current)
    return u.toString()
  })()}
}
