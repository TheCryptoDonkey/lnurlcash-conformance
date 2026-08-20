// An LNURLcash SERVICE that can be told to misbehave.
//
// The point is not to be a good mint. It is to be a mint that reproduces,
// on demand, every failure a real one can inflict on a holder: an
// interrupted mutation whose outcome is unknowable, a signature in the
// wrong byte order, a note whose declared value is a lie, a melt that
// never settles, a callback that quietly declines to confirm anything.
// A wallet that survives all of these has earned the right to hold
// somebody's money.
//
// Usable as a library (createMockMint) or standalone (npm start).

import {createServer} from 'node:http'
import {sha256} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {randomBytes} from 'node:crypto'

const LSM_PREFIX = 'Lightning Signed Message:'

const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))

const sigDigest = (noteIdHex, amountMsat) =>
  sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes(LSM_PREFIX),
        ...utf8ToBytes(`LNURLcash:${amountMsat}:${noteIdHex}`)
      ])
    )
  )

// msat -> the amount part of a bolt11 human-readable part, exactly. 'n' is
// 100 msat per unit, 'p' is 0.1, so anything not a multiple of 100 msat
// goes out in pico units.
const encodeAmountHrp = msat =>
  msat % 100 === 0 ? `${msat / 100}n` : `${msat * 10}p`

const fakeInvoice = (amountMsat, preimage) => {
  // Not a real invoice: it is a syntactically valid human-readable part
  // (which is all a WALLET parses to check the amount) plus deterministic
  // filler in the data part. Nothing here is payable, and nothing should
  // pretend otherwise - a conformance run must never be mistakable for a
  // mainnet one.
  const data = bytesToHex(sha256(hexToBytes(preimage))).replace(/[b-f]/g, 'q')
  return `lnbc${encodeAmountHrp(amountMsat)}1${data}`
}

const DEFAULTS = {
  username: 'mint',
  minSendableMsat: 1000,
  maxSendableMsat: 100_000_000,
  // fee withheld on minting, advertised in the payRequest metadata
  baseFeeMsat: 0,
  feePpm: 0,
  // 'trailing' is the LUD-25 wire format (r || s || recovery id). 'leading'
  // reproduces the layout lnurl-mint once emitted, forwarding its node's
  // signmessage output unreordered.
  signatureLayout: 'trailing',
  // withhold sig/sig2 entirely, as a SERVICE with no funding source does
  signatures: true,
  // how the payRequest spells its withdrawLink. 'lnurlw' is the LUD-17
  // scheme form moneyer emits; 'plain' is the fetchable https:// URL
  // lnurl-mint emits and the spec's diagram shows. Both are legal raw,
  // non-bech32 URLs, and a WALLET that handles one but not the other
  // fails against half the public mints. Run your client against both.
  withdrawLinkForm: 'lnurlw',
  // LUD-21 verify endpoint. Off means 404, not merely unadvertised: the
  // preimage it serves IS a bearer secret, so an operator needs a real
  // off switch.
  verify: true,
  // ---- misbehaviour ----
  // answer the informational GET with a k1 other than the one queried
  echoWrongK1: false,
  // report a maxWithdrawable that is not what the note is worth
  lieAboutValue: 0,
  // hang up mid-mutation, leaving the outcome genuinely unknown to the
  // caller while the mutation itself still lands
  dropAfterMutation: false,
  // reply 200 with a body that confirms nothing
  unconfirmedMutation: false,
  // reply with a body that is not JSON at all
  malformedJson: false,
  // hold every melt in flight forever, so the note stays locked as pending
  meltNeverSettles: false,
  // fail every melt's payment, restoring the note
  meltAlwaysFails: false,
  // non-compliant: generate the replacement secret SERVICE-side and hand
  // it back, the exposure LUD-25's h/h2 exists to close
  serverGeneratedSecrets: false,
  // non-compliant: round the total mint fee up to a whole sat, as a fee
  // implementation that works in sats rather than msat does - the note
  // mints short of the formula
  roundFeeToSat: false,
  // non-compliant: serve the preimage from /verify before settlement. On
  // a mint that value IS the bearer secret of the note the payment will
  // create, so this hands the note to anyone holding the payment hash
  verifyLeaksEarly: false,
  // delay before responding, in milliseconds
  slowMs: 0,
  // reject splits and mints, as a mint winding down does
  sunset: false,
  // expose /_test/ endpoints so out-of-process test suites can fund a
  // note and settle an invoice. Never enable against anything real.
  testHooks: false
}

export const createMockMint = async (options = {}) => {
  const opts = {...DEFAULTS, ...options}
  const priv = opts.privateKey
    ? hexToBytes(opts.privateKey)
    : hexToBytes('1111111111111111111111111111111111111111111111111111111111111111')
  const pubkey = bytesToHex(secp256k1.getPublicKey(priv, true))

  // notes are stored by id - sha256(k1) - never by the secret itself. For a
  // freshly minted note that id is exactly the payment hash of the invoice
  // that funded it, so the preimage never needs to be persisted at all.
  const notes = new Map() // id -> {amountMsat, state: outstanding|pending|burned}
  const invoices = new Map() // paymentHash -> {amountMsat, preimage, settled}

  const sign = (noteIdHex, amountMsat) => {
    if (!opts.signatures) return undefined
    const lead = secp256k1.sign(sigDigest(noteIdHex, amountMsat), priv, {
      format: 'recovered',
      prehash: false
    })
    const trailing = new Uint8Array([...lead.subarray(1), lead[0]])
    return bytesToHex(opts.signatureLayout === 'leading' ? lead : trailing)
  }

  const mintNote = (id, amountMsat) => {
    notes.set(id, {amountMsat, state: 'outstanding'})
    return sign(id, amountMsat)
  }

  const applyFee = gross => {
    const proportional =
      Math.floor(gross / 1e6) * opts.feePpm +
      Math.floor(((gross % 1e6) * opts.feePpm) / 1e6)
    let fee = opts.baseFeeMsat + proportional
    if (opts.roundFeeToSat) fee = Math.ceil(fee / 1000) * 1000
    return Math.max(0, gross - fee)
  }

  // The advertised minimum must survive the advertised fee: a minSendable
  // whose note nets nothing invites a payment /p/cb then refuses. Binary
  // search for the smallest gross that still nets at least 1 msat -
  // applyFee is non-decreasing, so the minimum exists and is exact.
  const minSendableMsat = (() => {
    let hi = opts.minSendableMsat + opts.baseFeeMsat + 1
    while (applyFee(hi) < 1) hi *= 2
    let lo = 0
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2)
      if (applyFee(mid) >= 1) hi = mid
      else lo = mid + 1
    }
    return Math.max(opts.minSendableMsat, lo)
  })()

  const state = {
    notes,
    invoices,
    pubkey,
    opts,
    // test hooks
    creditNote(k1, amountMsat) {
      return mintNote(noteId(k1), amountMsat)
    },
    noteState(k1) {
      return notes.get(noteId(k1))?.state ?? null
    },
    settleMelt(k1) {
      const note = notes.get(noteId(k1))
      if (note) note.state = 'burned'
    },
    failMelt(k1) {
      const note = notes.get(noteId(k1))
      if (note) note.state = 'outstanding'
    }
  }

  // ---- test hooks ----
  //
  // Not part of LUD-25 and off unless --testHooks is passed. An in-process
  // test can reach into `state` directly; a test suite in another language
  // cannot, and would otherwise have no way to fund a note or settle an
  // invoice - the mock invents its invoices, so nothing can ever pay one.
  // These exist so the Python, Rust, Go and Kotlin suites can drive exactly
  // the same flows the TypeScript one drives in-process.
  const handleTestHook = (url, q, send) => {
    if (!opts.testHooks) {
      return send({status: 'ERROR', reason: 'test hooks are disabled'}, 404)
    }
    const fail = reason => send({status: 'ERROR', reason})
    if (url.pathname === '/_test/credit') {
      const k1 = q.get('k1')?.toLowerCase()
      const amount = Number(q.get('amount'))
      if (!k1 || !/^[0-9a-f]{64}$/.test(k1) || !Number.isFinite(amount)) {
        return fail('need k1 (32 bytes hex) and amount')
      }
      const sig = mintNote(noteId(k1), amount)
      return send({status: 'OK', k1, amount, sig: sig ?? null})
    }
    if (url.pathname === '/_test/settle') {
      const hash = q.get('payment_hash')?.toLowerCase()
      const invoice = hash ? invoices.get(hash) : null
      if (!invoice) return fail('unknown payment hash')
      invoice.settled = true
      // paying a mint invoice is what brings its note into existence: the
      // preimage IS the note secret, and the note id IS the payment hash
      if (!notes.has(hash)) mintNote(hash, invoice.amountMsat)
      return send({status: 'OK', settled: true})
    }
    if (url.pathname === '/_test/state') {
      const k1 = q.get('k1')?.toLowerCase()
      if (!k1) return fail('need k1')
      return send({status: 'OK', state: notes.get(noteId(k1))?.state ?? null})
    }
    return fail('unknown test hook')
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`)
    const q = url.searchParams

    // Test hooks answer before any misbehaviour is applied: they are fixture
    // plumbing, not part of the protocol under test, and a suite cannot set
    // up a scenario through an endpoint that is busy being slow or emitting
    // broken JSON on purpose.
    const sendRaw = (body, status = 200) => {
      res.writeHead(status, {
        'content-type': 'application/json',
        'access-control-allow-origin': '*'
      })
      res.end(JSON.stringify(body))
    }
    if (url.pathname.startsWith('/_test/')) {
      return handleTestHook(url, q, sendRaw)
    }

    // Every protocol endpoint below is a GET, and /w/cb mutates on whatever
    // arrives - an OPTIONS preflight or a stray POST must never reach a
    // handler. The grader checks exactly this.
    if (req.method !== 'GET') {
      return sendRaw({status: 'ERROR', reason: 'Not found.'}, 404)
    }

    if (opts.slowMs) await new Promise(r => setTimeout(r, opts.slowMs))
    const send = (body, status = 200) => {
      if (opts.malformedJson) {
        res.writeHead(status, {'content-type': 'application/json'})
        res.end('{ this is not json')
        return
      }
      res.writeHead(status, {
        'content-type': 'application/json',
        'access-control-allow-origin': '*'
      })
      res.end(JSON.stringify(body))
    }
    const fail = reason => send({status: 'ERROR', reason})
    const origin = `http://${req.headers.host}`

    // ---- LUD-16 payRequest (minting) ----
    const lnurlpMatch = url.pathname.match(/^\/\.well-known\/lnurlp\/(.+)$/)
    if (lnurlpMatch) {
      const user = lnurlpMatch[1]
      if (user !== opts.username && user !== '_') {
        return send({status: 'ERROR', reason: 'Unknown user.'}, 404)
      }
      const metadata = [
        ['text/plain', 'a mock LNURLcash mint - nothing here is payable'],
        ['text/identifier', `${user}@${req.headers.host}`]
      ]
      if (opts.baseFeeMsat > 0 || opts.feePpm > 0) {
        metadata.push(['text/plain', `Mint fees: ${opts.baseFeeMsat},${opts.feePpm}`])
      }
      return send({
        tag: 'payRequest',
        callback: `${origin}/p/cb`,
        minSendable: minSendableMsat,
        maxSendable: opts.maxSendableMsat,
        metadata: JSON.stringify(metadata),
        withdrawLink:
          opts.withdrawLinkForm === 'plain' ? `${origin}/w` : `lnurlw://${req.headers.host}/w`,
        disposable: false
      })
    }

    // ---- LUD-25 mint address (experimental) ----
    const lnurlwMatch = url.pathname.match(/^\/\.well-known\/lnurlw\/(.+)$/)
    if (lnurlwMatch) {
      const user = lnurlwMatch[1]
      if (user !== opts.username && user !== '_') {
        return send({status: 'ERROR', reason: 'Unknown user.'}, 404)
      }
      return send({
        tag: 'withdrawRequest',
        callback: `${origin}/w`,
        minWithdrawable: opts.minSendableMsat,
        maxWithdrawable: applyFee(opts.maxSendableMsat),
        defaultDescription: 'mock mint',
        payLink: `${origin}/.well-known/lnurlp/${user}`,
        mintPubkey: pubkey,
        nodeAlias: 'mock-mint',
        nodeUri: `${pubkey}@127.0.0.1:9735`,
        nodeColor: '#ff9900',
        // The node stats lnurl-mint advertises. `nodeCapacity` is msat, like
        // every other amount, and is named without the suffix on the wire -
        // an implementation that renames it on its own side has to map it,
        // and one that spreads the response through will read undefined.
        nodeCapacity: 500_000_000,
        nodeNumChannels: 4,
        nodeNumPeers: 6
      })
    }

    // ---- LUD-06 pay callback: mint a note ----
    if (url.pathname === '/p/cb') {
      if (opts.sunset) {
        return fail('This mint is sunsetting - minting is disabled.')
      }
      const amount = Number(q.get('amount'))
      if (!Number.isFinite(amount) || amount <= 0) {
        return fail('Invalid amount.')
      }
      if (amount < minSendableMsat || amount > opts.maxSendableMsat) {
        return fail('Amount out of range.')
      }
      const net = applyFee(amount)
      if (net <= 0) return fail('Amount too small to mint a note.')
      const preimage = bytesToHex(randomBytes(32))
      const paymentHash = noteId(preimage)
      invoices.set(paymentHash, {amountMsat: net, preimage, settled: false})
      const body = {pr: fakeInvoice(amount, preimage), disposable: false}
      if (opts.verify) body.verify = `${origin}/verify/${paymentHash}`
      return send(body)
    }

    // ---- LUD-21 verify ----
    const verifyMatch = url.pathname.match(/^\/verify\/([0-9a-f]{64})$/i)
    if (verifyMatch) {
      if (!opts.verify) {
        res.writeHead(404, {'content-type': 'application/json'})
        return res.end(JSON.stringify({status: 'ERROR', reason: 'Not found.'}))
      }
      const invoice = invoices.get(verifyMatch[1].toLowerCase())
      if (!invoice) return fail('Unknown payment hash.')
      return send({
        status: 'OK',
        settled: invoice.settled,
        // the preimage IS the bearer secret here - a real SERVICE should
        // think hard before serving it, and a WALLET that receives one
        // must rotate immediately
        preimage: invoice.settled || opts.verifyLeaksEarly ? invoice.preimage : null,
        pr: fakeInvoice(invoice.amountMsat, invoice.preimage)
      })
    }

    // ---- LUD-03 informational GET ----
    if (url.pathname === '/w') {
      const k1 = q.get('k1')?.toLowerCase()
      if (!k1) return fail('Unknown note.')
      if (!/^[0-9a-f]{64}$/.test(k1)) return fail('Unknown note.')
      const note = notes.get(noteId(k1))
      if (!note) return fail('Unknown note.')
      if (note.state === 'burned') return fail('Note already spent.')
      return send({
        tag: 'withdrawRequest',
        callback: `${origin}/w/cb`,
        k1: opts.echoWrongK1 ? 'f'.repeat(64) : k1,
        minWithdrawable: 0,
        maxWithdrawable: note.amountMsat + opts.lieAboutValue,
        defaultDescription: 'an LNURLcash note',
        mintPubkey: pubkey
      })
    }

    // ---- the mutating callback ----
    if (url.pathname === '/w/cb') {
      const k1s = q.getAll('k1').map(s => s.toLowerCase())
      const pr = q.get('pr')
      const amountRaw = q.get('amount')
      const h = q.get('h')
      const h2 = q.get('h2')

      if (k1s.length === 0) return fail('Missing k1.')
      // a repeated k1 would count one note's value twice into the output -
      // refused atomically, as the reference mint does
      if (new Set(k1s).size !== k1s.length) return fail('Invalid or already spent k1.')
      if (pr && k1s.length > 1) return fail('pr must not be combined with multiple k1.')
      if (pr && amountRaw) return fail('pr must not be combined with amount.')

      const found = []
      for (const k1 of k1s) {
        if (!/^[0-9a-f]{64}$/.test(k1)) return fail('Invalid or already spent k1.')
        const note = notes.get(noteId(k1))
        if (!note) return fail('Invalid or already spent k1.')
        if (note.state === 'burned') return fail('Invalid or already spent k1.')
        if (note.state === 'pending') return fail('pending')
        found.push({k1, note})
      }
      const total = found.reduce((sum, f) => sum + f.note.amountMsat, 0)

      const finish = body => {
        if (opts.dropAfterMutation) {
          // the mutation has already been applied by this point: the caller
          // learns nothing, which is exactly the ambiguity a WALLET must
          // survive without discarding its fresh secrets
          req.destroy()
          return
        }
        if (opts.unconfirmedMutation) return send({acknowledged: true})
        return send(body)
      }

      // melt
      if (pr) {
        const {k1, note} = found[0]
        note.state = 'pending'
        const body = {status: 'OK'}
        // The melt's own payment preimage, which is NOT the note secret and
        // must never be conflated with it: by the time a melt proof exists
        // the note that funded it is already burned, so unlike a freshly
        // minted note's preimage this one is not bearer material.
        const meltPreimage = bytesToHex(randomBytes(32))
        if (opts.verify) {
          const paymentHash = noteId(meltPreimage)
          body.pr = pr
          body.verify = `${origin}/verify/${paymentHash}`
          invoices.set(paymentHash, {
            amountMsat: note.amountMsat,
            preimage: meltPreimage,
            settled: false
          })
        }
        if (!opts.meltNeverSettles) {
          // a real melt settles asynchronously; the note is only burned
          // once the outgoing payment actually does
          setTimeout(() => {
            if (opts.meltAlwaysFails) note.state = 'outstanding'
            else {
              note.state = 'burned'
              const inv = invoices.get(noteId(meltPreimage))
              if (inv) inv.settled = true
            }
          }, 20)
        }
        return finish(body)
      }

      if (!h) return fail('missing h')
      if (amountRaw !== null && !h2) return fail('missing h2')
      if (!/^[0-9a-f]{64}$/.test(h)) return fail('missing h')
      if (h2 && !/^[0-9a-f]{64}$/.test(h2)) return fail('missing h2')
      // One id cannot carry two notes, and an id already in use - as a note
      // in any state, or as a mint invoice's payment hash - must never be
      // minted over: the invoice case points a future payer's money at a
      // stranger's note (its /verify serves the preimage that IS the k1 of
      // whatever sits under that id), and a burned note's id has a preimage
      // every previous holder still knows. Refused with the same reason as
      // any dead k1, so a probe learns nothing about which ids exist.
      if (h2 && h2 === h) return fail('Invalid or already spent k1.')
      for (const outputId of h2 ? [h, h2] : [h]) {
        if (notes.has(outputId) || invoices.has(outputId)) {
          return fail('Invalid or already spent k1.')
        }
      }

      // split
      if (amountRaw !== null) {
        if (opts.sunset) {
          return fail('This mint is sunsetting - splits are disabled.')
        }
        const amount = Number(amountRaw)
        if (!Number.isFinite(amount) || amount <= 0 || amount >= total) {
          return fail('Invalid amount.')
        }
        // LUD-25: a fee-advertising SERVICE deducts base_fee_msat from
        // every split's CHANGE - never from the requested amount - so a
        // holder cannot dodge per-melt costs by splitting into dust. A
        // change that cannot cover the fee, or would land at exactly
        // nothing, refuses with the spec's own reason.
        const changeBeforeFee = total - amount
        if (changeBeforeFee < opts.baseFeeMsat) return fail('insufficient value')
        const change = changeBeforeFee - opts.baseFeeMsat
        if (change < 1) return fail('insufficient value')
        for (const {note} of found) note.state = 'burned'
        const sig = mintNote(h, amount)
        const sig2 = mintNote(h2, change)
        const body = {status: 'OK'}
        if (sig) body.sig = sig
        if (sig2) body.sig2 = sig2
        if (opts.serverGeneratedSecrets) {
          body.k1 = 'a'.repeat(64)
          body.change = 'b'.repeat(64)
        }
        return finish(body)
      }

      // rotate (one k1) or merge (several) - same shape either way.
      // LUD-25: a merge of n notes refunds (n - 1) base fees, since the
      // SERVICE now faces one eventual melt instead of n. A rotate is a
      // merge of one - refund exactly 0.
      const refund = (k1s.length - 1) * opts.baseFeeMsat
      for (const {note} of found) note.state = 'burned'
      const sig = mintNote(h, total + refund)
      const body = {status: 'OK'}
      if (sig) body.sig = sig
      if (opts.serverGeneratedSecrets) body.k1 = 'a'.repeat(64)
      return finish(body)
    }

    res.writeHead(404, {'content-type': 'application/json'})
    res.end(JSON.stringify({status: 'ERROR', reason: 'Not found.'}))
  })

  await new Promise(resolve => server.listen(options.port ?? 0, '127.0.0.1', resolve))
  const {port} = server.address()

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    state,
    close: () => new Promise(resolve => server.close(resolve))
  }
}

// standalone
if (import.meta.url === `file://${process.argv[1]}`) {
  const flags = {}
  for (const arg of process.argv.slice(2)) {
    const [key, value = 'true'] = arg.replace(/^--/, '').split('=')
    flags[key] = value === 'true' ? true : value === 'false' ? false : isNaN(Number(value)) ? value : Number(value)
  }
  const mint = await createMockMint(flags)
  const k1 = bytesToHex(randomBytes(32))
  mint.state.creditNote(k1, 21000)
  console.log(`mock mint listening on ${mint.url}`)
  console.log(`  lightning address: ${flags.username ?? 'mint'}@127.0.0.1:${mint.port}`)
  console.log(`  a 21 sat note:     lnurlw://127.0.0.1:${mint.port}/w?k1=${k1}&amount=21000`)
  console.log(`  mint pubkey:       ${mint.state.pubkey}`)
  console.log('\nnothing here is payable - this mint invents its invoices')
}
