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
  // how the payRequest spells its withdrawLink. 'plain' is the fetchable
  // https:// URL the reference mint emits and the spec's diagram shows;
  // 'lnurlw' is the LUD-17 scheme form some mints emitted under the
  // draft's looser wording. Both are legal raw, non-bech32 URLs, and a
  // WALLET that handles one but not the other fails against real mints.
  // Run your client against both.
  withdrawLinkForm: 'plain',
  // LUD-21 verify endpoint. Off means 404, not merely unadvertised: the
  // preimage it serves IS a bearer secret, so an operator needs a real
  // off switch.
  verify: true,
  // Publish `payLink` on a note's informational GET, the way home for a
  // holder who has nothing but the note. On by default because the
  // reference mint does it; turn it off for a mint that does not.
  noteInfoPayLink: true,
  // ---- misbehaviour ----
  // point `payLink` at a DIFFERENT origin, nominating a third party to
  // vouch for this mint's key history. A client must ignore it.
  payLinkOffOrigin: false,
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
  // ceiling the mint fee to a whole sat, as dni's lnurl-mint does on
  // purpose. Compliant: LUD-25 does not say whether the fee rounds, so
  // the grader accepts anything between this and the msat-exact formula
  roundFeeToSat: false,
  // beyond the band: withhold this much on top of the ceilinged fee, the
  // one thing the minted-value check must still catch
  extraFeeMsat: 0,
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
  testHooks: false,
  // ---- optional, non-spec extensions ----
  //
  // None of these is in LUD-25 and none is on by default. Every one is
  // absent from the wire unless it is set, so a client that has never
  // heard of them sees exactly the responses it saw before.
  //
  // Mint info on the experimental discovery endpoint: who runs this, how
  // to reach them, what the terms are, and what the operator wants
  // holders to know today.
  name: undefined,
  description: undefined,
  // {nostr?: npub, email?: string, url?: string}, or the same as a JSON
  // string so the CLI can pass one
  contact: undefined,
  tosUrl: undefined,
  motd: undefined,
  version: undefined,
  // Compressed hex pubkeys this SERVICE has signed under before. A mint
  // that rotates its signing key keeps publishing the old ones so notes
  // it already issued still verify. Emitted only when the list is not
  // empty; previousPrivateKey's own pubkey joins it automatically.
  previousPubkeys: undefined,
  // An old signing key the mock still holds, so a case can issue one note
  // under it and the rest under the current key. Per note:
  // state.creditNote(k1, amount, {previousKey: true}).
  previousPrivateKey: undefined,
  // Sign EVERY note this mock issues under previousPrivateKey while still
  // advertising the current key as mintPubkey. That is the mid-rotation
  // state a real mint passes through when the advertisement moves before
  // the signer does, and it is the only way a note the mint issues on
  // demand can carry an old key's signature.
  signWithPreviousKey: false,
  // What a retried mutation gets. A rotate, split or merge is a GET, and
  // HTTP stacks retry a GET when the connection they used is dropped, so
  // a SERVICE sees the byte-identical request twice. 'refuse' answers the
  // second one as an already-spent input, which is what this mock has
  // always done and remains the default. 'replay' answers it with the
  // original success, which is what LUD-25 SHOULD say and what stops a
  // holder discarding a note the SERVICE really did mint.
  retriedMutation: 'refuse',
  // Liabilities. Off means 404, exactly as before; on serves GET /stats.
  stats: false,
  // What the node behind a stats-publishing mock claims to hold. Read
  // only when stats is on, and the reason a mock can be told to look
  // under-covered.
  localBalanceMsat: 100_000_000_000,
  // fees are emitted on the discovery endpoint whenever one is configured
  // (baseFeeMsat or feePpm above zero); a fee-free mint publishes nothing
  //
  // ---- naming the note you are buying ----
  //
  // Off, and nothing about it reaches the wire: nothing is advertised
  // anywhere, the pay callback does not read `h` at all, and a minted
  // note's secret is the payment preimage exactly as it always was.
  //
  // On, a WALLET MAY add h=<64 lowercase hex> to the LUD-06 pay callback -
  // the sha256 of a secret it chose, the same thing `h` means on the
  // withdraw callback. The note is then credited at that id when the
  // invoice settles, and the payment preimage is NOT a valid k1 for it.
  // Which matters because two sets of untrusted people learn a preimage:
  // every routing node on the payment path, and anyone who merely saw the
  // invoice and polled /verify with its payment hash.
  //
  // The capability is claimed in three places and they say different
  // things. `mintToHash: true` on the payRequest means "I accept an h on
  // my pay callback", and since every mint publishes a payRequest while
  // the mint address document is experimental, that is the one a wallet
  // decides from. The mint address document repeats it, as corroboration.
  // The pay callback's own response echoes it when THAT quote was bound,
  // which is the one that matters at the moment money moves: the other
  // two can be cached or stale.
  mintToHash: false,
  // Add the optional bound LUD-21 receipt to an honestly bound quote and
  // its verify response. Requires mintToHash, verify and signatures; off
  // by default so the baseline mock remains the current LUD-25 wire.
  mintReceipt: false,
  // non-compliant, and only reachable with mintToHash on: issue an
  // invoice for an `h` that is not 64 lowercase hex, so a wallet pays for
  // a quote this mint was always going to refuse
  mintToHashAcceptsMalformedH: false,
  // non-compliant, mintToHash on: issue an invoice for an `h` that
  // already names a note, an invoice or another quote's output, so two
  // payers' money points at one id
  mintToHashAcceptsUsedH: false,
  // non-compliant, mintToHash on: advertise the capability, echo it back
  // on the quote, and credit the note at the payment hash anyway. The
  // wallet stopped rotating on sight because it was told it did not need
  // to, so this is the worst of both schemes
  mintToHashIgnoresH: false,
  // Which of the three the mock actually says it in. Undefined means all
  // three, which is what an honest mint publishes. Narrowing it changes
  // only what is CLAIMED, never what the mint does: 'quote' alone is the
  // mint that shipped the feature before the advertisement, and
  // 'payRequest,mintAddress' is the one that binds without confirming at
  // the moment money moves. Read only when mintToHash is on. Accepts an
  // array or a comma-separated string, so the CLI can pass one.
  mintToHashAdvertisedOn: undefined,

  // The SAME capability in the spelling LUD-25 actually specifies:
  // `comment = hex(sha256(secret))` (LUD-12), advertised as a
  // `commentAllowed` of at least 64. A number advertises that many
  // characters and reads `comment` as the output name; false says
  // nothing and reads nothing. Independent of mintToHash - a mint may
  // ship either, both, or neither.
  //
  // The two spellings are not symmetric, and that is the whole reason
  // both exist here. `h` is a parameter invented for naming, so a
  // malformed one MUST be refused before an invoice exists. `comment` is
  // plain LUD-12 free text any wallet may send for unrelated reasons, so
  // LUD-25 requires the opposite: fall back to crediting k1=P, never
  // refuse - and MUST NOT serve verify on that fallback, where P is not
  // proof of payment but the note itself.
  commentAllowed: false,
  // non-compliant, commentAllowed on: refuse a comment that is not a
  // bare 32-byte hex hash instead of falling back, so an ordinary LUD-12
  // wallet cannot pay this mint at all
  commentRefusesMalformed: false,
  // non-compliant, commentAllowed on: serve LUD-21 verify even on the
  // no-comment fallback, where the preimage it hands out IS the note
  verifyOnUnnamedMint: false
}

export const createMockMint = async (options = {}) => {
  const opts = {...DEFAULTS, ...options}
  const priv = opts.privateKey
    ? hexToBytes(opts.privateKey)
    : hexToBytes('1111111111111111111111111111111111111111111111111111111111111111')
  const pubkey = bytesToHex(secp256k1.getPublicKey(priv, true))

  // An old signing key, kept only so a case can issue a note under it. A
  // real mint that has rotated does NOT keep the old private key on the
  // box - verifying an old signature needs the public half and nothing
  // more - which is why previousPubkeys can also be set on its own.
  const previousPriv = opts.previousPrivateKey ? hexToBytes(opts.previousPrivateKey) : null
  const asList = value =>
    value === undefined || value === null
      ? []
      : Array.isArray(value)
        ? value
        : String(value).split(',').map(v => v.trim()).filter(Boolean)
  const previousPubkeys = [
    ...(previousPriv ? [bytesToHex(secp256k1.getPublicKey(previousPriv, true))] : []),
    ...asList(opts.previousPubkeys)
  ].filter((key, i, all) => all.indexOf(key) === i)
  const contact =
    typeof opts.contact === 'string' ? JSON.parse(opts.contact) : opts.contact

  // Where this mock claims to accept an `h` on its pay callback. All three
  // unless told otherwise, and empty when the capability is off, so a mock
  // started with no options claims nothing anywhere.
  const mintToHashPlaces = new Set(
    opts.mintToHash
      ? opts.mintToHashAdvertisedOn === undefined
        ? ['payRequest', 'mintAddress', 'quote']
        : asList(opts.mintToHashAdvertisedOn)
      : []
  )

  // notes are stored by id - sha256(k1) - never by the secret itself. For a
  // freshly minted note that id is exactly the payment hash of the invoice
  // that funded it, so the preimage never needs to be persisted at all.
  const notes = new Map() // id -> {amountMsat, state: outstanding|pending|burned}
  const invoices = new Map() // paymentHash -> {amountMsat, preimage, settled}
  // Provenance for retried mutations: which outputs a given set of inputs
  // minted. Recorded, never inferred - matching on "a note exists at h"
  // alone would let anyone holding a burned k1 and any outstanding note
  // id pull a success out of the mint.
  const swaps = new Map() // identity -> [{id, amountMsat}]
  // Output ids a mint quote has already claimed: h -> the payment hash of
  // the invoice that will credit it. Only ever written when mintToHash is
  // on, so with the option off this is empty and every collision check
  // below asks exactly what it asked before.
  const boundOutputs = new Map()

  // An id is spoken for if it is a note in any state, the payment hash of
  // an invoice this mint issued, or the output a bound quote is waiting
  // to credit. Minting over any of them hands the output to somebody who
  // already knows how to spend it, or bricks a payment that can no longer
  // land.
  const outputIdInUse = id =>
    notes.has(id) || invoices.has(id) || boundOutputs.has(id)

  // What makes a request the same request: the same input k1 set, the
  // same h, the same h2, the same amount. The inputs are a set rather
  // than a sequence, because a merge naming the same notes in a different
  // order is the same merge. Anything else naming a burned input is a
  // double-spend attempt and is refused exactly as it was before, with
  // the same reason string, so no oracle appears.
  const swapIdentity = (k1s, h, h2, amountRaw) =>
    [[...k1s].sort().join(','), h ?? '', h2 ?? '', amountRaw ?? ''].join('|')

  const sign = (noteIdHex, amountMsat, key = priv) => {
    if (!opts.signatures) return undefined
    const lead = secp256k1.sign(sigDigest(noteIdHex, amountMsat), key, {
      format: 'recovered',
      prehash: false
    })
    const trailing = new Uint8Array([...lead.subarray(1), lead[0]])
    return bytesToHex(opts.signatureLayout === 'leading' ? lead : trailing)
  }

  const mintNote = (id, amountMsat, {previousKey = opts.signWithPreviousKey} = {}) => {
    notes.set(id, {amountMsat, state: 'outstanding'})
    return sign(id, amountMsat, previousKey && previousPriv ? previousPriv : priv)
  }

  const applyFee = gross => {
    const proportional =
      Math.floor(gross / 1e6) * opts.feePpm +
      Math.floor(((gross % 1e6) * opts.feePpm) / 1e6)
    let fee = opts.baseFeeMsat + proportional
    if (opts.roundFeeToSat) fee = Math.ceil(fee / 1000) * 1000
    fee += opts.extraFeeMsat
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
    previousPubkeys,
    // creditNote(k1, amount) is unchanged. Pass {previousKey: true} to
    // sign the note under previousPrivateKey instead, which is how a case
    // puts one note under the old key and the rest under the new.
    creditNote(k1, amountMsat, options = {}) {
      return mintNote(noteId(k1), amountMsat, options)
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
      const previousKey = q.get('key') === 'previous'
      const sig = mintNote(noteId(k1), amount, {previousKey})
      return send({status: 'OK', k1, amount, sig: sig ?? null})
    }
    if (url.pathname === '/_test/settle') {
      const hash = q.get('payment_hash')?.toLowerCase()
      const invoice = hash ? invoices.get(hash) : null
      if (!invoice) return fail('unknown payment hash')
      invoice.settled = true
      // paying a mint invoice is what brings its note into existence. The
      // preimage IS the note secret and the note id IS the payment hash,
      // unless the wallet named an output hash of its own on the quote -
      // then the note is credited there and the preimage is nobody's key.
      const target = invoice.boundTo ?? hash
      if (!notes.has(target)) mintNote(target, invoice.amountMsat)
      if (invoice.boundTo) boundOutputs.delete(invoice.boundTo)
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
        disposable: false,
        // "I accept an h on my pay callback". Every mint has a payRequest
        // and the mint address document is experimental, so this is the
        // one a wallet should decide from. Spread in last and only when
        // the option is on, so a mock started with no options answers
        // exactly what it always answered.
        ...(mintToHashPlaces.has('payRequest') ? {mintToHash: true} : {}),
        // LUD-25: "A mint payLink intending to support this SHOULD
        // advertise a commentAllowed of at least 64". A payRequest field
        // only - the mint address document is a withdrawRequest, where a
        // LUD-12 comment has nowhere to go.
        ...(opts.commentAllowed ? {commentAllowed: opts.commentAllowed} : {}),
        // A receipt verifier needs the signing key before payment. The
        // baseline mock remains byte-for-byte unchanged when receipts are
        // off; a real node-key signer can alternatively be recovered from
        // the BOLT-11 invoice itself.
        ...(opts.mintReceipt && opts.verify && opts.signatures
          ? {mintPubkey: pubkey}
          : {})
      })
    }

    // ---- LUD-25 mint address (experimental) ----
    const lnurlwMatch = url.pathname.match(/^\/\.well-known\/lnurlw\/(.+)$/)
    if (lnurlwMatch) {
      const user = lnurlwMatch[1]
      if (user !== opts.username && user !== '_') {
        return send({status: 'ERROR', reason: 'Unknown user.'}, 404)
      }
      const address = {
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
      }
      // Optional mint info, appended so the fields above keep their order
      // and a mock started with no options answers byte for byte what it
      // answered before any of this existed.
      if (opts.name !== undefined) address.name = opts.name
      if (opts.description !== undefined) address.description = opts.description
      if (contact !== undefined) address.contact = contact
      if (opts.tosUrl !== undefined) address.tosUrl = opts.tosUrl
      if (opts.motd !== undefined) address.motd = opts.motd
      if (opts.version !== undefined) address.version = opts.version
      // The structured twin of the fee line in the payRequest metadata.
      // Both are emitted; neither replaces the other.
      if (opts.baseFeeMsat > 0 || opts.feePpm > 0) {
        address.fees = {baseFeeMsat: opts.baseFeeMsat, feePpm: opts.feePpm}
      }
      if (previousPubkeys.length > 0) address.previousPubkeys = previousPubkeys
      // The same fact the payRequest states, kept here for consistency
      // with the other capability fields. Appended last, so a mock
      // started with no options answers byte for byte what it answered
      // before any of this existed.
      if (mintToHashPlaces.has('mintAddress')) address.mintToHash = true
      return send(address)
    }

    // ---- liabilities (optional, outside LUD-25) ----
    //
    // Notes here are not blinded, so a mint can state what it owes exactly
    // - no epochs, no blinded sums. Off by default, and when off this
    // falls through to the same 404 every unknown path gets.
    if (url.pathname === '/stats' && opts.stats) {
      let outstandingMsat = 0
      let outstandingNotes = 0
      let pendingMsat = 0
      let pendingMelts = 0
      let oldestPendingSince = null
      for (const note of notes.values()) {
        if (note.state === 'outstanding') {
          outstandingMsat += note.amountMsat
          outstandingNotes++
        } else if (note.state === 'pending') {
          pendingMsat += note.amountMsat
          pendingMelts++
          const since = note.pendingSince ?? Date.now()
          if (oldestPendingSince === null || since < oldestPendingSince) {
            oldestPendingSince = since
          }
        }
      }
      const at = new Date().toISOString()
      const body = {
        at,
        // what the mint owes to notes it can still be asked to honour. A
        // note mid-melt is counted under pending instead: its value is
        // committed, not free, and it comes back if the payment fails.
        outstandingMsat,
        outstandingNotes,
        pendingMsat,
        pendingMelts,
        oldestPendingMeltAgeSecs:
          oldestPendingSince === null
            ? null
            : Math.floor((Date.now() - oldestPendingSince) / 1000)
      }
      if (Number.isFinite(opts.localBalanceMsat)) {
        body.localBalanceMsat = opts.localBalanceMsat
        // a ratio with nothing owed says nothing, so it is omitted rather
        // than reported as infinite
        if (outstandingMsat > 0) {
          body.coverage =
            Math.round((opts.localBalanceMsat / outstandingMsat) * 10_000) / 10_000
        }
      }
      body.reconciledAt = at
      return send(body)
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

      // ---- naming the note you are buying ----
      //
      // With mintToHash off this whole branch is skipped and `h` is not
      // read at all, so the callback answers exactly what it answered
      // before the option existed.
      let boundTo = null
      let echoBound = false
      if (opts.mintToHash) {
        // absent is not the same as empty: a wallet that sent `h=` meant
        // to bind, and must not be handed an unbound quote in silence
        const sent = q.get('h')
        if (sent !== null) {
          // Hex is case-insensitive, so both spellings are the same 32
          // bytes and name one output, not two. A WALLET must send
          // lowercase; a SERVICE that keyed the string it was handed
          // would file the note under the upper-case spelling and never
          // find it when the wallet asked the withdraw endpoint for its
          // own lowercase secret. Normalised here, before the collision
          // check, or an upper-case spelling walks straight past it.
          const wellFormed = /^[0-9a-f]{64}$/i.test(sent)
          const h = wellFormed ? sent.toLowerCase() : sent
          // Both refusals come BEFORE an invoice exists, which is the
          // whole point: a wallet must never pay for a quote this mint
          // was always going to reject.
          if (!wellFormed && !opts.mintToHashAcceptsMalformedH) {
            return fail('Invalid h.')
          }
          // An id already spoken for must never be minted over. Refused
          // with the same reason a colliding output hash gets on the
          // withdraw callback, so a probe learns nothing about which ids
          // exist here.
          if (outputIdInUse(h) && !opts.mintToHashAcceptsUsedH) {
            return fail('Invalid or already spent k1.')
          }
          if (wellFormed) {
            // The echo says "this quote is bound", so an honest mint
            // sets it exactly when it did bind. mintToHashIgnoresH is the
            // mint that says it and does not; leaving 'quote' out of
            // mintToHashAdvertisedOn is the mint that does and does not say.
            echoBound = mintToHashPlaces.has('quote')
            if (!opts.mintToHashIgnoresH) boundTo = h
          }
        }
      }

      // The LUD-25 spelling. Read after `h` so a mock offering both lets
      // an explicit comment name the output, and deliberately NOT an
      // else-branch: a mint may ship either spelling or both.
      let namedByComment = false
      if (opts.commentAllowed) {
        const sent = q.get('comment')
        if (sent !== null && sent !== '') {
          const wellFormed = /^[0-9a-f]{64}$/i.test(sent)
          if (wellFormed) {
            const h = sent.toLowerCase()
            // Same collision rule the `h` spelling gets: an id already
            // spoken for must never be minted over, whichever parameter
            // named it.
            if (outputIdInUse(h) && !opts.mintToHashAcceptsUsedH) {
              return fail('Invalid or already spent k1.')
            }
            if (!opts.mintToHashIgnoresH) {
              boundTo = h
              namedByComment = true
            }
          } else if (opts.commentRefusesMalformed) {
            // The non-compliant branch. LUD-25 says a comment that is not
            // a bare hash MUST fall back, because plain LUD-12 comments
            // are free text: refusing one turns an ordinary "thanks!"
            // into a mint that cannot be paid.
            return fail('Invalid comment.')
          }
        }
      }

      const preimage = bytesToHex(randomBytes(32))
      const paymentHash = noteId(preimage)
      const pr = fakeInvoice(amount, preimage)
      const invoice = {amountMsat: net, preimage, settled: false, pr}
      if (boundTo) {
        invoice.boundTo = boundTo
        boundOutputs.set(boundTo, paymentHash)
      }
      invoices.set(paymentHash, invoice)
      const body = {pr, disposable: false}
      // LUD-25 gates verify on whether the note was named: in the
      // no-comment fallback the preimage verify would hand out IS the
      // note's entire bearer secret, so a mint offering the comment
      // spelling must withhold verify from quotes that used it. A mock
      // that never heard of the comment spelling keeps answering exactly
      // as it always did.
      const verifySafe = !opts.commentAllowed || namedByComment || opts.verifyOnUnnamedMint
      if (opts.verify && verifySafe) body.verify = `${origin}/verify/${paymentHash}`
      // Appended last, and only when the quote really was bound, so a
      // mock that was never told about any of this answers byte for byte
      // what it always answered.
      if (echoBound) body.mintToHash = true
      if (
        echoBound &&
        boundTo &&
        opts.mintReceipt &&
        opts.verify &&
        opts.signatures
      ) {
        body.mint = {h: boundTo, amount: net}
      }
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
      const body = {
        status: 'OK',
        settled: invoice.settled,
        // the preimage IS the bearer secret here - a real SERVICE should
        // think hard before serving it, and a WALLET that receives one
        // must rotate immediately. The exception is a quote the wallet
        // bound with its own h: that note is credited elsewhere, so the
        // preimage is an ordinary payment proof and leaks nothing.
        preimage: invoice.settled || opts.verifyLeaksEarly ? invoice.preimage : null,
        pr: invoice.pr ?? fakeInvoice(invoice.amountMsat, invoice.preimage)
      }
      if (invoice.boundTo && opts.mintReceipt && opts.signatures) {
        body.mint = {
          h: invoice.boundTo,
          amount: invoice.amountMsat,
          ...(invoice.settled
            ? {sig: sign(invoice.boundTo, invoice.amountMsat)}
            : {})
        }
      }
      return send(body)
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
        // The way home, as the reference mint publishes it. A holder with
        // nothing but a note can reach the document carrying this mint's
        // terms and its retired signing keys; without it a wallet that only
        // ever received notes cannot tell an announced key rotation from a
        // substituted key, because the document lives under a username the
        // note never mentions.
        ...(opts.noteInfoPayLink
          ? {
              payLink: opts.payLinkOffOrigin
                ? 'https://elsewhere.example/.well-known/lnurlp/mint'
                : `${origin}/.well-known/lnurlp/${opts.username}`
            }
          : {}),
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

      // The retry branch, before anything is refused for a burned input.
      // This path is a READ: it burns nothing, mints nothing and moves no
      // balance, so it does not go through finish() either. The signature
      // is deterministic over (id, amount), so it is recomputed rather
      // than stored.
      if (opts.retriedMutation === 'replay' && !pr) {
        const outputs = swaps.get(swapIdentity(k1s, h, h2, amountRaw))
        if (outputs) {
          const replay = {status: 'OK'}
          const first = sign(outputs[0].id, outputs[0].amountMsat)
          if (first) replay.sig = first
          if (outputs[1]) {
            const second = sign(outputs[1].id, outputs[1].amountMsat)
            if (second) replay.sig2 = second
          }
          if (opts.serverGeneratedSecrets) {
            replay.k1 = 'a'.repeat(64)
            if (outputs[1]) replay.change = 'b'.repeat(64)
          }
          return send(replay)
        }
      }

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
        note.pendingSince = Date.now()
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
            settled: false,
            pr
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
      // opts.acceptsMissingH2: the misbehaviour where a SERVICE fills in the
      // change note's secret itself rather than refusing. Whoever runs the
      // mint is then a prior holder of half the split.
      if (amountRaw !== null && !h2 && !opts.acceptsMissingH2) return fail('missing h2')
      if (!/^[0-9a-f]{64}$/.test(h)) return fail('missing h')
      if (h2 && !/^[0-9a-f]{64}$/.test(h2)) return fail('missing h2')
      // One id cannot carry two notes, and an id already in use - as a note
      // in any state, as a mint invoice's payment hash, or as the output a
      // bound quote is waiting to credit - must never be minted over: the
      // invoice case points a future payer's money at a stranger's note
      // (its /verify serves the preimage that IS the k1 of whatever sits
      // under that id), and a burned note's id has a preimage every
      // previous holder still knows. Refused with the same reason as any
      // dead k1, so a probe learns nothing about which ids exist.
      if (h2 && h2 === h) return fail('Invalid or already spent k1.')
      for (const outputId of h2 ? [h, h2] : [h]) {
        if (outputIdInUse(outputId)) {
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
        // opts.splitIgnoresBaseFee: the misbehaviour where a SERVICE never
        // learned the split-fee rule at all - no fee out of change, and so
        // no floor to refuse against either.
        let change
        if (opts.splitIgnoresBaseFee) {
          change = changeBeforeFee
        } else {
          if (changeBeforeFee < opts.baseFeeMsat) return fail('insufficient value')
          change = changeBeforeFee - opts.baseFeeMsat
        }
        if (change < 1) return fail('insufficient value')
        for (const {note} of found) note.state = 'burned'
        const sig = mintNote(h, amount)
        const sig2 = mintNote(h2, change)
        swaps.set(swapIdentity(k1s, h, h2, amountRaw), [
          {id: h, amountMsat: amount},
          {id: h2, amountMsat: change}
        ])
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
      swaps.set(swapIdentity(k1s, h, h2, amountRaw), [
        {id: h, amountMsat: total + refund}
      ])
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
  // A flag's value becomes a number only when it really is one. A 64-hex
  // key made of nothing but digits parses as a Number and loses every
  // digit past the seventeenth, so anything outside the safe integer
  // range stays the string it was typed as.
  const coerce = value => {
    if (value === 'true') return true
    if (value === 'false') return false
    if (!/^-?\d+(\.\d+)?$/.test(value)) return value
    const n = Number(value)
    return Number.isSafeInteger(n) || (!Number.isInteger(n) && Number.isFinite(n)) ? n : value
  }
  for (const arg of process.argv.slice(2)) {
    const [key, value = 'true'] = arg.replace(/^--/, '').split('=')
    flags[key] = coerce(value)
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
