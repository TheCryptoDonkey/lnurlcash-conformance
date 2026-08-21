# lnurlcash-conformance

Conformance vectors, an adversarial mock mint, and a grader for LNURLcash
([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) implementations.

Three things, all usable independently:

| | |
| --- | --- |
| **`vectors/`** | language-neutral JSON. Load them directly from your test suite, in any language. |
| **`mock-mint/`** | a real HTTP mint that can be told to misbehave, on demand, in every way the spec warns about. |
| **`runner/`** | `lnurlcash-conform <mint>` — grades a live service and exits non-zero if it is non-compliant. |

If you are writing an LNURLcash implementation in any language, run these
before you run real sats through it.

## Why this exists

LNURLcash notes are bearer instruments: whoever holds the `k1` can spend it,
and a mistake is silent, immediate and irreversible. The wire protocol is
small enough that anyone can implement it in an afternoon, which is exactly
the problem — the protocol is easy and the *discipline* is not. Ambiguous
mutations, melt semantics, who generates a replacement secret, which end of
a signature carries the recovery id: get any of those wrong and it works
perfectly until it costs somebody their money.

These vectors are the shared statement of what the discipline is, so that
every implementation can be wrong in the same place at the same time, and
find out about it in CI rather than in production.

## Using the vectors

```bash
npm install --save-dev lnurlcash-conformance
```

They are plain JSON — load them from any language, no dependency required:

```js
const cases = JSON.parse(readFileSync('vectors/signature.json', 'utf8')).cases
for (const c of cases) {
  assert.equal(verify(c.k1, c.amountMsat, c.signature, c.mintPubkey), c.valid)
}
```

| File | Covers |
| --- | --- |
| `signature.json` | offline verification, both recovery-id orderings, malformed input |
| `bech32.json` | LUD-01 encoding, round trips, corrupted checksums |
| `url-admission.json` | which URLs may be fetched, and why `data:` must never be |
| `input-resolution.json` | bech32, LUD-17, Lightning Addresses, bare domains |
| `note-url.json` | parsing and building note URLs, secret casing, stale signatures |
| `fees.json` | fee advertisement, application, gross-up minimality, overflow |
| `bolt11.json` | amount extraction, invoice equality, preimage shape |
| `callbacks.json` | the exact query each operation puts on the wire |
| `responses.json` | classifying every reply, including the ambiguous ones |
| `withdraw-info.json` | the informational GET, and what makes a response invalid |
| `pay-request.json` | minting, LUD-11 disposable, LUD-21 verify |
| `lifecycle.json` | behavioural requirements, as scenarios to drive |
| `threat-suite.json` | the transport/exposure scorecard — candidate spec options against fixed attacks (non-normative) |

Regenerate with `npm run generate`; check them with `npm test`, which
verifies every digest recomputes, every declared signature really does
verify, and every fee expectation follows from the formula.

## The mock mint

```bash
npx lnurlcash-mock-mint --port=8899
```

Prints a lightning address, a spendable 21 sat note, and its pubkey.
Nothing is payable — it invents its invoices, and a conformance run must
never be mistakable for a mainnet one.

Every misbehaviour is a flag, and each reproduces a real failure a holder
must survive:

| Flag | What it does |
| --- | --- |
| `--dropAfterMutation` | applies the mutation, then hangs up. The outcome is genuinely unknowable. |
| `--unconfirmedMutation` | replies 200 with a body confirming nothing |
| `--malformedJson` | replies with something that is not JSON |
| `--echoWrongK1` | answers the informational GET with a different `k1` |
| `--lieAboutValue=N` | reports a `maxWithdrawable` it never signed |
| `--signatureLayout=leading` | emits the recovery id at the other end |
| `--signatures=false` | issues no signatures at all |
| `--serverGeneratedSecrets` | hands back a secret it generated — the exposure `h` exists to close |
| `--meltNeverSettles` | holds every melt in flight, so notes stay `pending` |
| `--meltAlwaysFails` | fails every payment, restoring the note |
| `--slowMs=N` | delays every response |
| `--sunset` | refuses anything that grows its liabilities |
| `--baseFeeMsat=N --feePpm=N` | advertises and withholds a mint fee |
| `--roundFeeToSat` | rounds the withheld fee up to a whole sat — the note mints short of the formula |
| `--verifyLeaksEarly` | serves the preimage from verify before settlement — the bearer secret, to anyone with the hash |
| `--verify=false` | no LUD-21 endpoint at all, not merely unadvertised |
| `--withdrawLinkForm=lnurlw` | spells `withdrawLink` as `lnurlw://host/w` instead of the plain `https://host/w` the reference mint emits. Both are legal; a client has to take both |

As a library, for your own test suite:

```js
import {createMockMint} from 'lnurlcash-conformance/mock-mint'

const mint = await createMockMint({dropAfterMutation: true})
mint.state.creditNote(k1, 21000)
// ... drive your client against mint.url, then
await mint.close()
```

`mint.state` exposes `creditNote`, `noteState`, `settleMelt`, `failMelt` and
the raw note and invoice maps, so a test can assert what the SERVICE
actually did rather than what it said.

## The grader

```bash
npx lnurlcash-conform mint@example.com
```

Read-only by default: resolves the payRequest, checks the `withdrawLink`
(either legal spelling, and the report says which one the mint uses),
the fee advertisement, invoice amounts, that LUD-21 verify serves no
preimage before settlement (on a mint that value IS the bearer secret, and
everyone on the payment's route knows the payment hash), whether an
unknown note is reported distinguishably from a spent one, and the
experimental mint address.

One check needs a real payment, which the runner cannot make on its own.
Given a freshly minted, never-rotated note and what its mint invoice was
paid at, it compares the note's value against the advertised fee:

LUD-25 says nothing about whether that fee rounds, and the two live
implementations differ. dni's lnurl-mint ceilings it to a whole sat on
purpose, so the mint is never short a sat; moneyer withholds the
msat-exact amount. Both pass. The check grades the range between them and
names which it saw, and a msat outside it either way fails - a mint taking
more than the ceilinged fee, or crediting more than it advertised.

```bash
npx lnurlcash-conform mint@example.com --note='lnurlw://...?k1=...' --paid=500000
# or --pr=<the mint invoice>, when it carries an amount
```

This is still read-only. The full run spends:

```bash
npx lnurlcash-conform mint@example.com --note='lnurlw://...?k1=...' --spend
```

It burns the note it is given and prints where the value ended up. It
checks that the informational GET is idempotent and echoes the queried
`k1`, that the URL's own `amount` is ignored, that a rotate with no `h` is
refused, that a rotate returns no secret, that signatures verify against the
advertised `mintPubkey`, that split and merge conserve value - exactly,
under LUD-25's fee algebra, when the mint's fee advertisement is known -
and that a burned secret cannot be replayed. It also probes three adversarial shapes a
mint must refuse atomically: a duplicated `k1` (which a careless mint counts
twice, minting money from nothing), an output hash that collides with an
existing note id (minting over it hands the output to whoever already knows
that id's preimage), a split whose `h` equals `h2` (one id cannot carry
two notes), a split naming only one output hash (a mint that accepts it is
generating the change secret itself), and a split leaving change one msat
short of the advertised base fee (which LUD-25 says to refuse with
`insufficient value`, not to serve at a loss). And it replays the callback as a POST and as an OPTIONS
preflight - real HTTP stacks send both on their own initiative, so the
mutating endpoint must answer GET only. After every refusal it confirms the refused note is still
spendable. Use a small note. Exit code is non-zero if anything failed.

**What the grader cannot reach.** It never melts. Melting spends real sats
against a real mint, which is not something a grading tool may decide to do,
so `pending` on a k1 mid-melt, restoring the note when the outgoing payment
fails, and the melt's own LUD-21 `verify` are all outside what a grade can
say anything about. They are not unspecified and not untested: the mock mint
implements every one of them (`meltNeverSettles`, `meltAlwaysFails`), so a
client suite driving the mock covers the whole melt path. A clean grade
means the read-only and non-melt mutating surface is compliant, no more.

The grader shares no code with any LNURLcash library — it is written against
`fetch` and `@noble` directly. A grader that shared an implementation with
the thing it grades would agree with that implementation's mistakes, which
is the one thing it must never do.

## Scope and neutrality

This repo takes no position on whose implementation is correct. Where the
vectors and an implementation disagree, either may be wrong, and the LUD-25
PR is where that gets settled.

Spec and reference implementations, all by dni, all MIT:

- [LUD-25 draft](https://github.com/lnurl/luds/pull/301)
- [lnurl-mint](https://github.com/dni/lnurl-mint) — the reference service
- [lnurl-wallet](https://github.com/dni/lnurl-wallet) — the reference wallet

Implementations to run these vectors against are indexed in
[awesome-lnurlcash](https://github.com/TheCryptoDonkey/awesome-lnurlcash).

Contributions of vectors are welcome, particularly from implementers who
found a case these missed. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT.
