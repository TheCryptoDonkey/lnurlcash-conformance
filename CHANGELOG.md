# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps
may add or tighten checks that a previously-passing mint now fails; pin an
exact version if you gate CI on the grade.

## 0.2.0 - unreleased

- New `vectors/derivation.json`: deterministic note secrets from a BIP39
  seed, so that a wallet can be restored from words alone and two
  implementations of the same wallet derive the same notes.
  - `k1` is WALLET-generated in LUD-25 and the draft says nothing about how
    one is produced, so a wallet is free to derive it instead of drawing it
    at random. Nothing about this is observable on the wire: the mint still
    only ever sees `sha256(k1)`.
  - The scheme, in full, so this entry alone is enough to reimplement it.
    `root = HMAC-SHA256(key = utf8("lnurlcash-note-v1"), msg = seed bytes)`,
    then `k1 = HMAC-SHA256(key = root, msg = utf8(host + ":" + index))`.
    Output is 32 bytes, lowercase hex, the same size as a payment preimage.
    `host` is the mint host as the wallet stores it, lowercase, with the
    port when there is one; `index` is decimal ASCII counting from 0. The
    seed is the 64-byte BIP39 seed of a 12-word English mnemonic with no
    passphrase.
  - Cases cover the standard `abandon ... about` mnemonic at `mint.example`
    for indices 0, 1, 2, 19 and 20 (19 and 20 straddle a 20-index gap
    limit), a second mnemonic at the same host and index to show the seed
    separates them, and a host carrying a port.
  - Every case carries `seedHex` as well as the mnemonic, so an
    implementation with no BIP39 library can still test the derivation
    half on its own.
  - `@scure/bip39` is a devDependency, used only to generate the file. The
    published package gains no runtime dependency.

- Self-check covers the new file: every `k1` recomputes from its own
  `seedHex`, every mnemonic validates against the English wordlist and
  produces the stated seed, and no two cases collide.

- Three optional extensions a mint may publish, none of them in LUD-25,
  all of them absent or off unless asked for. A mock started with no
  options answers byte for byte what it answered before, and a mint
  publishing none of them is not graded down.

  - **Mint info** on the experimental discovery endpoint. Mock knobs
    `name`, `description`, `contact` (`{nostr, email, url}`), `tosUrl`,
    `motd`, `version` and `previousPubkeys`, appended after the existing
    fields so nothing above them moves. `fees: {baseFeeMsat, feePpm}` is
    emitted whenever a fee is configured: the structured twin of the fee
    line in the payRequest metadata, which stays exactly as it was.
    `nodeCapacity` is emitted as before, under that name.

  - **Liabilities**. Mock knob `stats: true` (default `false`, and when
    off `/stats` falls through to the same 404 every unknown path gets)
    serving `GET /stats` as `{at, outstandingMsat, outstandingNotes,
    pendingMsat, pendingMelts, oldestPendingMeltAgeSecs, localBalanceMsat?,
    coverage?, reconciledAt}`. Notes here are not blinded, so a mint can
    state what it owes exactly. A note mid-melt counts under `pending`
    rather than `outstanding`: its value is committed, not free, and it
    comes back if the payment fails. `coverage` is
    `localBalanceMsat / outstandingMsat` to four decimal places, omitted
    when nothing is owed. Knob `localBalanceMsat` sets what the node
    claims to hold, so a mock can be told to look under-covered.

  - **Signing-key rotation**. Mock knobs `previousPrivateKey` (an old key
    the mock still holds; its public half joins `previousPubkeys` on its
    own) and `previousPubkeys`. `state.creditNote(k1, amount,
    {previousKey: true})` signs one note under the old key and leaves the
    rest under the new, and `/_test/credit?...&key=previous` does the
    same out of process. `signWithPreviousKey` issues every note under the
    old key while still advertising the new one: the mid-rotation state a
    mint passes through when the advertisement moves before the signer.

- Grader, all soft, all read-only:

  - `publishes a mint address (experimental, optional)` keeps its name and
    its existing assertions, and now checks the shape of the new fields
    when they are present: the string fields non-empty, `tosUrl` and
    `contact.url` fetchable, `contact.nostr` decoded as an npub rather
    than pattern-matched, `contact.email` address-shaped, `fees` numeric
    and not negative, `previousPubkeys` an array of 33-byte compressed
    pubkeys in hex that does not merely restate the current one. A
    malformed field is a warning, never a failure, and absence is neither.
    The pass line names which fields it saw. A mint publishing its node
    capacity as `nodeCapacityMsat` warns as well: the wire name carries no
    suffix, and anything mapping the documented name reads undefined.

  - New `publishes liabilities (optional)`. No `/stats`, or a `/stats`
    that answers with something other than a liabilities body, is a
    warning and nothing more. When it does answer, `outstandingMsat` must
    be a number at or above zero and `coverage` must be numeric when
    present. A node holding less than the mint owes warns rather than
    fails: whether a mint is fully backed is the operator's to disclose,
    and one that publishes an uncomfortable number is behaving better than
    one that publishes nothing.

  - `signs the notes it issues (optional)` accepts a signature recovering
    any key the mint publishes, the current `mintPubkey` first and then
    anything in `previousPubkeys`, and says which it was. Grading a note
    issued before a rotation as forged would punish a mint for rotating
    properly. `gradeNote` takes the list as `options.previousPubkeys`; the
    CLI carries it across from the discovery endpoint on its own, which
    `gradeMint` now hangs off the payRequest it returns as `mintAddress`.

- `signature.json` gains a `rotation` block: a note signed under a
  previous key with both keys published (valid), the same signature byte
  for byte with only the current key published (invalid), a
  current-key signature alongside a published previous one (valid), and a
  signature under a key that was never published (invalid). The cases
  carry `mintPubkeys` as a list rather than the single `mintPubkey` the
  existing cases carry, and live in their own block for that reason: a
  verifier that knows nothing about rotation reads `cases` and is
  completely unaffected by this release.

## 0.1.2 - 2026-08-21

- The minted-value check took a band instead of a single number, because
  it was failing the reference implementation.
  - LUD-25 states the mint fee as `base_fee_msat` plus a ppm cut and says
    nothing about rounding. dni's lnurl-mint ceilings that fee to a whole
    sat on purpose, so the mint is "never short a sat"; moneyer is
    msat-exact. Every public mint on the awesome list except moneyer runs
    lnurl-mint, so the majority of live services round.
  - The check asserted equality against the msat-exact formula, and even
    named the rounding in its failure message as something "the formula
    does not allow". Measured on real sats: 40,000 msat at
    mint.forgesworn.dev with a 1000 + 1000 ppm fee credits 38,000, not
    38,960. A clean grade was unreachable for the reference.
  - Deciding which reading is right is not this repo's job - "either may
    be wrong, and the LUD-25 PR is where that gets settled". So the
    compliant answer is now the range between the two: the formula is the
    most a holder can be credited, the sat-ceilinged fee the least. The
    report names which one it saw.
  - Both edges are graded, and selfgrade proves it: a msat past the
    ceilinged fee fails, and so does crediting more than the formula. A
    band with no edges would grade nothing. The mock's `roundFeeToSat` is
    reclassified from a misbehaviour to the reference's behaviour, and
    gains `extraFeeMsat` for landing outside the band deliberately.

- Two refusals LUD-25 spells out were never graded. Both are reachable
  against a live mint, and both were being stepped around rather than
  tested.
  - `refuses a split with no h2`: a split names two outputs, so a mint
    given only `h` either refuses or invents the change note's secret
    itself. The second is the exact prior-holder exposure wallet-generated
    secrets exist to close, and it was ungraded.
  - `refuses a split whose change cannot cover the base fee`: the grader
    already knew the advertised base fee, and skipped (`note too small to
    split past the advertised base fee`) rather than deliberately leaving
    change one msat short of it. It now does that on purpose and expects
    `insufficient value`. Warns when no fee is advertised, since the rule
    cannot bite.
  - Both confirm the note survives the refusal, and both are self-verified:
    the mock gains `acceptsMissingH2` and `splitIgnoresBaseFee`, and
    selfgrade asserts each is caught by name rather than by failure count.
- The grader never melts, so `pending`, restore-on-failure and a melt's own
  LUD-21 `verify` cannot be graded against a live service - melting real
  sats is not something a grader may do on its own initiative. The mock
  covers all three for client-side suites. Said so in the README, which
  previously left the gap to be inferred.

- `withdrawLink` has two legal spellings in the wild. LUD-25 calls it "a
  raw, non bech32-encoded URL as described in LUD-17", and LUD-17 describes
  both the `lnurlw://` scheme and the plain `https://` URL it stands for.
  lnurl-mint (and the spec's own diagram) emit `https://mint.example/w`;
  moneyer emits `lnurlw://moneyer.dev/w`. The mock mint only ever served
  the second, so a client that broke on the reference mint's form would
  still have passed here.
  - The mock mint now serves the plain `https://` spelling by default,
    matching the reference mint, and takes `withdrawLinkForm: 'lnurlw'`
    for the other. A test asserting the old `lnurlw://` default needs
    updating (lnurlcash-kit's did).
  - `pay-request.json` gains accepted cases for the plain form and for an
    onion host; a parser must pass both through untouched.
  - The grader accepts either spelling, rejects a bech32 `lnurl1...` value,
    and names the form in its report. Its three ad-hoc `lnurlw://` rewrites
    are now one exported `fromLud17`.
  - Selfgrade runs the compliant mock in both forms.

## 0.1.1 - 2026-08-20

- The mock mint's mint-address response now carries the node stats
  lnurl-mint advertises: `nodeCapacity` (msat), `nodeNumChannels` and
  `nodeNumPeers`. `nodeCapacity` is the field an implementation is most
  likely to rename on its own side and then forget to map - lnurl-wallet
  and lnurlcash-kit both did, and neither test caught it, because nothing
  they tested against ever sent the wire name.

## 0.1.0 - 2026-08-20

First release. Three things, usable independently.

- **`vectors/`** - language-neutral JSON test vectors, generated and frozen.
  Load them from a suite in any language; the release gate regenerates them
  and refuses to publish if a single byte moved.
- **`mock-mint/`** - a real HTTP mint that misbehaves on demand, in every
  way the spec warns about: destroyed responses, never-settling melts,
  wrong-`k1` echoes, mutation on non-GET, secrets served before settlement.
  Typed for TypeScript consumers.
- **`runner/`** - `lnurlcash-conform <mint>` grades a live service and exits
  non-zero if it is non-compliant. Read-only by default; `--spend` opts into
  the mutating checks, `--note`/`--paid` adds the minted-value check without
  spending anything.

Checks in this release cover the six LUD-25 endpoints, the fee algebra on
mutations (base fee from split change, `(n-1)` refunds on merge, insufficient
value), the adversarial mutation shapes a mint must refuse, that a mint never
mutates on a non-GET request, and that LUD-21 verify serves no secret before
settlement.
