# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps
may add or tighten checks that a previously-passing mint now fails; pin an
exact version if you gate CI on the grade.

## Unreleased

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
