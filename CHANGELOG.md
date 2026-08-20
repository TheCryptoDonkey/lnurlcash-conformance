# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps
may add or tighten checks that a previously-passing mint now fails; pin an
exact version if you gate CI on the grade.

## Unreleased

- `withdrawLink` has two legal spellings in the wild. LUD-25 calls it "a
  raw, non bech32-encoded URL as described in LUD-17", and LUD-17 describes
  both the `lnurlw://` scheme and the plain `https://` URL it stands for.
  lnurl-mint (and the spec's own diagram) emit `https://mint.example/w`;
  moneyer emits `lnurlw://moneyer.dev/w`. The mock mint only ever served
  the second, so a client that broke on the reference mint's form would
  still have passed here.
  - The mock mint takes `withdrawLinkForm: 'plain'` to serve the
    `https://` spelling. Default unchanged.
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
