# Mandatory comment-bound minting

**Status:** adopted by the current LUD-25 draft.

This file is the historical record for a rule the conformance suite enforced
before the draft did. It is no longer a local override.

At `fc1296c`, LUD-25 required a missing or malformed mint comment to fall back
to a note keyed by the Lightning payment preimage. The suite rejected that
fallback because every routing hop learns the preimage and some funding
sources do not return one at all.

The reference mint adopted fail-closed behaviour in `b257d58` on 2026-08-28.
LUD-25 then adopted the same rule in `c9bf5d` and made the rejection ordering
explicit in `70f09c` on 2026-08-31.

The current draft contract is therefore:

1. A minting `payRequest` advertises `commentAllowed: 64`.
2. `WALLET` persists a fresh 32-byte secret before requesting an invoice.
3. It sends `comment=hex(sha256(secret))`.
4. `SERVICE` rejects a missing or malformed comment before creating an
   invoice.
5. On settlement, the note is credited at the comment hash. The payment
   preimage is settlement proof and never a bearer credential.

The `mintToHash` `h` parameter remains an additive Moneyer/ForgeSworn
compatibility field. A service may accept it alongside `comment`, but it does
not replace the mandatory comment and both fields must identify the same
output.

Relevant upstream text:

- <https://github.com/lnurl/luds/pull/301>
- <https://github.com/lnurl/luds/commit/c9bf5d459f64>
- <https://github.com/lnurl/luds/commit/70f09cc64e47>
