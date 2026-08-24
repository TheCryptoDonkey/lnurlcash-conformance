# Sunset on the wire

Status: additive implementation proposal for eventual LUD-25 adoption.

This document records a gap found operating LUD-25 mints, and proposes the
smallest wire change that closes it. It does not modify the upstream LUD-25
draft or dni's reference repositories.

## The switch exists everywhere except the wire

Sunsetting is already a settled convention across the LNURLcash stack. A mint
winding down refuses anything that grows its liabilities — minting, and the
split branch of the withdraw callback — while leaving rotate, merge and melt
open, because none of those increases what the mint owes and a holder still
needs to consolidate and redeem.

It is implemented in both mints, graded, and handled by clients:

| where | how |
|---|---|
| `lnurl-mint` (the reference) | `sunset_mint` in `config.py`, env `SUNSET_MINT` |
| `moneyer` | `MONEYER_SUNSET` |
| `lnurlcash-conformance` | `--sunset`, "refuses anything that grows its liabilities" |
| `lnurlcash-kit`, `notecase`, `lnurlcash-py` | classify the refusal as *definitive*, not transient |

What none of them do is **say so in the discovery document**. There is no
`sunset` field on the mint-address document, and no equivalent on the
`payRequest`. A mint's own state is known to the mint, tested by the grader,
and correctly handled by wallets — and remains invisible until something is
refused.

## Why that matters

A refusal is a fine signal for the operation being refused. It is a poor
signal for everything a holder and a wallet want to decide *before* acting.

**A holder of an outstanding note gets no prompt.** This is the important
one. A bearer note is a claim on one specific operator. When that operator is
winding down, the holder needs to melt — and nothing tells their wallet to
suggest it. The wallet learns only if the holder happens to attempt a split,
or the holder happens to read a message of the day. A wind-down that is
invisible until the mint is gone is a wind-down that strands notes.

**Mint directories and quick-start lists cannot self-update.** Wallets ship
curated lists of public mints for one-tap onboarding. Those lists are
compiled into releases. A mint that retires stays in them until each author
notices and cuts a new build, so users keep being offered a mint that will
refuse them — or that has ceased to exist. A machine-readable flag lets a
wallet grey the entry out on its own, without a release.

**Mint selection has no filter.** A wallet choosing among several mints
cannot rank or exclude one that is retiring. It discovers by trying.

The existing partial answer is `motd`, and it is not sufficient. It is free
prose for humans, not a machine-readable state; and it is a moneyer
extension rather than a LUD-25 field, so the reference mint cannot carry one
at all. An operator running lnurl-mint today has **no in-band channel** to
announce a wind-down.

## Proposed additive wire fields

On the mint-address document (the `withdrawRequest` served at
`/.well-known/lnurlw/<user>`):

```json
{
  "tag": "withdrawRequest",
  "sunset": true,
  "sunsetAt": 1793491200
}
```

| field | type | meaning |
|---|---|---|
| `sunset` | boolean | `SERVICE` is winding down: it refuses operations that grow its liabilities, and keeps redemption open. |
| `sunsetAt` | integer, optional | Unix seconds after which `SERVICE` does not undertake to remain redeemable. |

Both are **absent** rather than `false`/`null` when they do not apply,
following the convention the rest of the document already uses: absent means
the `SERVICE` published nothing, never that the answer is empty.

`sunsetAt` is proposed alongside the boolean rather than deferred because a
wind-down notice is only actionable with a date. The terms template shipped
with moneyer already promises holders notice "at least *n* days beforehand";
`sunsetAt` is what makes that promise machine-readable rather than something
a holder must read prose to discover.

## Candidate normative text for LUD-25

Intended to be transplantable into the draft's mint-address section.

A `SERVICE` that is winding down MAY add `"sunset": true` to its mint-address
document, and MAY add `"sunsetAt": <unix seconds>`. A `SERVICE` that publishes
`sunsetAt` MUST also publish `sunset`. A `SERVICE` MUST NOT publish `sunset`
unless it is in fact refusing operations that grow its outstanding
liabilities.

`sunset` is advisory. It does not change which operations a `SERVICE`
refuses, and a `WALLET` MUST NOT infer from its absence that any operation
will succeed. The refusals themselves remain the authoritative signal, and a
`WALLET` MUST continue to handle them exactly as it does today.

## Wallet requirements

A `WALLET` that reads `sunset`:

- SHOULD surface it before the holder selects that `SERVICE` for minting.
- SHOULD prompt the holder to melt or rotate out any note it holds on that
  `SERVICE`, and SHOULD raise the urgency of that prompt as `sunsetAt`
  approaches.
- MUST NOT treat `sunset` as a reason to relax any check it otherwise makes.
  Signature verification, key pinning and rotation review are unaffected.
- MUST NOT rely on `sunset` for safety. A `SERVICE` that is winding down and
  does not say so is indistinguishable on this field from one that is not,
  which is precisely today's situation.

## Rejected: a successor pointer

An obvious extension is a `successor` URL naming where a retiring mint's
notes may now be redeemed. It is deliberately not proposed here.

A `successor` field is an instruction to send bearer secrets somewhere new,
carried by the party that would benefit from redirecting them. A
compromised or malicious `SERVICE` could point holders at a mint it
controls, and a holder acting on it would be handing over live notes. The
field would need an authentication story at least as strong as the note
signatures themselves before it could be safely honoured, and that is a
larger design than this one.

`sunset` has no such property: the worst a lying `SERVICE` achieves by
publishing it is to discourage its own use.

## Compatibility

Purely additive.

- A `SERVICE` that does not implement it omits both fields, and behaves
  exactly as today.
- A `WALLET` that does not read them is unaffected: the refusals it already
  handles are unchanged and remain normative.
- No existing field changes meaning, and no operation changes behaviour.

## Conformance

`lnurlcash-conformance`'s `--sunset` mock should publish `sunset: true` on
the mint-address document alongside the refusals it already produces, so that
wallet-side handling of the field can be graded rather than only the
wallet-side handling of the refusal. A `--sunsetAt=<ts>` companion would let a
grader check that a wallet escalates as the date nears.

Worth grading on the wallet side: that a `WALLET` still handles a sunsetting
`SERVICE` correctly when the field is **absent**, since that is the case
every deployed mint presents today.
