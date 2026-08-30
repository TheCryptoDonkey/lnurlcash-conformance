# Comment protection is mandatory here, and the draft has not caught up

**Status:** this suite deliberately grades against a rule LUD-25 does not yet
state. Recorded here because a conformance suite that quietly diverges from
the document it names is worse than one that diverges loudly.

## What the draft says

Line 80 of the draft ([PR #301](https://github.com/lnurl/luds/pull/301), read
at `fc1296c`):

> If `SERVICE` receives no `comment` on a mint payment, or one that isn't a
> bare hex-encoded 32-byte hash, it MUST fall back to crediting the note as
> `k1=P` exactly as described above [...]

So an unnamed quote mints a note keyed by the payment preimage, and the
draft's opening claim (line 12) follows from it: a wallet that knows nothing
about LNURLcash can pay a mint like any other `payRequest`.

## What this suite requires instead

A mint that advertises comment protection - `commentAllowed >= 64`, or
`mintToHash` - MUST refuse a quote that names no output, by either spelling.
Refusing is graded as correct; falling back to a preimage-keyed note is
graded as a failure.

## Why

Two reasons, and the second is the one that makes it not merely a preference.

**The preimage is not the wallet's secret to keep.** A Lightning preimage
propagates back hop by hop as each node settles its outgoing HTLC. Every
routing node on the payment legitimately learns `P`, often before the payer
finishes processing the payment. The draft acknowledges this at length in its
Security considerations, and answers it by advising the wallet to rotate the
note immediately. That is a race the wallet can lose, and the fallback is the
only thing that puts it in one.

**A preimage-keyed note cannot be minted at all on some funding sources.**
`dni/lnurl-mint` [issue #29](https://github.com/dni/lnurl-mint/issues/29)
adds a Spark (Breez SDK) funding source, and notes that a spark-routed
payment completes with no preimage. There is nothing to key the fallback
note by. A mint on such a backend cannot implement line 80 as written - not
because it declines to, but because the value the rule names does not exist.

## The reference behaviour, checked rather than inferred

The rules above were first read off `router.py`. They have since been checked
against the reference mint's own tests (`tests/test_comment_protection.py` at
`b257d58`), because a suite grading an inferred model of an implementation is
worse than one grading nothing:

| what this suite requires | dni's test |
| --- | --- |
| absent `comment` refused | `test_missing_comment_is_rejected` |
| malformed `comment` refused | `test_malformed_comment_is_rejected` |
| capability always advertised | `commentAllowed: int = 64`, a fixed model field |
| `verify` served on a named quote | `test_verify_advertised_whenever_verify_is_enabled` |

One check here is stricter than anything dni asserts: this suite requires the
refusal to arrive with no `pr`, so a wallet cannot pay for a quote the mint
was always going to reject. `get_pay_callback` does raise before
`create_invoice`, so the reference satisfies it - but nothing in his tests
pins that ordering, and a refactor could lose it silently.

The old `verify`-on-fallback prohibition is not merely unenforced here, it is
unreachable: with no fallback there is no unnamed quote for `verify` to leak
a note secret through. dni's test asserts exactly that shape.

## Who does what, as of 2026-08-29

| implementation | unnamed quote | agrees with |
| --- | --- | --- |
| LUD-25 draft, line 80 | MUST fall back to `k1=P` | - |
| `dni/lnurl-mint` `b257d58` | rejected outright | this suite |
| `bitkarrot/lnurlmint` | falls back | `lnurl-mint` as of 27 Aug |
| `moneyer` (default) | falls back | the draft |
| `moneyer` (`REQUIRE_COMMENT=1`) | rejected outright | this suite |

The reference mint's commit predates any spec change: it landed 2026-08-28,
two days after the draft was last touched, with no accompanying PR comment.
The reading taken here is that the mint leads and the draft will follow.

Worth being exact about that third row, because it is easy to read as
independent corroboration of the draft and is not. The LNbits extension is
built from `lnurl-mint` at `5a4603d` (27 Aug), which carries dni's comment
feature (#24) but predates the mandate (`b257d58`, 28 Aug) by a day. It falls
back because that is what dni's own code did when it was forked, not because
anyone weighed the draft's rule and chose it. Its author has said the
extension is experimental, not yet tested end to end, and that the spec review
comes after a WASM LNbits port.

So no implementation has independently chosen the fallback. Every mint that
still has it is either dni's pre-28-August code, a fork of it, or moneyer -
where it is now behind a flag.

## What this costs, and what it does not

**It costs line 12.** "Fully optional and backward-compatible" stops being
true. A wallet that has never heard of LNURLcash sends a bare LUD-06 request
and gets an error, not an invoice. That is a real loss and should be argued
for on the merits rather than absorbed quietly - if the draft adopts the
mandate, line 12 needs rewriting in the same commit.

**It does not require every mint to offer comment protection.** The rule is
scoped to mints that advertise it. A mint offering no naming capability at
all is still graded "not offered", as before, and is not failed. Making
comment protection mandatory for *every* mint is the further step, and it is
deliberately not taken here while the draft is unchanged.

## What would retire this document

Either outcome ends the divergence, and this file goes with it:

- the draft adopts the mandate, in which case delete this and cite line 80;
- the draft reaffirms the fallback, in which case revert the flip - the
  fixture for the old behaviour is still here, as `commentFallsBack`.

## Known consequence

Under this rule the suite fails two mints that are doing exactly what the
draft asks: `bitkarrot/lnurlmint`, and `moneyer` in its default
configuration. That is intended, and is the cost of grading ahead of the
document. Anyone gating CI on the grade should pin an exact version.
