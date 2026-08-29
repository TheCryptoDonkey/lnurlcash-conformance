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

## Who does what, as of 2026-08-29

| implementation | unnamed quote | agrees with |
| --- | --- | --- |
| LUD-25 draft, line 80 | MUST fall back to `k1=P` | - |
| `dni/lnurl-mint` `b257d58` | rejected outright | this suite |
| `bitkarrot/lnurlmint` | falls back | the draft |
| `moneyer` (default) | falls back | the draft |
| `moneyer` (`REQUIRE_COMMENT=1`) | rejected outright | this suite |

The reference mint's commit predates any spec change: it landed 2026-08-28,
two days after the draft was last touched, with no accompanying PR comment.
The reading taken here is that the mint leads and the draft will follow.

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
