# Contributing

The most valuable contribution here is a vector for a case that bit you.

## Adding a vector

Vectors are generated, not hand-written: edit `tools/generate.mjs` and run
`npm run generate`. That keeps every derived value — digests, signatures,
encodings, fee expectations — computed from the scheme rather than typed in
by hand, which is where the mistakes live.

Then run `npm test`. The self-check recomputes every declared digest,
verifies every signature the vectors claim is valid, and confirms every fee
expectation follows from the formula. A vector that cannot survive that is
a bug report about itself.

Two rules:

**Derive, don't assert.** If an expectation can be computed from the spec's
own definition, compute it. Hand-written numbers are how a mistake becomes
canonical.

**Say why.** Most cases carry a `why`. A vector that fails should tell the
implementer what the case is protecting them from, not just that they got a
different answer.

## Disagreements

If a vector and an implementation disagree, either may be wrong. The
[LUD-25 PR](https://github.com/lnurl/luds/pull/301) is where the spec gets
settled; open an issue here with the case and what your implementation does,
and if the spec turns out to be ambiguous, that is worth raising there too —
an ambiguity found now is cheaper than two implementations that quietly
disagree forever.

## Scope

In scope: vectors, mock mint misbehaviours, grader checks.

Out of scope: an LNURLcash implementation. This repo must not depend on one,
including the mock mint and grader, which are written against `fetch` and
`@noble` directly. A grader that shares code with what it grades inherits
its mistakes.
