# NIP-47 for bearer-note wallets

`draft` `optional`

How a wallet whose funds are LNURLcash ([LUD-25](https://github.com/lnurl/luds/pull/301))
bearer notes answers [NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md),
so that a client which has never heard of LUD-25 can pay and be paid through
one without knowing what is behind it.

This is written from two implementations that were built independently and do
not agree. Where they agree, it is recorded. Where they disagree, this picks
one and says why. The kind numbers and method names are NIP-47's; nothing here
adds a method.

## Why a profile and not a library

NIP-47 was written for a Lightning node. A bearer-note wallet is not one, and
the gap shows up in the same five places every time:

- a note is minted by a **quote**, so `make_invoice` hands out an invoice for
  money the wallet does not have yet;
- a **melt** returns in flight, so `pay_invoice` is asked for a preimage the
  wallet may not be able to produce inside the request;
- a mint charges a **split fee**, so the balance falls by more than the invoice;
- the wallet holds notes at **several mints**, and NIP-47 carries no way to
  name one;
- notes can be **pending or ambiguous**, which is a state a node's balance
  never has.

Two implementations hit all five and answered some of them differently. A
client cannot tell which it is talking to, so the differences are interop bugs
rather than taste.

## What is already settled

Both implementations arrived at these independently. Treat them as the floor.

A wallet **MUST** serialise `pay_invoice` per connection, so that a budget
check and the record of what it spent cannot interleave. Two payments arriving
together must not both read the same remaining budget and both decide there is
room.

A wallet **MUST** drop requests older than a bounded age without answering
them. A `pay_invoice` replayed after the wallet was offline is a second
payment. A client that genuinely wants to retry sends a fresh request.

A wallet **MUST** debit the budget when a payment's outcome is unknown. The
money may be in flight. A wallet that only debits on proven settlement can be
walked past its budget by anyone who can make settlement uncertain.

A wallet **MUST** persist a spend before answering the request that caused it.
A budget that was spent has to be on disk before the payer is told it worked,
or a crash between the two gives the grant its allowance back.

## `pay_invoice`

### The preimage is not optional

On success a wallet **MUST** return a `preimage` of 64 lowercase hex
characters, and **MUST NOT** return success without one.

This is the one live interop break between the two implementations, and it is
already settled by precedent elsewhere. Alby Hub sends `"preimage": ""` on
every unsettled invoice, so clients learned to read an empty string as *absent*
on a transaction object. `pay_invoice` is the other case: there the preimage is
the evidence that settlement happened, not an optional detail, and clients
verify it against the invoice's payment hash. A wallet that answers success
with `""` is refused outright by any client that does.

If the mint reveals no preimage, that is not a success. See below.

### Unknown is not failure, and NIP-47 cannot say so

A melt returns in flight. Settlement may not be provable inside the request
window, and a wallet must not fabricate a preimage to fill the gap.

Today a wallet in that position **MUST** answer with an error, **MUST** keep
the budget debited, and **SHOULD** say in the message that the payment may
still be in flight. Both implementations use `OTHER`; a wallet **SHOULD** use
`OTHER` for this rather than `PAYMENT_FAILED`, which claims more than it knows.

**A client MUST NOT read an error from `pay_invoice` as proof that no money
moved.** That is an uncomfortable thing to write down and it is the honest
state of the protocol. `PAYMENT_FAILED` means failed; every other error code
means the wallet is not sure.

The proper fix is upstream and small. NIP-47 transaction objects already carry
a `state`, and `pending` is already a valid value. `pay_invoice` has no way to
answer with one. Allowing it to return a transaction object in
`state: "pending"`, which the client then follows with `lookup_invoice`, reuses
vocabulary that exists rather than inventing an outcome. That belongs in the
NWC extensions repository, not here, and it is not specific to bearer notes:
it is true of any wallet whose settlement is asynchronous.

### Refusals must be distinguishable from attempts

A wallet **MUST** distinguish a payment it declined to attempt from one it
attempted and cannot account for. Insufficient funds, a malformed invoice and
an exhausted budget are refusals: nothing moved, and the budget **MUST NOT** be
debited. Anything after the first request reaches the mint is an attempt, and
the rules above apply.

### Fees

A wallet **SHOULD** report `fees_paid`, measured as what the balance actually
lost beyond the invoice amount rather than quoted from the mint. On a
bearer-note wallet the cost of a payment includes the mint's fee for splitting
a note down to the amount, which is invisible to a client that only sees the
invoice.

A wallet **MUST** check a payment against the budget inclusive of the fee it
expects to pay. Both current implementations check the invoice amount alone and
then pay amount plus fee, so a connection can exceed its grant by the fee on
every payment. Small, and still wrong.

### Amount-less invoices

A wallet **SHOULD** accept a zero-amount invoice and take the amount from the
request's `amount` parameter, which is what NIP-47 defines it for. A wallet
that does not support them **MUST** refuse cleanly rather than pay some other
amount.

Where the invoice names its own amount and the request also carries one, a
wallet **MUST NOT** pay an amount the invoice does not name. Refusing the
mismatch outright is the safest reading and one implementation already does it.

## `make_invoice` and `lookup_invoice`

### An invoice is a quote, and the money arrives later

`make_invoice` on a bearer-note wallet buys a mint quote. The invoice is real
and payable, but no note exists until it is paid and the wallet claims it.

A wallet **MUST** be able to answer `lookup_invoice` for an invoice it issued,
from the moment it issued it, and **MUST** keep that record after the note is
claimed.

`settled_at` **MUST** mean the wallet holds the note, not that the invoice was
paid. Until the claim lands the wallet cannot spend the money, and a client
told otherwise will act on funds that are not there yet.

The amount reported after a claim **MAY** differ from the invoice amount,
because the mint's fee comes out in between. A wallet **SHOULD** report what it
actually holds.

### Which mint

NIP-47 carries no way to name a mint, so `make_invoice` **MUST** use the
wallet's own default and the choice is the wallet's alone. A client cannot ask
for one and **MUST NOT** assume any particular mint is behind an invoice.

An optional `mint` parameter is the one genuinely method-shaped extension this
profile implies. It is drafted separately and is not required to implement
anything here.

## `get_balance`

A wallet **MUST** count only notes it can spend right now. Notes that are
pending, in flight, or parked ambiguous after a dropped connection **MUST NOT**
be counted.

The failure this prevents: a client reads the balance, sends a `pay_invoice`
for it, and the wallet refuses for insufficient funds against a number it
supplied itself moments earlier.

A wallet **MAY** decline `get_balance` entirely. A balance tells a stranger how
much there is to steal, and both implementations treat it as opt-in per
connection.

## What a connection grants

Not strictly interop, and both implementations agree, so it is recorded here
for anyone building a third.

A connection **SHOULD** default to methods that neither spend nor disclose a
balance. `get_info`, `make_invoice` and `lookup_invoice` are a useful grant on
their own: they let something be paid without letting it pay.

A connection that may spend **MUST** carry a budget. There should be no
unlimited grant available to hand out by accident.

A wallet **SHOULD** answer a request id it has already answered with the
original answer, rather than doing the work twice. A relay will hand the same
event over again.

## Open

- Whether `pay_invoice` may answer `state: "pending"`, upstream in the NWC
  extensions repository.
- An optional `mint` parameter for `make_invoice`.
- Everything LUD-25-specific here rests on a draft. If
  [lnurl/luds#301](https://github.com/lnurl/luds/pull/301) lands changed, the
  quote, fee and claim sections change with it.
