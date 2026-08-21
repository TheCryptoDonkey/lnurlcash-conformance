// Types for the mock mint, so TypeScript consumers get the misbehaviour flags
// checked rather than reaching for `any`. Hand-written to match index.mjs;
// the flag list here is the same one DEFAULTS declares there.

export type SignatureLayout = 'trailing' | 'leading'

export type NoteState = 'outstanding' | 'pending' | 'burned'

export type WithdrawLinkForm = 'lnurlw' | 'plain'

export type RetriedMutation = 'refuse' | 'replay'

export interface MockMintOptions {
  username?: string
  minSendableMsat?: number
  maxSendableMsat?: number
  /** withheld on minting, advertised in the payRequest metadata */
  baseFeeMsat?: number
  feePpm?: number
  /**
   * 'trailing' is the LUD-25 wire format (r || s || recovery id). 'leading'
   * reproduces the layout lnurl-mint once emitted, forwarding its node's
   * signmessage output unreordered.
   */
  signatureLayout?: SignatureLayout
  /** withhold sig/sig2 entirely, as a SERVICE with no funding source does */
  signatures?: boolean
  /**
   * How the payRequest spells its withdrawLink. 'plain' (default) is the
   * fetchable https:// URL the reference mint emits and the spec's diagram
   * shows; 'lnurlw' is the LUD-17 scheme form. Both are legal; test against both.
   */
  withdrawLinkForm?: WithdrawLinkForm
  /** LUD-21 verify endpoint. Off means 404, not merely unadvertised. */
  verify?: boolean
  privateKey?: string

  // ---- misbehaviour ----
  /** answer the informational GET with a k1 other than the one queried */
  echoWrongK1?: boolean
  /** report a maxWithdrawable that is not what the note is worth */
  lieAboutValue?: number
  /** hang up mid-mutation, leaving the outcome unknown while it still lands */
  dropAfterMutation?: boolean
  /** reply 200 with a body that confirms nothing */
  unconfirmedMutation?: boolean
  /** reply with a body that is not JSON at all */
  malformedJson?: boolean
  /** hold every melt in flight forever, so the note stays locked as pending */
  meltNeverSettles?: boolean
  /** fail every melt's payment, restoring the note */
  meltAlwaysFails?: boolean
  /** non-compliant: generate the replacement secret SERVICE-side and hand it back */
  serverGeneratedSecrets?: boolean
  /** ceiling the mint fee to a whole sat, as dni's lnurl-mint does; compliant */
  roundFeeToSat?: boolean
  /** withhold this many msat on top of the fee, landing outside the compliant band */
  extraFeeMsat?: number
  /** non-compliant: accept a split with no h2, generating the change secret instead of refusing */
  acceptsMissingH2?: boolean
  /** non-compliant: split without taking the base fee out of change, and so without its floor */
  splitIgnoresBaseFee?: boolean
  /** delay before responding, in milliseconds */
  slowMs?: number
  /** reject splits and mints, as a mint winding down does */
  sunset?: boolean
  /** non-compliant: serve the preimage from verify before settlement */
  verifyLeaksEarly?: boolean
  /** expose /_test/ endpoints. Never enable against anything real. */
  testHooks?: boolean

  // ---- optional, non-spec extensions ----
  //
  // None of these is in LUD-25 and none is on by default. Every one is
  // absent from the wire unless it is set.

  /** operator-facing name, on the experimental discovery endpoint */
  name?: string
  /** one line about the mint, on the discovery endpoint */
  description?: string
  /** how to reach the operator, on the discovery endpoint */
  contact?: MintContact | string
  /** link to the mint's terms, on the discovery endpoint */
  tosUrl?: string
  /** message of the day: how an operator talks to holders */
  motd?: string
  /** the mint software's version string */
  version?: string
  /**
   * Compressed hex pubkeys this SERVICE has signed under before, so notes
   * it already issued still verify after a signing-key rotation. Emitted
   * only when the list is not empty. A comma-separated string is accepted
   * so the CLI can pass one.
   */
  previousPubkeys?: string[] | string
  /**
   * An old signing key the mock still holds, so a case can issue one note
   * under it and the rest under the current key. Its public half joins
   * previousPubkeys automatically. A real mint that has rotated keeps only
   * the public half.
   */
  previousPrivateKey?: string
  /**
   * Sign every note this mock issues under previousPrivateKey while still
   * advertising the current key as mintPubkey: the mid-rotation state a
   * mint passes through when the advertisement moves before the signer.
   */
  signWithPreviousKey?: boolean
  /**
   * What a retried mutation gets. A rotate, split or merge is a GET and
   * HTTP stacks retry a GET on a dropped connection, so a SERVICE sees
   * the byte-identical request twice. 'refuse' (default) answers the
   * second one as an already-spent input; 'replay' answers it with the
   * original success, which is what stops a holder discarding a note the
   * SERVICE really did mint. Identical means the same input k1 set, the
   * same h, the same h2 and the same amount; anything else naming a
   * burned input is refused exactly as before.
   */
  retriedMutation?: RetriedMutation
  /** serve GET /stats, the liabilities endpoint. Off means 404, as before. */
  stats?: boolean
  /** what the node behind a stats-publishing mock claims to hold */
  localBalanceMsat?: number
}

export interface MintContact {
  /** an npub */
  nostr?: string
  email?: string
  url?: string
}

export interface MintLiabilities {
  at: string
  outstandingMsat: number
  outstandingNotes: number
  pendingMsat: number
  pendingMelts: number
  oldestPendingMeltAgeSecs: number | null
  localBalanceMsat?: number
  /** localBalanceMsat / outstandingMsat, 4 dp; omitted when nothing is owed */
  coverage?: number
  reconciledAt: string
}

export interface MockMintState {
  notes: Map<string, {amountMsat: number; state: NoteState; pendingSince?: number}>
  invoices: Map<string, {amountMsat: number; preimage: string; settled: boolean}>
  pubkey: string
  /** the keys this mint has signed under before, as the discovery endpoint publishes them */
  previousPubkeys: string[]
  opts: Required<MockMintOptions>
  /**
   * Fund a note directly, bypassing the minting flow. Returns the note's
   * signature, or undefined when this mint was started with `signatures:
   * false` (as a SERVICE with no funding source behaves).
   *
   * Pass `{previousKey: true}` to sign it under `previousPrivateKey`
   * instead, which is how a case puts one note under the old signing key
   * and the rest under the new one.
   */
  creditNote(
    k1: string,
    amountMsat: number,
    options?: {previousKey?: boolean}
  ): string | undefined
  noteState(k1: string): NoteState | null
  settleMelt(k1: string): void
  failMelt(k1: string): void
}

export interface MockMint {
  url: string
  port: number
  state: MockMintState
  close(): Promise<void>
}

export function createMockMint(options?: MockMintOptions): Promise<MockMint>
