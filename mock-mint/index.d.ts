// Types for the mock mint, so TypeScript consumers get the misbehaviour flags
// checked rather than reaching for `any`. Hand-written to match index.mjs;
// the flag list here is the same one DEFAULTS declares there.

export type SignatureLayout = 'trailing' | 'leading'

export type NoteState = 'outstanding' | 'pending' | 'burned'

export type WithdrawLinkForm = 'lnurlw' | 'plain'

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
  /** expose /_test/ endpoints. Never enable against anything real. */
  testHooks?: boolean
}

export interface MockMintState {
  notes: Map<string, {amountMsat: number; state: NoteState}>
  invoices: Map<string, {amountMsat: number; preimage: string; settled: boolean}>
  pubkey: string
  opts: Required<MockMintOptions>
  /**
   * Fund a note directly, bypassing the minting flow. Returns the note's
   * signature, or undefined when this mint was started with `signatures:
   * false` (as a SERVICE with no funding source behaves).
   */
  creditNote(k1: string, amountMsat: number): string | undefined
  noteState(k1: string): NoteState | null
  settleMelt(k1: string): void
}

export interface MockMint {
  url: string
  port: number
  state: MockMintState
  close(): Promise<void>
}

export function createMockMint(options?: MockMintOptions): Promise<MockMint>
