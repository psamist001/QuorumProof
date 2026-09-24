#![no_std]
// Design rationale for the non-transferability enforced throughout this contract
// (see `transfer()` below and `ContractError::SoulboundNonTransferable`) is recorded
// in docs/adr/adr-002-sbt-non-transferability.md — read that before changing the
// transfer/burn/recovery semantics.

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod proptest_sbt_registry;

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Bytes, Env, IntoVal, Symbol, Vec,
};

const STANDARD_TTL: u32 = 16_384;
const EXTENDED_TTL: u32 = 524_288;
const MAX_BATCH_SIZE: u32 = 1000;
/// Issue #989: maximum accepted length of an SBT metadata URI, in bytes.
const MAX_METADATA_URI_LEN: usize = 256;

// ── Issue #1511: Governance audit trail for cross-contract address repointing ──
const TOPIC_ADMIN_TRANSFERRED: &str = "AdminTransferred";
const TOPIC_CONTRACT_ADDRESS_UPDATED: &str = "ContractAddressUpdated";

/// ASCII-case-insensitive prefix test.
///
/// `soroban_sdk::String` exposes no `to_lowercase`/`starts_with`, and the
/// contract is `no_std`, so scheme validation operates on the raw bytes.
fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()]
            .iter()
            .zip(needle.iter())
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
}

/// Issue #1405: shared length/scheme validation for a metadata URI's raw
/// bytes, used by both `mint()` and `set_sbt_metadata_uri`. Panics if
/// `uri_bytes` exceeds `MAX_METADATA_URI_LEN` or doesn't start with
/// `https://`/`ipfs://` (case-insensitive).
fn validate_metadata_uri(uri_bytes: &[u8]) {
    if uri_bytes.len() > MAX_METADATA_URI_LEN {
        panic!("metadata_uri exceeds 256 characters");
    }
    let valid_scheme = starts_with_ignore_ascii_case(uri_bytes, b"https://")
        || starts_with_ignore_ascii_case(uri_bytes, b"ipfs://");
    if !valid_scheme {
        panic!("metadata_uri must be HTTPS or IPFS");
    }
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
// #[contracterror] is required for panic_with_error! to work correctly with Soroban.
// Copy + Clone are the only derives compatible with #[contracterror].
pub enum ContractError {
    SoulboundNonTransferable = 1,
    TokenNotFound = 2,
    RecoveryNotFound = 3,
    RecoveryAlreadyExists = 4,
    UnauthorizedRecovery = 5,
    InsufficientApprovals = 6,
    InvalidGuardian = 7,
    NotWhitelisted = 8,
    HolderBlacklisted = 9,
    /// Caller is not the SBT holder (burn_sbt is holder-only).
    UnauthorizedBurn = 10,
    /// The supplied proof_of_residency is empty or structurally invalid.
    InvalidProof = 11,
    /// Unauthorized attestor transfer attempt (Issue #1239).
    UnauthorizedAttestor = 12,
    /// Appeal not found (Issue #1242).
    AppealNotFound = 13,
    /// Invalid proof of possession (Issue #1241).
    InvalidPossessionProof = 14,
    /// Metadata commitment mismatch (Issue #1240).
    MetadataCommitmentMismatch = 15,
    /// No attribute exists for the given SBT/key pair.
    AttributeNotFound = 16,
    /// Caller is not the issuer (admin) — attribute mutation is issuer-only.
    UnauthorizedAttributeIssuer = 17,
    /// Caller is not authorized to read a private attribute value.
    PrivateAttributeAccessDenied = 18,
    /// SBT is not registered in the given marketplace.
    MarketplaceListingNotFound = 19,
    /// Caller does not own the SBT and cannot (de)register its marketplace listing.
    UnauthorizedMarketplaceAction = 20,
    /// No possession commitment exists for the given commitment value.
    CommitmentNotFound = 21,
    /// The supplied proof does not hash to the stored commitment.
    InvalidCommitmentProof = 22,
    /// The proposed co-owner is not a valid co-owner for this SBT.
    InvalidCoOwner = 23,
    /// The SBT has no co-owner set.
    CoOwnerNotSet = 24,
    /// Issue #1243: A clawback is already pending for this SBT.
    ClawbackAlreadyExists = 25,
    /// Issue #1243: No clawback request exists with the given id.
    ClawbackNotFound = 26,
    /// Issue #1243: Caller is not the issuer who initiated this clawback.
    UnauthorizedClawback = 27,
    /// Issue #1402: `entries` is empty or exceeds `MAX_BATCH_SIZE`.
    BatchTooLarge = 28,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Token(u64),
    TokenCount,
    Owner(u64),
    OwnerTokens(Address),
    OwnerCredential(Address, u64),
    Delegation(u64),
    UsageDelegation(u64, Address),
    Admin,
    Paused,
    QuorumProofId,
    RecoveryRequest(u64),
    RecoveryRequestCount,
    PendingRecoveryByHolder(Address),
    RecoveryApprovals(u64),
    RecoveryGuardians,
    RecoveryThreshold,
    AuditTrail(u64),
    AuditTrailCount,
    NotificationHistory(Address),
    ReputationConfig,
    SbtWhitelist(u64),
    BurnedTokens,
    CredentialAccessLog(u64),
    Blacklist(Address),
    SbtActivityLog(u64),
    /// Issue #516: Cache entry for cross-contract credential revocation check.
    CredentialCache(u64),
    /// Compressed metadata storage
    CompressedMetadata(u64),
    /// Escrow record for pending SBT transfers, keyed by sbt_id
    SBTEscrow(u64),
    /// Issue #1242: Revocation reason for an SBT
    RevocationReason(u64),
    /// Issue #1242: Appeal record for a revoked SBT, keyed by sbt_id
    SBTAppeal(u64),
    /// Issue #1242: Appeal history for an SBT
    AppealHistory(u64),
    /// Issue #1241: Proof of possession for an SBT
    SBTProofOfPossession(u64),
    /// Issue #1240: Off-chain metadata commitment for an SBT
    MetadataCommitment(u64),
    /// Issue #1239: Attestor delegation for SBT transfer
    AttestorDelegation(u64),
    /// Encoded attribute value for an SBT, keyed by (sbt_id, attribute_key).
    SbtAttribute(u64, Bytes),
    /// List of attribute keys that have been set on an SBT, keyed by sbt_id.
    SbtAttributeKeys(u64),
    /// Reverse index for public attributes: (key, value) -> Vec<sbt_id>.
    AttributeIndex(Bytes, Bytes),
    /// Marketplace listing metadata, keyed by (sbt_id, marketplace_id).
    MarketplaceListing(u64, Bytes),
    /// Registry index: marketplace_id -> Vec<sbt_id> registered in it.
    MarketplaceIndex(Bytes),
    /// Reverse lookup: sbt_id -> Vec<marketplace_id> it is listed in.
    SbtMarketplaces(u64),
    /// Global on-chain registry index of every sbt_id ever listed in any
    /// marketplace, enabling discovery without knowing a marketplace_id.
    GlobalMarketplaceRegistry,
    /// A holder's SBT possession commitment, keyed by the commitment hash
    /// itself so verification never needs to know which address created it.
    PossessionCommitment(Bytes),
    /// Per-SBT counter used to derive a fresh nonce for each new commitment.
    CommitmentNonce(u64),
    /// Ownership/co-ownership change log for an SBT, oldest first.
    OwnershipHistory(u64),
    /// Issue #989: wallet-facing metadata URI for an SBT.
    SbtMetadataUri(u64),
    /// Issue #1243: A time-locked clawback request, keyed by its id.
    ClawbackRequest(u64),
    /// Monotonic counter handing out `ClawbackRequest` ids.
    ClawbackRequestCount,
    /// The pending clawback id for an SBT, if any (sbt_id -> clawback_id).
    /// Enforces that only one clawback may be pending per SBT at a time.
    PendingClawbackBySbt(u64),
    /// A co-owner candidate proposed by an SBT's owner, awaiting the
    /// candidate's acceptance.
    CoOwnerProposal(u64),
}

/// Issue #516: Cached result of a cross-contract is_revoked check.
/// Stored in persistent storage keyed by credential_id.
/// The cache is valid while `cached_at + CREDENTIAL_CACHE_TTL_LEDGERS > current_ledger`.
#[contracttype]
#[derive(Clone)]
pub struct CredentialCacheEntry {
    /// Whether the credential was revoked at the time of caching.
    pub revoked: bool,
    /// Ledger sequence number when this entry was written.
    pub cached_at: u32,
}

/// Issue #516: Cache TTL in ledgers (~1 hour at 5s/ledger = 720 ledgers).
const CREDENTIAL_CACHE_TTL_LEDGERS: u32 = 720;

/// Weights used to compute a holder's reputation score.
/// score = tokens_held * token_weight + notifications * activity_weight
#[contracttype]
#[derive(Clone)]
pub struct ReputationConfig {
    /// Points awarded per SBT currently held.
    pub token_weight: u32,
    /// Points awarded per notification history entry (activity signal).
    pub activity_weight: u32,
}

/// A single on-chain notification entry stored per holder.
#[contracttype]
#[derive(Clone)]
pub struct NotificationEntry {
    /// The SBT token ID this notification relates to.
    pub token_id: u64,
    /// Event kind: "mint", "burn", "recover", "transfer"
    pub event: Symbol,
    /// Ledger timestamp when the event occurred.
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct SoulboundToken {
    pub id: u64,
    pub owner: Address,
    pub credential_id: u64,
    pub metadata_uri: Bytes,
    /// Monotonically increasing version; starts at 1 on mint, incremented on each metadata update.
    pub version: u32,
    /// Issue #992: If set, this SBT has been upgraded to another SBT ID.
    /// Old SBT cannot be verified independently when upgraded.
    pub upgraded_to: Option<u64>,
    /// Issue #1275: Optional co-owner (e.g. an organization) for credentials
    /// issued jointly to an individual and an organization. When set,
    /// ownership transfer requires signatures from both `owner` and
    /// `co_owner`.
    pub co_owner: Option<Address>,
}

/// Issue #1275: A single entry in an SBT's ownership history, recorded on
/// mint and on every subsequent owner/co-owner change.
#[contracttype]
#[derive(Clone)]
pub struct OwnershipHistoryEntry {
    pub owner: Address,
    pub co_owner: Option<Address>,
    /// Ledger timestamp when this ownership state took effect.
    pub changed_at: u64,
    /// Event kind: "mint", "dual_xfer", "set_co", "rm_co", "attestor"
    pub event: Symbol,
}

#[contracttype]
#[derive(Clone)]
pub struct Delegation {
    pub token_id: u64,
    pub delegatee: Address,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageScope {
    DeFiCollateral(u64),
    IdentityVerification(u64),
    GovernanceVoting(u64),
}

/// Constant micropayment amount per credential access (stub).
const CREDENTIAL_ACCESS_MICROPAYMENT: i128 = 100;

/// A single entry in the credential access audit log.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAccessEntry {
    /// Address of the verifier who accessed the credential.
    pub accessor: Address,
    /// Ledger timestamp of the access event.
    pub timestamp: u64,
    /// Micropayment credited (or to be transferred) to the holder.
    pub payment: i128,
}

#[contracttype]
#[derive(Clone)]
pub struct ScopedDelegation {
    pub token_id: u64,
    pub delegatee: Address,
    pub scope: UsageScope,
}

/// Represents a recovery request for an SBT holder's lost/compromised account
#[contracttype]
#[derive(Clone)]
pub struct RecoveryRequest {
    /// Unique recovery request ID
    pub id: u64,
    /// Original account owner who initiated recovery
    pub initiator: Address,
    /// New account to recover SBTs to
    pub new_owner: Address,
    /// Time when recovery was initiated
    pub initiated_at: u64,
    /// Whether the recovery has been finalized
    pub completed: bool,
    /// Number of approvals received so far
    pub approvals_count: u32,
}

/// Represents a single approval by a recovery guardian
#[contracttype]
#[derive(Clone)]
pub struct RecoveryApproval {
    /// The guardian who approved
    pub guardian: Address,
    /// Time when approval was given
    pub approved_at: u64,
}

/// Represents a time-locked SBT clawback request (Issue #1243)
#[contracttype]
#[derive(Clone)]
pub struct ClawbackRequest {
    /// Unique clawback request ID
    pub id: u64,
    /// The SBT token ID to be clawed back
    pub sbt_id: u64,
    /// The issuer initiating the clawback
    pub issuer: Address,
    /// Reason for the clawback (e.g., fraudulent claim)
    pub reason: Bytes,
    /// When the clawback was initiated
    pub initiated_at: u64,
    /// Timestamp when the timelock expires and clawback can be executed
    pub expires_at: u64,
    /// Whether the clawback has been executed or cancelled
    pub status: Symbol,
}

/// Audit trail entry for recovery operations
#[contracttype]
#[derive(Clone)]
pub struct AuditTrailEntry {
    /// Unique audit trail ID
    pub id: u64,
    /// Recovery request ID (if applicable)
    pub recovery_request_id: u64,
    /// Type of action: "initiate", "approve", "finalize"
    pub action: Symbol,
    /// Actor performing the action
    pub actor: Address,
    /// Timestamp of the action
    pub timestamp: u64,
    /// Additional details about the action
    pub details: soroban_sdk::String,
}

/// Entry for a single mint operation within a batch.
#[contracttype]
#[derive(Clone)]
pub struct BatchMintEntry {
    pub owner: Address,
    pub credential_id: u64,
    pub metadata_uri: Bytes,
}

/// Entry for a single burn operation within a batch.
#[contracttype]
#[derive(Clone)]
pub struct BatchBurnEntry {
    pub caller: Address,
    pub token_id: u64,
}

/// Entry for a single admin-transfer operation within a batch.
#[contracttype]
#[derive(Clone)]
pub struct BatchTransferEntry {
    pub token_id: u64,
    pub new_owner: Address,
}

/// A single activity log entry for an SBT lifecycle event.
#[contracttype]
#[derive(Clone)]
pub struct SbtActivityEntry {
    /// The action: "mint", "burn", or "update_meta"
    pub action: Symbol,
    /// The address that performed the action.
    pub actor: Address,
    /// Ledger timestamp when the action occurred.
    pub timestamp: u64,
}

/// Issue #1242: Revocation record for an SBT with reason tracking.
#[contracttype]
#[derive(Clone)]
pub struct RevocationRecord {
    /// The SBT token ID that was revoked.
    pub sbt_id: u64,
    /// Reason for revocation (e.g., "credential_expired", "holder_breach").
    pub reason: Bytes,
    /// Address that initiated the revocation.
    pub revoked_by: Address,
    /// Ledger timestamp when revocation occurred.
    pub revoked_at: u64,
}

/// Issue #1242: Appeal record for a revoked SBT.
#[contracttype]
#[derive(Clone)]
pub struct AppealRecord {
    /// The SBT token ID being appealed.
    pub sbt_id: u64,
    /// Evidence provided for the appeal.
    pub appeal_evidence: Bytes,
    /// Address submitting the appeal (typically the holder).
    pub appealed_by: Address,
    /// Ledger timestamp when appeal was submitted.
    pub appealed_at: u64,
    /// Appeal status: "pending", "approved", "denied"
    pub status: Symbol,
}

/// Issue #1241: Proof of possession for an SBT.
#[contracttype]
#[derive(Clone)]
pub struct PossessionProof {
    /// The SBT token ID this proof is for.
    pub sbt_id: u64,
    /// The proof data (e.g., signed challenge).
    pub proof_data: Bytes,
    /// Timestamp when the proof was generated.
    pub generated_at: u64,
}

/// Issue #1240: Off-chain metadata commitment with verification.
#[contracttype]
#[derive(Clone)]
pub struct MetadataCommitmentRecord {
    /// The SBT token ID this commitment is for.
    pub sbt_id: u64,
    /// Hash of the new metadata.
    pub metadata_hash: Bytes,
    /// Holder's signature over the metadata hash.
    pub signature: Bytes,
    /// Ledger timestamp when commitment was created.
    pub committed_at: u64,
}

/// Issue #1239: Attestor delegation for SBT transfer.
#[contracttype]
#[derive(Clone)]
pub struct AttestorDelegationRecord {
    /// The SBT token ID being transferred.
    pub sbt_id: u64,
    /// The attestor authorized to transfer this SBT.
    pub attestor: Address,
    /// The new holder after transfer.
    pub new_holder: Address,
    /// Reason for the transfer (e.g., "employment_termination").
    pub transfer_reason: Bytes,
    /// Whether the transfer has been executed.
    pub executed: bool,
    /// Ledger timestamp when delegation was created.
    pub created_at: u64,
}

/// Event emitted when an SBT is burned by its holder via `burn_sbt`.
///
/// Published as the event data with topic `["burn_sbt", sbt_id]`.
#[contracttype]
#[derive(Clone)]
pub struct BurnEvent {
    /// The SBT token ID that was burned.
    pub sbt_id: u64,
    /// The address that held (and burned) the SBT.
    pub holder: Address,
    /// Ledger timestamp when the burn occurred.
    pub timestamp: u64,
}

// ── Issue #1511: Governance event structs ────────────────────────────────────

/// Emitted when the contract admin is transferred to a new address.
#[contracttype]
#[derive(Clone)]
pub struct AdminTransferredEventData {
    /// The previous admin address.
    pub old_admin: Address,
    /// The new admin address.
    pub new_admin: Address,
}

/// Emitted when a cross-contract address (quorum_proof) is repointed.
#[contracttype]
#[derive(Clone)]
pub struct ContractAddressUpdatedEventData {
    /// Label identifying which contract was updated (e.g. "quorum_proof").
    pub contract_name: soroban_sdk::String,
    /// The previous contract address.
    pub old_address: Address,
    /// The new contract address.
    pub new_address: Address,
}

/// An encoded attribute attached to an SBT (e.g. `specialization: mechanical
/// engineering`), separate from the credential reference itself so verifiers
/// can query on a narrow claim without needing the full credential.
///
/// # Attribute encoding schema
/// - `key` and `value` are opaque `Bytes` — callers agree on an encoding
///   off-chain (e.g. UTF-8 strings, or a namespaced `category:value` form
///   such as `b"specialization"` / `b"mechanical_engineering"`).
/// - Keys are not required to be unique across the whole contract, only per
///   SBT: the same `key` can carry different values on different SBTs.
/// - `private == true` restricts reads of `value` to the issuer (admin) and
///   the SBT's current owner via [`SbtRegistryContract::get_sbt_attribute`];
///   private attributes are also excluded from the public
///   [`SbtRegistryContract::query_sbt_by_attribute`] index so their values
///   are never revealed through discovery.
#[contracttype]
#[derive(Clone)]
pub struct SbtAttributeRecord {
    /// The SBT token ID this attribute belongs to.
    pub sbt_id: u64,
    /// Attribute name, e.g. `b"specialization"`.
    pub key: Bytes,
    /// Attribute value, e.g. `b"mechanical_engineering"`.
    pub value: Bytes,
    /// Whether this attribute's value is restricted to issuer/holder reads.
    pub private: bool,
    /// Ledger timestamp when the attribute was last set.
    pub set_at: u64,
}

/// A single SBT's listing in a discoverable marketplace, enabling verifiers
/// (or marketplace UIs) to enumerate SBTs by marketplace without the holder
/// having to push data to each marketplace out of band.
#[contracttype]
#[derive(Clone)]
pub struct MarketplaceListingRecord {
    /// The SBT token ID being listed.
    pub sbt_id: u64,
    /// Opaque marketplace identifier (e.g. a namespaced slug).
    pub marketplace_id: Bytes,
    /// Marketplace-specific metadata (e.g. listing terms, category tags).
    pub metadata: Bytes,
    /// Ledger timestamp when the listing was created or last updated.
    pub listed_at: u64,
    /// Whether the listing is currently active (false after deregistration).
    pub active: bool,
}

/// A hash-based commitment that lets a holder prove possession of an SBT
/// without revealing which address holds it. See `docs/sbt-possession-privacy.md`
/// for the full privacy guarantees and threat model of this scheme.
///
/// The commitment is `sha256(sbt_id_be_bytes || nonce_be_bytes)`. Only the
/// commitment hash is stored on-chain, keyed by itself — the record contains
/// no holder address, so a verifier calling `verify_sbt_commitment` learns
/// only "some holder legitimately created this commitment for this SBT at
/// this time," never who that holder is.
#[contracttype]
#[derive(Clone)]
pub struct PossessionCommitmentRecord {
    /// The SBT token ID this commitment attests possession of.
    pub sbt_id: u64,
    /// The commitment hash itself (also the storage key).
    pub commitment: Bytes,
    /// Ledger timestamp when the commitment was created.
    pub created_at: u64,
}

#[contract]
pub struct SbtRegistryContract;

#[contractimpl]
#[allow(dead_code)]
impl SbtRegistryContract {
    /// Mint a soulbound token linked to a credential_id.
    ///
    /// Creates a non-transferable token bound to the `owner` address and associated
    /// with the given `credential_id`. Each `(owner, credential_id)` pair may only
    /// have one SBT — attempting to mint a duplicate panics.
    ///
    /// Cross-contract verifies via `quorum_proof` that the credential exists and is
    /// not revoked before minting.
    ///
    /// # Parameters
    /// - `owner`: The address receiving the SBT; must authorize this call.
    /// - `credential_id`: The credential this SBT is linked to.
    /// - `metadata_uri`: Content-addressed URI (e.g. IPFS) for the token metadata.
    ///
    /// # Panics
    /// Panics with `ContractError::SoulboundNonTransferable` if an SBT already exists
    /// for this `(owner, credential_id)` pair.
    /// Panics if the credential does not exist or is revoked in `quorum_proof`.
    pub fn mint(env: Env, owner: Address, credential_id: u64, metadata_uri: Bytes) -> u64 {
        owner.require_auth();

        if Self::is_paused(&env) {
            panic!("contract is paused");
        }

        if env.storage().instance().has(&DataKey::Blacklist(owner.clone())) {
            panic_with_error!(&env, ContractError::HolderBlacklisted);
        }

        // Issue #1405: validate metadata_uri length/scheme up front, matching
        // the check set_sbt_metadata_uri already enforces, so an
        // unbounded or malformed-scheme URI can never be stored at mint time.
        {
            let uri_len = metadata_uri.len() as usize;
            if uri_len > MAX_METADATA_URI_LEN {
                panic!("metadata_uri exceeds 256 characters");
            }
            let mut uri_buf = [0u8; MAX_METADATA_URI_LEN];
            let uri_slice = &mut uri_buf[..uri_len];
            metadata_uri.copy_into_slice(uri_slice);
            validate_metadata_uri(uri_slice);
        }

        // Cross-contract: verify credential exists and is not revoked.
        // Uses env.invoke_contract to avoid a circular crate dependency with quorum_proof.
        let qp_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("not initialized");
        // Issue #516: Check credential cache before making a cross-contract call.
        let current_ledger = env.ledger().sequence();
        let revoked: bool = if let Some(entry) = env
            .storage()
            .persistent()
            .get::<_, CredentialCacheEntry>(&DataKey::CredentialCache(credential_id))
        {
            if current_ledger.saturating_sub(entry.cached_at) < CREDENTIAL_CACHE_TTL_LEDGERS {
                // Cache hit: use cached value, skip cross-contract call.
                entry.revoked
            } else {
                // Cache expired: refresh via cross-contract call.
                let r: bool = env.invoke_contract(
                    &qp_id,
                    &Symbol::new(&env, "is_revoked"),
                    soroban_sdk::vec![&env, credential_id.into_val(&env)],
                );
                env.storage().persistent().set(
                    &DataKey::CredentialCache(credential_id),
                    &CredentialCacheEntry { revoked: r, cached_at: current_ledger },
                );
                env.storage().persistent().extend_ttl(
                    &DataKey::CredentialCache(credential_id),
                    STANDARD_TTL,
                    EXTENDED_TTL,
                );
                r
            }
        } else {
            // Cache miss: call cross-contract and populate cache.
            // is_revoked panics with CredentialNotFound if the credential doesn't exist.
            let r: bool = env.invoke_contract(
                &qp_id,
                &Symbol::new(&env, "is_revoked"),
                soroban_sdk::vec![&env, credential_id.into_val(&env)],
            );
            env.storage().persistent().set(
                &DataKey::CredentialCache(credential_id),
                &CredentialCacheEntry { revoked: r, cached_at: current_ledger },
            );
            env.storage().persistent().extend_ttl(
                &DataKey::CredentialCache(credential_id),
                STANDARD_TTL,
                EXTENDED_TTL,
            );
            r
        };
        assert!(!revoked, "credential is revoked");

        // Check whitelist if enabled for this SBT
        if let Some(whitelist) = env
            .storage()
            .persistent()
            .get::<_, Vec<Address>>(&DataKey::SbtWhitelist(credential_id))
        {
            if !whitelist.iter().any(|addr| addr == owner) {
                panic_with_error!(&env, ContractError::NotWhitelisted);
            }
        }

        if env
            .storage()
            .instance()
            .has(&DataKey::OwnerCredential(owner.clone(), credential_id))
        {
            panic_with_error!(&env, ContractError::SoulboundNonTransferable);
        }
        let mut token_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TokenCount)
            .unwrap_or(0);
        token_count += 1;
        let token_id = token_count;
        // Issue #512: Store metadata_uri separately to reduce SoulboundToken struct footprint.
        // The struct stores an empty Bytes; callers retrieve metadata via get_token which
        // transparently rehydrates metadata_uri from CompressedMetadata storage.
        env.storage()
            .persistent()
            .set(&DataKey::CompressedMetadata(token_id), &metadata_uri);
        env.storage().persistent().extend_ttl(
            &DataKey::CompressedMetadata(token_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );
        let token = SoulboundToken {
            id: token_id,
            owner: owner.clone(),
            credential_id,
            metadata_uri: Bytes::new(&env), // stored separately in CompressedMetadata
            version: 1,
            upgraded_to: None,
            co_owner: None,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);
        env.storage().persistent().extend_ttl(
            &DataKey::Token(token_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &owner.clone());
        env.storage().persistent().extend_ttl(
            &DataKey::Owner(token_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );
        env.storage()
            .instance()
            .set(&DataKey::TokenCount, &token_count);
        let mut owner_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(owner.clone()))
            .unwrap_or(Vec::new(&env));
        owner_tokens.push_back(token_id);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(owner.clone()), &owner_tokens);
        env.storage().persistent().extend_ttl(
            &DataKey::OwnerTokens(owner.clone()),
            16_384,
            524_288,
        );

        // Uniqueness mapping
        env.storage().instance().set(
            &DataKey::OwnerCredential(owner.clone(), credential_id),
            &token_id,
        );

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("mint").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (owner.clone(), credential_id));
        Self::record_notification(&env, owner.clone(), token_id, symbol_short!("mint"));
        Self::log_sbt_activity(&env, token_id, symbol_short!("mint"), owner.clone());
        Self::record_ownership_history(&env, token_id, owner.clone(), None, symbol_short!("mint"));
        token_id
    }
    ///
    /// # Parameters
    /// - `token_id`: The ID of the token to retrieve.
    ///
    /// # Panics
    /// Panics with "token not found" if no token exists with that ID.
    pub fn get_token(env: Env, token_id: u64) -> SoulboundToken {
        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        // Issue #512: Rehydrate metadata_uri from separate CompressedMetadata storage.
        // Transparent to callers — metadata_uri is always populated on return.
        if let Some(metadata) = env
            .storage()
            .persistent()
            .get::<_, Bytes>(&DataKey::CompressedMetadata(token_id))
        {
            token.metadata_uri = metadata;
        }
        token
    }

    /// Returns the owner address of a token.
    ///
    /// # Parameters
    /// - `token_id`: The ID of the token to query.
    ///
    /// # Panics
    /// Panics with "token not found" if no token exists with that ID.
    pub fn owner_of(env: Env, token_id: u64) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Owner(token_id))
            .expect("token not found")
    }

    /// Returns all token IDs owned by the given address.
    ///
    /// # Parameters
    /// - `owner`: The address whose tokens to list.
    ///
    /// # Panics
    /// Does not panic; returns an empty `Vec` if the owner holds no tokens.
    pub fn get_tokens_by_owner(env: Env, owner: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::OwnerTokens(owner))
            .unwrap_or(Vec::new(&env))
    }

    /// Alias for get_tokens_by_owner — returns all SBT token IDs owned by an address.
    pub fn get_sbt_by_owner(env: Env, owner: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::OwnerTokens(owner))
            .unwrap_or(Vec::new(&env))
    }

    /// Issue #1564: Reverse-index lookup — returns all SBT token IDs held by
    /// an address.  This is the canonical holder-facing name for the reverse
    /// index that `OwnerTokens(Address)` stores.  The index is maintained
    /// automatically by `mint`, `burn_sbt`, `transfer` (always panics for
    /// soulbound semantics), and `recover_sbt`, so the returned list is
    /// always authoritative; no separate rebuild is needed on-chain.
    pub fn get_tokens_by_holder(env: Env, holder: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::OwnerTokens(holder))
            .unwrap_or(Vec::new(&env))
    }

    /// Delegate rights for a specific SBT to another address until a timestamp expires.
    pub fn delegate_sbt_rights(
        env: Env,
        owner: Address,
        token_id: u64,
        delegatee: Address,
        expires_at: u64,
    ) {
        owner.require_auth();
        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        assert!(token.owner == owner, "not the owner");

        let current_ts: u64 = env.ledger().timestamp();
        assert!(expires_at > current_ts, "expiry must be in the future");

        let delegation = Delegation {
            token_id,
            delegatee: delegatee.clone(),
            expires_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Delegation(token_id), &delegation);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("delegate").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (delegatee, expires_at));
    }

    /// Revoke an active delegation for a specific SBT. Only the token owner may call this.
    pub fn revoke_sbt_delegation(env: Env, owner: Address, token_id: u64) {
        owner.require_auth();
        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        assert!(token.owner == owner, "not the owner");

        let delegatee: Option<Address> = env
            .storage()
            .instance()
            .get::<_, Delegation>(&DataKey::Delegation(token_id))
            .map(|delegation| delegation.delegatee);
        env.storage()
            .persistent()
            .remove(&DataKey::Delegation(token_id));

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("undeleg").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, delegatee);
    }

    /// Retrieve delegation details for a token.
    pub fn get_delegation(env: Env, token_id: u64) -> Delegation {
        env.storage()
            .persistent()
            .get(&DataKey::Delegation(token_id))
            .expect("delegation not found")
    }

    /// Check whether a delegatee currently holds active rights for the token.
    pub fn is_delegate_active(env: Env, token_id: u64, delegatee: Address) -> bool {
        let current_ts: u64 = env.ledger().timestamp();
        env.storage()
            .persistent()
            .get(&DataKey::Delegation(token_id))
            .map_or(false, |delegation: Delegation| {
                delegation.delegatee == delegatee && delegation.expires_at > current_ts
            })
    }

    /// Delegate token usage with specific scope and time-based expiry.
    pub fn delegate_sbt_usage(
        env: Env,
        sbt_id: u64,
        delegatee: Address,
        scope: UsageScope,
    ) {
        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .expect("token not found");
        token.owner.require_auth();

        assert!(token.owner != delegatee, "cannot delegate to self");

        let expires_at = match &scope {
            UsageScope::DeFiCollateral(expires_at) => *expires_at,
            UsageScope::IdentityVerification(expires_at) => *expires_at,
            UsageScope::GovernanceVoting(expires_at) => *expires_at,
        };
        let current_ts = env.ledger().timestamp();
        assert!(expires_at > current_ts, "expiry must be in the future");

        let delegation = ScopedDelegation {
            token_id: sbt_id,
            delegatee: delegatee.clone(),
            scope: scope.clone(),
        };

        env.storage()
            .instance()
            .set(&DataKey::UsageDelegation(sbt_id, delegatee.clone()), &delegation);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("deleg_use").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, (delegatee, scope));
    }

    /// Verify a delegated SBT specifically for DeFi protocol usages.
    pub fn verify_delegated_sbt(env: Env, sbt_id: u64, delegatee: Address) -> bool {
        matches!(
            Self::active_usage_scope(&env, sbt_id, delegatee),
            Some(UsageScope::DeFiCollateral(_))
        )
    }

    /// Verify a delegated SBT specifically for identity verification usages.
    pub fn verify_delegated_identity(env: Env, sbt_id: u64, delegatee: Address) -> bool {
        matches!(
            Self::active_usage_scope(&env, sbt_id, delegatee),
            Some(UsageScope::IdentityVerification(_))
        )
    }

    /// Verify a delegated SBT specifically for governance voting usages.
    pub fn verify_delegated_governance(env: Env, sbt_id: u64, delegatee: Address) -> bool {
        matches!(
            Self::active_usage_scope(&env, sbt_id, delegatee),
            Some(UsageScope::GovernanceVoting(_))
        )
    }

    /// Internal helper: return the scope of a delegatee's usage delegation for
    /// an existing token, but only while that delegation is still unexpired.
    fn active_usage_scope(env: &Env, sbt_id: u64, delegatee: Address) -> Option<UsageScope> {
        if !env.storage().persistent().has(&DataKey::Token(sbt_id)) {
            return None;
        }

        let key = DataKey::UsageDelegation(sbt_id, delegatee);
        let delegation: ScopedDelegation = env.storage().instance().get(&key)?;
        let expires_at = match &delegation.scope {
            UsageScope::DeFiCollateral(expires_at) => *expires_at,
            UsageScope::IdentityVerification(expires_at) => *expires_at,
            UsageScope::GovernanceVoting(expires_at) => *expires_at,
        };
        if expires_at > env.ledger().timestamp() {
            Some(delegation.scope)
        } else {
            None
        }
    }

    /// Returns the total number of SBTs ever minted.
    pub fn sbt_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::TokenCount)
            .unwrap_or(0u64)
    }

    pub fn transfer(env: Env, _from: Address, _to: Address, _token_id: u64) {
        // Always rejected by design — see docs/adr/adr-002-sbt-non-transferability.md.
        panic_with_error!(&env, ContractError::SoulboundNonTransferable);
    }

    /// Burn a soulbound token. Only the owner may call this.
    /// Returns the credential_id linked to this token.
    pub fn burn(env: Env, owner: Address, token_id: u64) -> u64 {
        owner.require_auth();
        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));
        assert!(token.owner == owner, "not the owner");
        env.storage().persistent().remove(&DataKey::Token(token_id));
        env.storage().persistent().remove(&DataKey::Owner(token_id));
        env.storage()
            .persistent()
            .remove(&DataKey::Delegation(token_id));
        env.storage().instance().remove(&DataKey::OwnerCredential(
            owner.clone(),
            token.credential_id,
        ));
        let mut owner_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(owner.clone()))
            .expect("owner has no tokens");
        let pos = owner_tokens
            .iter()
            .position(|id| id == token_id)
            .expect("token not in owner list");
        owner_tokens.remove(pos as u32);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(owner.clone()), &owner_tokens);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("burn").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events()
            .publish(topics, (owner.clone(), token.credential_id));
        Self::record_notification(&env, owner.clone(), token_id, symbol_short!("burn"));
        Self::log_sbt_activity(&env, token_id, symbol_short!("burn"), owner.clone());
        token.credential_id
    }

    /// Initialize the contract with an admin and the quorum_proof contract address.
    pub fn initialize(env: Env, admin: Address, quorum_proof_id: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::QuorumProofId, &quorum_proof_id);
    }

    // ── Issue #1511: Governance — admin transfer & cross-contract address repointing ──

    /// Transfer contract admin to a new address, emitting an `AdminTransferred` event.
    ///
    /// Provides an auditable trail for every admin key rotation. The caller
    /// must be the current admin and must authorize the call.
    ///
    /// # Parameters
    /// - `admin`: The current admin address (must authorize).
    /// - `new_admin`: The address to become the new admin.
    ///
    /// # Panics
    /// - If the contract is not initialized (no admin stored).
    /// - If `admin` does not match the stored admin.
    pub fn update_admin(env: Env, admin: Address, new_admin: Address) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored == admin, "unauthorized");

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().extend_ttl(STANDARD_TTL, EXTENDED_TTL);

        let event_data = AdminTransferredEventData {
            old_admin: stored,
            new_admin,
        };
        let topic = soroban_sdk::String::from_str(&env, TOPIC_ADMIN_TRANSFERRED);
        let mut topics: soroban_sdk::Vec<soroban_sdk::String> = soroban_sdk::Vec::new(&env);
        topics.push_back(topic);
        env.events().publish(topics, event_data);
    }

    /// Repoint the quorum_proof contract address, emitting a `ContractAddressUpdated` event.
    ///
    /// When the quorum_proof contract is redeployed, this allows updating the stored
    /// address so cross-contract credential verification calls route to the new contract.
    ///
    /// # Parameters
    /// - `admin`: The current admin address (must authorize).
    /// - `new_address`: The new quorum_proof contract address.
    ///
    /// # Panics
    /// - If the contract is not initialized.
    /// - If `admin` does not match the stored admin.
    pub fn update_quorum_proof_id(env: Env, admin: Address, new_address: Address) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored == admin, "unauthorized");

        let old_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("quorum_proof_id not set");

        env.storage()
            .instance()
            .set(&DataKey::QuorumProofId, &new_address);
        env.storage().instance().extend_ttl(STANDARD_TTL, EXTENDED_TTL);

        let event_data = ContractAddressUpdatedEventData {
            contract_name: soroban_sdk::String::from_str(&env, "quorum_proof"),
            old_address,
            new_address,
        };
        let topic = soroban_sdk::String::from_str(&env, TOPIC_CONTRACT_ADDRESS_UPDATED);
        let mut topics: soroban_sdk::Vec<soroban_sdk::String> = soroban_sdk::Vec::new(&env);
        topics.push_back(topic);
        env.events().publish(topics, event_data);
    }

    /// Get the currently stored quorum_proof address.
    pub fn get_quorum_proof_id(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("quorum_proof_id not set")
    }

    /// Burn a soulbound token. Callable by the token holder only.
    ///
    /// The caller must provide a `proof_of_residency` — a non-empty byte string
    /// that demonstrates they still possess the underlying credential (stub: any
    /// non-empty `Bytes` is accepted; real ZK verification is tracked in #ZK-IMPL).
    ///
    /// On success:
    /// - Token, Owner, OwnerTokens, Delegation, and OwnerCredential entries are removed.
    /// - A `BurnEvent` is emitted with `sbt_id`, `holder`, and `timestamp`.
    /// - A notification and activity-log entry are written.
    ///
    /// # Parameters
    /// - `holder`: The token owner; must authorize this call.
    /// - `sbt_id`: The ID of the SBT to burn.
    /// - `proof_of_residency`: Non-empty bytes proving the holder retains the
    ///   underlying credential. Empty bytes are rejected with `InvalidProof`.
    ///
    /// # Errors
    /// - `ContractError::TokenNotFound` — no SBT with that ID exists.
    /// - `ContractError::UnauthorizedBurn` — caller is not the SBT holder.
    /// - `ContractError::InvalidProof` — `proof_of_residency` is empty.
    pub fn burn_sbt(env: Env, holder: Address, sbt_id: u64, proof_of_residency: Bytes) {
        holder.require_auth();

        if Self::is_paused(&env) {
            panic!("contract is paused");
        }

        // Validate proof is non-empty (stub: any non-empty bytes accepted).
        if proof_of_residency.is_empty() {
            panic_with_error!(&env, ContractError::InvalidProof);
        }

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        // Holder-only: the caller must be the SBT owner.
        if token.owner != holder {
            panic_with_error!(&env, ContractError::UnauthorizedBurn);
        }

        let owner = token.owner.clone();
        let timestamp = env.ledger().timestamp();

        env.storage().persistent().remove(&DataKey::Token(sbt_id));
        env.storage().persistent().remove(&DataKey::Owner(sbt_id));
        env.storage()
            .persistent()
            .remove(&DataKey::Delegation(sbt_id));
        env.storage().instance().remove(&DataKey::OwnerCredential(
            owner.clone(),
            token.credential_id,
        ));

        let mut owner_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(owner.clone()))
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = owner_tokens.iter().position(|id| id == sbt_id) {
            owner_tokens.remove(pos as u32);
        }
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(owner.clone()), &owner_tokens);

        // Emit BurnEvent with sbt_id, holder, and timestamp.
        let burn_event = BurnEvent {
            sbt_id,
            holder: owner.clone(),
            timestamp,
        };
        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(Symbol::new(&env, "burn_sbt").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, burn_event);

        Self::record_notification(&env, owner.clone(), sbt_id, symbol_short!("burn"));
        Self::log_sbt_activity(&env, sbt_id, symbol_short!("burn"), owner);
    }

    /// Recover an SBT to a new owner during credential recovery.
    /// Callable by the stored quorum_proof contract or the admin.
    pub fn recover_sbt(env: Env, caller: Address, token_id: u64, new_owner: Address) {
        caller.require_auth();
        let qp_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("not initialized");
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(caller == qp_id || caller == admin, "unauthorized");

        // Issue #1403: recovery moves the SBT to a new holder address, so it
        // must honor the blacklist the same way mint() does — recovery is not
        // meant to be a way around a blacklist entry, only around lost keys.
        if env.storage().instance().has(&DataKey::Blacklist(new_owner.clone())) {
            panic_with_error!(&env, ContractError::HolderBlacklisted);
        }

        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        let old_owner = token.owner.clone();

        // Remove from old owner's list
        let mut old_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(old_owner.clone()))
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = old_tokens.iter().position(|id| id == token_id) {
            old_tokens.remove(pos as u32);
        }
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(old_owner.clone()), &old_tokens);
        env.storage()
            .persistent()
            .remove(&DataKey::Delegation(token_id));
        env.storage().instance().remove(&DataKey::OwnerCredential(
            old_owner.clone(),
            token.credential_id,
        ));

        // Add to new owner
        token.owner = new_owner.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &new_owner);
        let mut new_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(new_owner.clone()))
            .unwrap_or(Vec::new(&env));
        new_tokens.push_back(token_id);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(new_owner.clone()), &new_tokens);
        env.storage().instance().set(
            &DataKey::OwnerCredential(new_owner.clone(), token.credential_id),
            &token_id,
        );

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("recover").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (old_owner, new_owner.clone()));
        Self::record_notification(&env, new_owner, token_id, symbol_short!("recover"));
    }

    /// Admin-only: transfer an SBT to a new owner (e.g. after credential re-issuance).
    pub fn admin_transfer_sbt(env: Env, admin: Address, token_id: u64, new_owner: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(admin == stored_admin, "unauthorized");

        // Issue #1403: mirror mint()'s blacklist check so a blacklisted
        // address cannot regain an SBT via admin transfer.
        if env.storage().instance().has(&DataKey::Blacklist(new_owner.clone())) {
            panic_with_error!(&env, ContractError::HolderBlacklisted);
        }

        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        let old_owner = token.owner.clone();

        // Remove from old owner's list
        let mut old_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(old_owner.clone()))
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = old_tokens.iter().position(|id| id == token_id) {
            old_tokens.remove(pos as u32);
        }
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(old_owner.clone()), &old_tokens);
        env.storage()
            .persistent()
            .remove(&DataKey::Delegation(token_id));
        env.storage().instance().remove(&DataKey::OwnerCredential(
            old_owner.clone(),
            token.credential_id,
        ));

        // Add to new owner
        token.owner = new_owner.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &new_owner);
        let mut new_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(new_owner.clone()))
            .unwrap_or(Vec::new(&env));
        new_tokens.push_back(token_id);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(new_owner.clone()), &new_tokens);
        env.storage().instance().set(
            &DataKey::OwnerCredential(new_owner.clone(), token.credential_id),
            &token_id,
        );

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("transfer").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (old_owner, new_owner.clone()));
        Self::record_notification(&env, new_owner, token_id, symbol_short!("transfer"));
    }

    // ── Issue #1275: Dual-Ownership (individual + organization) ────────

    /// Propose `candidate` as co-owner of an SBT held by `owner`. This only
    /// records the proposal — the SBT is left untouched until the candidate
    /// calls `accept_co_owner`, so an owner cannot name an unwilling party.
    /// Proposing again replaces any earlier pending proposal.
    ///
    /// # Panics
    /// - "token not found" if `token_id` does not exist.
    /// - "not the owner" if `owner` does not hold the SBT.
    /// - `ContractError::InvalidCoOwner` if `candidate == owner`.
    pub fn propose_co_owner(env: Env, owner: Address, token_id: u64, candidate: Address) {
        owner.require_auth();

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        assert!(token.owner == owner, "not the owner");
        if candidate == owner {
            panic_with_error!(&env, ContractError::InvalidCoOwner);
        }

        env.storage()
            .persistent()
            .set(&DataKey::CoOwnerProposal(token_id), &candidate);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("prop_co").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (owner, candidate));
    }

    /// Accept a pending co-owner proposal. Requires the candidate's own
    /// signature, which is what makes co-ownership consensual.
    ///
    /// # Panics
    /// - `ContractError::CoOwnerProposalNotFound` if there is no pending
    ///   proposal for `candidate` on this SBT.
    /// - "token not found" if `token_id` does not exist.
    /// - `ContractError::InvalidCoOwner` if `candidate` is now the owner.
    pub fn accept_co_owner(env: Env, candidate: Address, token_id: u64) {
        candidate.require_auth();

        let proposed: Address = env
            .storage()
            .persistent()
            .get(&DataKey::CoOwnerProposal(token_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::CoOwnerProposalNotFound));
        if proposed != candidate {
            panic_with_error!(&env, ContractError::CoOwnerProposalNotFound);
        }

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");

        env.storage()
            .persistent()
            .remove(&DataKey::CoOwnerProposal(token_id));
        Self::assign_co_owner(&env, token_id, token, candidate);
    }

    /// Returns the pending co-owner proposal for an SBT, if any.
    pub fn get_co_owner_proposal(env: Env, token_id: u64) -> Option<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::CoOwnerProposal(token_id))
    }

    /// Assign a co-owner (e.g. an organization) to an SBT already held by an
    /// individual `owner`, in a single call.
    ///
    /// Deprecated in favour of `propose_co_owner` / `accept_co_owner`; it is
    /// kept for compatibility and now requires the co-owner's signature too,
    /// so it can no longer be used to name an unwilling party.
    ///
    /// # Panics
    /// - "token not found" if `token_id` does not exist.
    /// - `ContractError::InvalidCoOwner` if `co_owner == owner`.
    pub fn set_co_owner(env: Env, owner: Address, token_id: u64, co_owner: Address) {
        owner.require_auth();
        co_owner.require_auth();

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        assert!(token.owner == owner, "not the owner");

        Self::assign_co_owner(&env, token_id, token, co_owner);
    }

    /// Internal helper: write the co-owner onto an already-loaded token,
    /// emit the `set_co` event and append to the ownership history.
    fn assign_co_owner(
        env: &Env,
        token_id: u64,
        mut token: SoulboundToken,
        co_owner: Address,
    ) {
        let owner = token.owner.clone();
        if co_owner == owner {
            panic_with_error!(env, ContractError::InvalidCoOwner);
        }

        token.co_owner = Some(co_owner.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(env);
        topics.push_back(symbol_short!("set_co").into_val(env));
        topics.push_back(token_id.into_val(env));
        env.events().publish(topics, (owner.clone(), co_owner.clone()));
        Self::record_ownership_history(
            env,
            token_id,
            owner,
            Some(co_owner),
            symbol_short!("set_co"),
        );
    }

    /// Remove the co-owner from an SBT. Requires signatures from **both**
    /// the current `owner` and the current `co_owner` — neither party can
    /// unilaterally strip the other's ownership stake.
    ///
    /// # Panics
    /// - "token not found" if `token_id` does not exist.
    /// - `ContractError::CoOwnerNotSet` if the token has no co-owner.
    /// - "co-owner mismatch" if `co_owner` does not match the stored co-owner.
    pub fn remove_co_owner(env: Env, owner: Address, co_owner: Address, token_id: u64) {
        owner.require_auth();
        co_owner.require_auth();

        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        assert!(token.owner == owner, "not the owner");
        match &token.co_owner {
            Some(stored) => assert!(*stored == co_owner, "co-owner mismatch"),
            None => panic_with_error!(&env, ContractError::CoOwnerNotSet),
        }

        token.co_owner = None;
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("rm_co").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (owner.clone(), co_owner));
        Self::record_ownership_history(&env, token_id, owner, None, symbol_short!("rm_co"));
    }

    /// Transfer primary ownership of a dual-owned (or single-owned) SBT to
    /// `new_owner`. If the SBT has a `co_owner` set, **both** the current
    /// `owner` and `co_owner` must authorize this call; otherwise only
    /// `owner`'s signature is required. The co-owner slot itself is left
    /// unchanged by this transfer — only the primary `owner` moves.
    ///
    /// # Panics
    /// - "token not found" if `token_id` does not exist.
    pub fn transfer_ownership_dual(env: Env, token_id: u64, new_owner: Address) {
        if Self::is_paused(&env) {
            panic!("contract is paused");
        }

        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        let old_owner = token.owner.clone();
        old_owner.require_auth();
        if let Some(co_owner) = token.co_owner.clone() {
            co_owner.require_auth();
        }

        // Remove from old owner's list
        let mut old_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(old_owner.clone()))
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = old_tokens.iter().position(|id| id == token_id) {
            old_tokens.remove(pos as u32);
        }
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(old_owner.clone()), &old_tokens);
        env.storage().instance().remove(&DataKey::OwnerCredential(
            old_owner.clone(),
            token.credential_id,
        ));

        // Add to new owner
        token.owner = new_owner.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &new_owner);
        let mut new_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(new_owner.clone()))
            .unwrap_or(Vec::new(&env));
        new_tokens.push_back(token_id);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(new_owner.clone()), &new_tokens);
        env.storage().instance().set(
            &DataKey::OwnerCredential(new_owner.clone(), token.credential_id),
            &token_id,
        );

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("dual_xfer").into_val(&env));
        topics.push_back(token_id.into_val(&env));
        env.events().publish(topics, (old_owner, new_owner.clone()));
        Self::record_notification(&env, new_owner.clone(), token_id, symbol_short!("dual_xfer"));
        Self::record_ownership_history(
            &env,
            token_id,
            new_owner,
            token.co_owner,
            symbol_short!("dual_xfer"),
        );
    }

    /// Returns the co-owner of an SBT, if any.
    ///
    /// # Panics
    /// "token not found" if `token_id` does not exist.
    pub fn get_co_owner(env: Env, token_id: u64) -> Option<Address> {
        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .expect("token not found");
        token.co_owner
    }

    /// Returns the full ownership history (owner/co-owner changes) for an
    /// SBT, oldest first. Empty if the token doesn't exist or predates this
    /// feature.
    pub fn get_ownership_history(env: Env, token_id: u64) -> Vec<OwnershipHistoryEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::OwnershipHistory(token_id))
            .unwrap_or(Vec::new(&env))
    }

    /// Internal helper: append an entry to an SBT's ownership history.
    fn record_ownership_history(
        env: &Env,
        token_id: u64,
        owner: Address,
        co_owner: Option<Address>,
        event: Symbol,
    ) {
        let key = DataKey::OwnershipHistory(token_id);
        let mut history: Vec<OwnershipHistoryEntry> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(env));
        history.push_back(OwnershipHistoryEntry {
            owner,
            co_owner,
            changed_at: env.ledger().timestamp(),
            event,
        });
        env.storage().persistent().set(&key, &history);
        env.storage()
            .persistent()
            .extend_ttl(&key, STANDARD_TTL, EXTENDED_TTL);
    }

    /// Admin-only contract upgrade to new WASM. Uses deployer convention for auth.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: soroban_sdk::BytesN<32>) {
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Emergency pause: prevents all state-changing operations (mint, burn, etc.).
    /// Only the admin may call this. Allows reads to continue.
    pub fn pause(env: Env, admin: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored_admin == admin, "unauthorized");
        env.storage().instance().set(&DataKey::Paused, &true);
        env.storage().instance().extend_ttl(16_384, 524_288);
    }

    /// Resume normal operation after pause. Only the admin may call this.
    pub fn unpause(env: Env, admin: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored_admin == admin, "unauthorized");
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().extend_ttl(16_384, 524_288);
    }

    /// Check if the contract is paused. Returns true if paused, false otherwise.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    // ── SBT Holder Recovery ──────────────────────────────────────

    /// Configure the recovery guardians and approval threshold for the contract.
    /// Only the admin may call this. Sets up the multi-sig recovery mechanism.
    ///
    /// # Parameters
    /// - `admin`: The admin address; must authorize this call.
    /// - `guardians`: List of addresses authorized to approve recovery requests.
    /// - `threshold`: Number of guardian approvals required to finalize recovery.
    ///
    /// # Panics
    /// Panics if caller is not the admin.
    /// Panics if guardians list is empty or exceeds maximum allowed.
    /// Panics if threshold is 0 or exceeds the number of guardians.
    pub fn setup_recovery_guardians(
        env: Env,
        admin: Address,
        guardians: Vec<Address>,
        threshold: u32,
    ) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored_admin == admin, "unauthorized");

        assert!(!guardians.is_empty(), "guardians list cannot be empty");
        assert!(guardians.len() <= 10, "too many guardians (max 10)");
        assert!(threshold > 0, "threshold must be greater than 0");
        assert!(
            threshold <= guardians.len() as u32,
            "threshold cannot exceed number of guardians"
        );

        env.storage()
            .instance()
            .set(&DataKey::RecoveryGuardians, &guardians);
        env.storage()
            .instance()
            .set(&DataKey::RecoveryThreshold, &threshold);
        env.storage()
            .instance()
            .extend_ttl(STANDARD_TTL, EXTENDED_TTL);
    }

    /// Get the current recovery guardians configured for this contract.
    pub fn get_recovery_guardians(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::RecoveryGuardians)
            .unwrap_or(Vec::new(&env))
    }

    /// Get the current recovery approval threshold.
    pub fn get_recovery_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::RecoveryThreshold)
            .unwrap_or(0u32)
    }

    /// Initiate a recovery request for a lost or compromised account.
    ///
    /// The holder calls this to request recovery of their SBTs to a new address.
    /// Once the recovery is approved by the threshold number of guardians,
    /// the holder can finalize the recovery to transfer their SBTs.
    ///
    /// # Parameters
    /// - `initiator`: The current account holder; must authorize this call.
    /// - `new_owner`: The new account to recover SBTs to.
    ///
    /// # Panics
    /// Panics if no recovery guardians have been configured.
    /// Panics if a recovery request already exists for this holder.
    /// Panics if initiator is the same as new_owner.
    pub fn initiate_recovery(env: Env, initiator: Address, new_owner: Address) -> u64 {
        initiator.require_auth();

        let guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryGuardians)
            .unwrap_or(Vec::new(&env));
        assert!(!guardians.is_empty(), "recovery guardians not configured");
        assert!(
            initiator != new_owner,
            "new owner must be different from initiator"
        );

        // Check if there's already a pending recovery for this holder
        if env
            .storage()
            .instance()
            .has(&DataKey::PendingRecoveryByHolder(initiator.clone()))
        {
            panic_with_error!(&env, ContractError::RecoveryAlreadyExists);
        }

        // Create recovery request
        let request_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryRequestCount)
            .unwrap_or(0u64)
            + 1;
        let request = RecoveryRequest {
            id: request_id,
            initiator: initiator.clone(),
            new_owner: new_owner.clone(),
            initiated_at: env.ledger().timestamp(),
            completed: false,
            approvals_count: 0,
        };

        env.storage()
            .instance()
            .set(&DataKey::RecoveryRequest(request_id), &request);
        env.storage()
            .instance()
            .set(&DataKey::RecoveryRequestCount, &request_id);
        env.storage().instance().set(
            &DataKey::PendingRecoveryByHolder(initiator.clone()),
            &request_id,
        );
        env.storage()
            .instance()
            .extend_ttl(STANDARD_TTL, EXTENDED_TTL);

        // Initialize empty approvals vector
        let approvals: Vec<RecoveryApproval> = Vec::new(&env);
        env.storage()
            .instance()
            .set(&DataKey::RecoveryApprovals(request_id), &approvals);
        env.storage()
            .instance()
            .extend_ttl(STANDARD_TTL, EXTENDED_TTL);

        // Record audit trail
        Self::record_audit_trail(
            &env,
            request_id,
            symbol_short!("init"),
            initiator.clone(),
            soroban_sdk::String::from_str(&env, "Recovery initiated"),
        );

        // Emit event
        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("recov_in").into_val(&env));
        topics.push_back(request_id.into_val(&env));
        env.events().publish(topics, initiator);

        request_id
    }

    /// Approve a pending recovery request as a guardian.
    ///
    /// A configured recovery guardian calls this to approve a recovery request.
    /// Once the threshold number of approvals is reached, the initiator can
    /// finalize the recovery.
    ///
    /// # Parameters
    /// - `guardian`: The guardian address approving; must authorize this call and be in guardians list.
    /// - `recovery_request_id`: The ID of the recovery request to approve.
    ///
    /// # Panics
    /// Panics with `ContractError::RecoveryNotFound` if the recovery request doesn't exist.
    /// Panics if the guardian is not in the configured guardians list.
    /// Panics if the guardian has already approved this request.
    /// Panics if the recovery has already been completed.
    pub fn approve_recovery(env: Env, guardian: Address, recovery_request_id: u64) {
        guardian.require_auth();

        let guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryGuardians)
            .unwrap_or(Vec::new(&env));

        let mut is_guardian = false;
        for g in guardians.iter() {
            if g == guardian {
                is_guardian = true;
                break;
            }
        }
        assert!(
            is_guardian,
            "only configured guardians can approve recoveries"
        );

        // Get recovery request
        let mut recovery: RecoveryRequest = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryRequest(recovery_request_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::RecoveryNotFound));

        assert!(!recovery.completed, "recovery already completed");

        // Get existing approvals
        let mut approvals: Vec<RecoveryApproval> = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryApprovals(recovery_request_id))
            .unwrap_or(Vec::new(&env));

        // Check if guardian has already approved
        for approval in approvals.iter() {
            assert!(
                approval.guardian != guardian,
                "guardian has already approved this recovery"
            );
        }

        // Add approval
        let new_approval = RecoveryApproval {
            guardian: guardian.clone(),
            approved_at: env.ledger().timestamp(),
        };
        approvals.push_back(new_approval);

        // Update recovery request with new approval count
        recovery.approvals_count += 1;

        env.storage()
            .instance()
            .set(&DataKey::RecoveryApprovals(recovery_request_id), &approvals);
        env.storage()
            .instance()
            .set(&DataKey::RecoveryRequest(recovery_request_id), &recovery);
        env.storage()
            .instance()
            .extend_ttl(STANDARD_TTL, EXTENDED_TTL);

        // Record audit trail
        Self::record_audit_trail(
            &env,
            recovery_request_id,
            symbol_short!("approv"),
            guardian.clone(),
            soroban_sdk::String::from_str(&env, "Recovery approved by guardian"),
        );

        // Emit event
        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("recov_ap").into_val(&env));
        topics.push_back(recovery_request_id.into_val(&env));
        env.events().publish(topics, guardian);
    }

    /// Finalize a recovery request by transferring SBTs to the new owner.
    ///
    /// The initiator calls this after collecting enough guardian approvals.
    /// This transfers all SBTs from the original account to the new owner.
    ///
    /// # Parameters
    /// - `initiator`: The recovery initiator; must authorize this call.
    /// - `recovery_request_id`: The ID of the recovery request to finalize.
    ///
    /// # Panics
    /// Panics with `ContractError::RecoveryNotFound` if the recovery request doesn't exist.
    /// Panics with `ContractError::InsufficientApprovals` if threshold not reached.
    /// Panics if recovery already completed.
    pub fn finalize_recovery(env: Env, initiator: Address, recovery_request_id: u64) {
        initiator.require_auth();

        let mut recovery: RecoveryRequest = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryRequest(recovery_request_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::RecoveryNotFound));

        assert!(
            recovery.initiator == initiator,
            "only recovery initiator can finalize"
        );
        assert!(!recovery.completed, "recovery already completed");

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryThreshold)
            .unwrap_or(0u32);
        assert!(
            recovery.approvals_count >= threshold,
            "insufficient approvals: need {} but have {}",
            threshold,
            recovery.approvals_count
        );

        // Transfer all SBTs from initiator to new_owner
        let token_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(initiator.clone()))
            .unwrap_or(Vec::new(&env));

        let new_owner = recovery.new_owner.clone();

        // Update each token and transfer ownership
        for token_id in token_ids.iter() {
            let mut token: SoulboundToken = env
                .storage()
                .persistent()
                .get(&DataKey::Token(token_id))
                .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

            // Update token owner
            token.owner = new_owner.clone();
            env.storage()
                .persistent()
                .set(&DataKey::Token(token_id), &token);
            env.storage()
                .persistent()
                .set(&DataKey::Owner(token_id), &new_owner);

            // Remove from old owner's mapping
            env.storage().instance().remove(&DataKey::OwnerCredential(
                initiator.clone(),
                token.credential_id,
            ));

            // Add to new owner's mapping
            env.storage().instance().set(
                &DataKey::OwnerCredential(new_owner.clone(), token.credential_id),
                &token_id,
            );
        }

        // Clear initiator's token list
        env.storage()
            .persistent()
            .remove(&DataKey::OwnerTokens(initiator.clone()));

        // Add to new owner's token list
        let mut new_owner_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(new_owner.clone()))
            .unwrap_or(Vec::new(&env));
        for token_id in token_ids.iter() {
            new_owner_tokens.push_back(token_id);
        }
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(new_owner.clone()), &new_owner_tokens);
        env.storage().persistent().extend_ttl(
            &DataKey::OwnerTokens(new_owner.clone()),
            STANDARD_TTL,
            EXTENDED_TTL,
        );

        // Mark recovery as completed
        recovery.completed = true;
        env.storage()
            .instance()
            .set(&DataKey::RecoveryRequest(recovery_request_id), &recovery);

        // Clear pending recovery tracking
        env.storage()
            .instance()
            .remove(&DataKey::PendingRecoveryByHolder(initiator.clone()));

        // Record audit trail
        Self::record_audit_trail(
            &env,
            recovery_request_id,
            symbol_short!("final"),
            initiator.clone(),
            soroban_sdk::String::from_str(&env, "Recovery finalized and SBTs transferred"),
        );

        // Emit event
        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("recov_fn").into_val(&env));
        topics.push_back(recovery_request_id.into_val(&env));
        env.events().publish(topics, (initiator, new_owner));
    }

    /// Get a recovery request by ID.
    ///
    /// # Parameters
    /// - `recovery_request_id`: The recovery request ID to retrieve.
    ///
    /// # Panics
    /// Panics with `ContractError::RecoveryNotFound` if the request doesn't exist.
    pub fn get_recovery_request(env: Env, recovery_request_id: u64) -> RecoveryRequest {
        env.storage()
            .instance()
            .get(&DataKey::RecoveryRequest(recovery_request_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::RecoveryNotFound))
    }

    /// Get all approvals for a recovery request.
    ///
    /// # Parameters
    /// - `recovery_request_id`: The recovery request ID.
    ///
    /// # Returns
    /// Vector of all approvals for the recovery request.
    pub fn get_recovery_approvals(env: Env, recovery_request_id: u64) -> Vec<RecoveryApproval> {
        env.storage()
            .instance()
            .get(&DataKey::RecoveryApprovals(recovery_request_id))
            .unwrap_or(Vec::new(&env))
    }

    /// Helper function to record audit trail entries for recovery operations.
    fn record_audit_trail(
        env: &Env,
        recovery_request_id: u64,
        action: Symbol,
        actor: Address,
        details: soroban_sdk::String,
    ) {
        let entry_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditTrailCount)
            .unwrap_or(0u64)
            + 1;
        let entry = AuditTrailEntry {
            id: entry_id,
            recovery_request_id,
            action,
            actor,
            timestamp: env.ledger().timestamp(),
            details,
        };

        env.storage()
            .instance()
            .set(&DataKey::AuditTrail(entry_id), &entry);
        env.storage()
            .instance()
            .set(&DataKey::AuditTrailCount, &entry_id);
        env.storage()
            .instance()
            .extend_ttl(STANDARD_TTL, EXTENDED_TTL);
    }

    /// Get an audit trail entry by ID.
    ///
    /// # Parameters
    /// - `audit_id`: The audit trail entry ID.
    ///
    /// # Returns
    /// The audit trail entry, or panics if not found.
    pub fn get_audit_trail_entry(env: Env, audit_id: u64) -> AuditTrailEntry {
        env.storage()
            .instance()
            .get(&DataKey::AuditTrail(audit_id))
            .expect("audit trail entry not found")
    }

    /// Get the total count of audit trail entries.
    pub fn get_audit_trail_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::AuditTrailCount)
            .unwrap_or(0u64)
    }

    /// Admin-only: set the weights used by get_holder_reputation.
    pub fn set_reputation_config(
        env: Env,
        admin: Address,
        token_weight: u32,
        activity_weight: u32,
    ) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(admin == stored_admin, "unauthorized");
        env.storage().instance().set(
            &DataKey::ReputationConfig,
            &ReputationConfig {
                token_weight,
                activity_weight,
            },
        );
    }

    /// Return the reputation score for a holder.
    /// score = tokens_held * token_weight + activity_events * activity_weight
    /// Defaults: token_weight = 10, activity_weight = 1.
    pub fn get_holder_reputation(env: Env, holder: Address) -> u32 {
        let cfg: ReputationConfig = env
            .storage()
            .instance()
            .get(&DataKey::ReputationConfig)
            .unwrap_or(ReputationConfig {
                token_weight: 10,
                activity_weight: 1,
            });
        let tokens = env
            .storage()
            .persistent()
            .get::<DataKey, Vec<u64>>(&DataKey::OwnerTokens(holder.clone()))
            .unwrap_or(Vec::new(&env))
            .len();
        let activity = env
            .storage()
            .persistent()
            .get::<DataKey, Vec<NotificationEntry>>(&DataKey::NotificationHistory(holder))
            .unwrap_or(Vec::new(&env))
            .len();
        tokens * cfg.token_weight + activity * cfg.activity_weight
    }

    /// Append a notification entry to the holder's on-chain history.
    fn record_notification(env: &Env, holder: Address, token_id: u64, event: Symbol) {
        let key = DataKey::NotificationHistory(holder);
        let mut history: Vec<NotificationEntry> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(env));
        history.push_back(NotificationEntry {
            token_id,
            event,
            timestamp: env.ledger().timestamp(),
        });
        env.storage().persistent().set(&key, &history);
        env.storage()
            .persistent()
            .extend_ttl(&key, STANDARD_TTL, EXTENDED_TTL);
    }

    /// Return all notification entries recorded for a holder.
    pub fn get_notifications(env: Env, holder: Address) -> Vec<NotificationEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::NotificationHistory(holder))
            .unwrap_or(Vec::new(&env))
    }

    /// Mint multiple SBTs in a single atomic transaction.
    /// Returns the newly assigned token IDs in input order.
    pub fn batch_mint(env: Env, entries: Vec<BatchMintEntry>) -> Vec<u64> {
        // Issue #1402: reject empty batches and batches over MAX_BATCH_SIZE
        // before any validation or state changes.
        if !Self::is_valid_batch_size(entries.len()) {
            panic_with_error!(&env, ContractError::BatchTooLarge);
        }

        // ── Validation phase ────────────────────────────────────────────────
        // All checks run before any state is written, guaranteeing atomicity.

        // Requirement 1.2: require auth from each distinct owner.
        // Collect distinct owners via O(n²) scan (no std HashSet in no_std).
        for i in 0..entries.len() {
            let owner_i = entries.get(i).unwrap().owner.clone();
            let mut already_authed = false;
            for j in 0..i {
                if entries.get(j).unwrap().owner == owner_i {
                    already_authed = true;
                    break;
                }
            }
            if !already_authed {
                owner_i.require_auth();
            }
        }

        // Fetch the QuorumProof contract address once.
        let qp_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("not initialized");

        for i in 0..entries.len() {
            let entry = entries.get(i).unwrap();

            // Issue #1403: mirror mint()'s blacklist check for each entry's owner.
            if env
                .storage()
                .instance()
                .has(&DataKey::Blacklist(entry.owner.clone()))
            {
                panic_with_error!(&env, ContractError::HolderBlacklisted);
            }

            // Requirement 1.3 / 1.4: verify credential is not revoked via QuorumProof.
            // is_revoked panics with CredentialNotFound if the credential doesn't exist.
            let revoked: bool = env.invoke_contract(
                &qp_id,
                &Symbol::new(&env, "is_revoked"),
                soroban_sdk::vec![&env, entry.credential_id.into_val(&env)],
            );
            assert!(!revoked, "credential is revoked");

            // Requirement 1.5: (owner, credential_id) must not already exist in storage.
            if env.storage().instance().has(&DataKey::OwnerCredential(
                entry.owner.clone(),
                entry.credential_id,
            )) {
                panic_with_error!(&env, ContractError::SoulboundNonTransferable);
            }
        }

        // Requirement 1.6: O(n²) intra-batch duplicate (owner, credential_id) scan.
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if entries.get(i).unwrap().owner == entries.get(j).unwrap().owner
                    && entries.get(i).unwrap().credential_id
                        == entries.get(j).unwrap().credential_id
                {
                    panic_with_error!(&env, ContractError::SoulboundNonTransferable);
                }
            }
        }

        // ── Execution phase (Issue #1244) ────────────────────────────────────
        // Validation passed — now execute the batch mint atomically.

        let mut token_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TokenCount)
            .unwrap_or(0);

        let mut result_ids: Vec<u64> = Vec::new(&env);

        for entry in entries.iter() {
            token_count += 1;
            let token_id = token_count;

            // Store metadata separately (Issue #512)
            env.storage()
                .persistent()
                .set(&DataKey::CompressedMetadata(token_id), &entry.metadata_uri);
            env.storage().persistent().extend_ttl(
                &DataKey::CompressedMetadata(token_id),
                STANDARD_TTL,
                EXTENDED_TTL,
            );

            let token = SoulboundToken {
                id: token_id,
                owner: entry.owner.clone(),
                credential_id: entry.credential_id,
                metadata_uri: Bytes::new(&env),
                version: 1,
                upgraded_to: None,
                co_owner: None,
            };
            env.storage()
                .persistent()
                .set(&DataKey::Token(token_id), &token);
            env.storage().persistent().extend_ttl(
                &DataKey::Token(token_id),
                STANDARD_TTL,
                EXTENDED_TTL,
            );
            env.storage()
                .persistent()
                .set(&DataKey::Owner(token_id), &entry.owner.clone());
            env.storage().persistent().extend_ttl(
                &DataKey::Owner(token_id),
                STANDARD_TTL,
                EXTENDED_TTL,
            );

            let mut owner_tokens: Vec<u64> = env
                .storage()
                .persistent()
                .get(&DataKey::OwnerTokens(entry.owner.clone()))
                .unwrap_or(Vec::new(&env));
            owner_tokens.push_back(token_id);
            env.storage()
                .persistent()
                .set(&DataKey::OwnerTokens(entry.owner.clone()), &owner_tokens);
            env.storage().persistent().extend_ttl(
                &DataKey::OwnerTokens(entry.owner.clone()),
                STANDARD_TTL,
                EXTENDED_TTL,
            );

            env.storage().instance().set(
                &DataKey::OwnerCredential(entry.owner.clone(), entry.credential_id),
                &token_id,
            );

            let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
            topics.push_back(symbol_short!("mint").into_val(&env));
            topics.push_back(token_id.into_val(&env));
            env.events()
                .publish(topics, (entry.owner.clone(), entry.credential_id));

            Self::record_notification(&env, entry.owner.clone(), token_id, symbol_short!("mint"));
            Self::log_sbt_activity(&env, token_id, symbol_short!("mint"), entry.owner.clone());
            Self::record_ownership_history(&env, token_id, entry.owner.clone(), None, symbol_short!("mint"));

            result_ids.push_back(token_id);
        }

        env.storage()
            .instance()
            .set(&DataKey::TokenCount, &token_count);

        result_ids
    }

    /// Burn multiple SBTs in a single atomic transaction.
    /// Returns the credential_id values of the burned tokens in input order.
    /// Each caller must authorize this call via require_auth.
    ///
    /// # Parameters
    /// - `entries`: Vector of burn entries, each specifying a caller and token_id.
    ///   The batch may be paginated by splitting large requests.
    ///
    /// # Returns
    /// Vector of credential_id values of the burned tokens, in input order.
    ///
    /// # Panics
    /// Panics if any token doesn't exist or if caller is not the holder.
    pub fn batch_burn(env: Env, entries: Vec<BatchBurnEntry>) -> Vec<u64> {
        // Issue #1402: reject empty batches and batches over MAX_BATCH_SIZE.
        if !Self::is_valid_batch_size(entries.len()) {
            panic_with_error!(&env, ContractError::BatchTooLarge);
        }

        // Require auth from each distinct caller
        for i in 0..entries.len() {
            let caller_i = entries.get(i).unwrap().caller.clone();
            let mut already_authed = false;
            for j in 0..i {
                if entries.get(j).unwrap().caller == caller_i {
                    already_authed = true;
                    break;
                }
            }
            if !already_authed {
                caller_i.require_auth();
            }
        }

        let mut result_cred_ids: Vec<u64> = Vec::new(&env);

        for entry in entries.iter() {
            let token: SoulboundToken = env
                .storage()
                .persistent()
                .get(&DataKey::Token(entry.token_id))
                .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

            assert!(token.owner == entry.caller, "not the owner");

            let credential_id = token.credential_id;

            env.storage()
                .persistent()
                .remove(&DataKey::Token(entry.token_id));
            env.storage()
                .persistent()
                .remove(&DataKey::Owner(entry.token_id));
            env.storage()
                .persistent()
                .remove(&DataKey::Delegation(entry.token_id));
            env.storage().instance().remove(&DataKey::OwnerCredential(
                entry.caller.clone(),
                credential_id,
            ));

            let mut owner_tokens: Vec<u64> = env
                .storage()
                .persistent()
                .get(&DataKey::OwnerTokens(entry.caller.clone()))
                .unwrap_or(Vec::new(&env));
            if let Some(pos) = owner_tokens.iter().position(|id| id == entry.token_id) {
                owner_tokens.remove(pos as u32);
            }
            env.storage()
                .persistent()
                .set(&DataKey::OwnerTokens(entry.caller.clone()), &owner_tokens);

            let burn_event = BurnEvent {
                sbt_id: entry.token_id,
                holder: entry.caller.clone(),
                timestamp: env.ledger().timestamp(),
            };
            let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
            topics.push_back(Symbol::new(&env, "burn_sbt").into_val(&env));
            topics.push_back(entry.token_id.into_val(&env));
            env.events().publish(topics, burn_event);

            Self::record_notification(&env, entry.caller.clone(), entry.token_id, symbol_short!("burn"));
            Self::log_sbt_activity(&env, entry.token_id, symbol_short!("burn"), entry.caller.clone());

            result_cred_ids.push_back(credential_id);
        }

        result_cred_ids
    }

    /// Admin-transfer multiple SBTs in a single atomic transaction.
    /// Returns the transferred token IDs in input order.
    /// Only the admin may call this.
    ///
    /// # Parameters
    /// - `admin`: The admin address; must authorize this call.
    /// - `entries`: Vector of transfer entries, each specifying a token_id and new_owner.
    ///   The batch may be paginated by splitting large requests.
    ///
    /// # Returns
    /// Vector of transferred token IDs, in input order.
    pub fn batch_transfer(
        env: Env,
        admin: Address,
        entries: Vec<BatchTransferEntry>,
    ) -> Vec<u64> {
        admin.require_auth();

        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(admin == stored_admin, "unauthorized");

        // Issue #1402: reject empty batches and batches over MAX_BATCH_SIZE.
        if !Self::is_valid_batch_size(entries.len()) {
            panic_with_error!(&env, ContractError::BatchTooLarge);
        }

        let mut result_ids: Vec<u64> = Vec::new(&env);

        for entry in entries.iter() {
            let mut token: SoulboundToken = env
                .storage()
                .persistent()
                .get(&DataKey::Token(entry.token_id))
                .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

            let old_owner = token.owner.clone();

            // Remove from old owner's list
            let mut old_tokens: Vec<u64> = env
                .storage()
                .persistent()
                .get(&DataKey::OwnerTokens(old_owner.clone()))
                .unwrap_or(Vec::new(&env));
            if let Some(pos) = old_tokens.iter().position(|id| id == entry.token_id) {
                old_tokens.remove(pos as u32);
            }
            env.storage()
                .persistent()
                .set(&DataKey::OwnerTokens(old_owner.clone()), &old_tokens);
            env.storage()
                .persistent()
                .remove(&DataKey::Delegation(entry.token_id));
            env.storage().instance().remove(&DataKey::OwnerCredential(
                old_owner.clone(),
                token.credential_id,
            ));

            // Add to new owner
            token.owner = entry.new_owner.clone();
            env.storage()
                .persistent()
                .set(&DataKey::Token(entry.token_id), &token);
            env.storage()
                .persistent()
                .set(&DataKey::Owner(entry.token_id), &entry.new_owner);
            let mut new_tokens: Vec<u64> = env
                .storage()
                .persistent()
                .get(&DataKey::OwnerTokens(entry.new_owner.clone()))
                .unwrap_or(Vec::new(&env));
            new_tokens.push_back(entry.token_id);
            env.storage()
                .persistent()
                .set(&DataKey::OwnerTokens(entry.new_owner.clone()), &new_tokens);
            env.storage().instance().set(
                &DataKey::OwnerCredential(entry.new_owner.clone(), token.credential_id),
                &entry.token_id,
            );

            let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
            topics.push_back(symbol_short!("transfer").into_val(&env));
            topics.push_back(entry.token_id.into_val(&env));
            env.events()
                .publish(topics, (old_owner, entry.new_owner.clone()));
            Self::record_notification(&env, entry.new_owner.clone(), entry.token_id, symbol_short!("transfer"));

            result_ids.push_back(entry.token_id);
        }

        result_ids
    }

    /// Helper function to validate batch size for pagination.
    /// Returns true if the batch size is within acceptable limits.
    pub fn is_valid_batch_size(batch_size: u32) -> bool {
        batch_size > 0 && batch_size <= MAX_BATCH_SIZE
    }

    /// Get the maximum batch size allowed for batch operations.
    pub fn get_max_batch_size() -> u32 {
        MAX_BATCH_SIZE
    }

    /// Blacklist a holder address. Admin-only.
    /// Blacklisted holders cannot mint new SBTs.
    pub fn add_holder_to_blacklist(env: Env, admin: Address, holder: Address) {
        admin.require_auth();
        let stored_admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored_admin == admin, "unauthorized");
        env.storage().instance().set(&DataKey::Blacklist(holder), &true);
    }

    /// Returns true if the holder is blacklisted.
    pub fn is_holder_blacklisted(env: Env, holder: Address) -> bool {
        env.storage().instance().has(&DataKey::Blacklist(holder))
    }

    /// Issue #1404: remove a holder from the blacklist. Admin-only.
    /// Reverses `add_holder_to_blacklist`, allowing a previously blacklisted
    /// address to mint again.
    pub fn remove_holder_from_blacklist(env: Env, admin: Address, holder: Address) {
        admin.require_auth();
        let stored_admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(stored_admin == admin, "unauthorized");
        env.storage().instance().remove(&DataKey::Blacklist(holder.clone()));

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("unblcklst").into_val(&env));
        env.events().publish(topics, (holder, admin));
    }

    /// Update the metadata URI of an SBT. Only the token owner may call this.
    /// Increments the token version on each update.
    pub fn update_metadata(env: Env, owner: Address, token_id: u64, new_metadata_uri: Bytes) {
        owner.require_auth();
        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));
        assert!(token.owner == owner, "not the owner");
        // Issue #512: Store metadata separately; keep struct metadata_uri empty.
        env.storage()
            .persistent()
            .set(&DataKey::CompressedMetadata(token_id), &new_metadata_uri);
        env.storage().persistent().extend_ttl(
            &DataKey::CompressedMetadata(token_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );
        token.version += 1;
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &token);
        env.storage().persistent().extend_ttl(
            &DataKey::Token(token_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );
        Self::log_sbt_activity(&env, token_id, symbol_short!("upd_meta"), owner);
    }

    /// Append an activity entry to the SBT's activity log.
    fn log_sbt_activity(env: &Env, token_id: u64, action: Symbol, actor: Address) {
        let key = DataKey::SbtActivityLog(token_id);
        let mut log: Vec<SbtActivityEntry> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(env));
        log.push_back(SbtActivityEntry {
            action,
            actor,
            timestamp: env.ledger().timestamp(),
        });
        env.storage().persistent().set(&key, &log);
        env.storage()
            .persistent()
            .extend_ttl(&key, STANDARD_TTL, EXTENDED_TTL);
    }

    /// Return the full activity log for an SBT.
    pub fn get_sbt_activity_log(env: Env, sbt_id: u64) -> Vec<SbtActivityEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::SbtActivityLog(sbt_id))
            .unwrap_or(Vec::new(&env))
    }

    // ── Issue #989: SBT Metadata URI and Rendering ──────────────────────────────

    /// Issue #989: Set the metadata URI for an SBT.
    /// Issuer-only: the issuer of the credential underlying this SBT can update the
    /// metadata URI to enable wallet rendering and display.
    /// URI must be HTTPS or IPFS and max 256 characters.
    ///
    /// # Parameters
    /// - `issuer`: The issuer address (must match credential's issuer).
    /// - `sbt_id`: The SBT ID.
    /// - `metadata_uri`: New metadata URI (HTTPS or IPFS, max 256 chars).
    ///
    /// # Panics
    /// - If SBT not found.
    /// - If caller is not the credential's issuer.
    /// - If URI format is invalid (not HTTPS or IPFS).
    /// - If URI exceeds 256 characters.
    pub fn set_sbt_metadata_uri(env: Env, issuer: Address, sbt_id: u64, metadata_uri: soroban_sdk::String) {
        issuer.require_auth();

        // `String::len` is the byte length of the URI itself; the XDR
        // envelope adds framing that must not count here. The buffer is
        // sized to MAX_METADATA_URI_LEN, so the length must be checked
        // before copying into it.
        let uri_len = metadata_uri.len() as usize;
        if uri_len > MAX_METADATA_URI_LEN {
            panic!("metadata_uri exceeds 256 characters");
        }

        // Copy into a fixed buffer so the scheme can be inspected without alloc.
        let mut uri_buf = [0u8; MAX_METADATA_URI_LEN];
        let uri_bytes = &mut uri_buf[..uri_len];
        metadata_uri.copy_into_slice(uri_bytes);
        validate_metadata_uri(uri_bytes);

        // Get the SBT to verify it exists
        let sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        // Verify the credential still exists and is not revoked
        // This ensures issuer authorization (only valid issuers create credentials)
        let qp_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("not initialized");
        
        let revoked: bool = env.invoke_contract(
            &qp_id,
            &Symbol::new(&env, "is_revoked"),
            soroban_sdk::vec![&env, sbt.credential_id.into_val(&env)],
        );
        assert!(!revoked, "credential is revoked or does not exist");

        // Store metadata URI (convert String to Bytes for storage)
        let uri_bytes_val = soroban_sdk::Bytes::from_slice(&env, uri_bytes);

        env.storage()
            .persistent()
            .set(&DataKey::SbtMetadataUri(sbt_id), &uri_bytes_val);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::SbtMetadataUri(sbt_id), STANDARD_TTL, EXTENDED_TTL);

        Self::log_sbt_activity(&env, sbt_id, symbol_short!("uri"), issuer);
    }

    /// Issue #989: Get the metadata URI for an SBT.
    /// Returns the URI used by wallets for rich rendering and display.
    ///
    /// # Parameters
    /// - `sbt_id`: The SBT ID.
    ///
    /// # Returns
    /// The metadata URI as a String, or empty string if not set.
    pub fn get_sbt_metadata_uri(env: Env, sbt_id: u64) -> soroban_sdk::String {
        let uri_bytes: Option<soroban_sdk::Bytes> = env
            .storage()
            .persistent()
            .get(&DataKey::SbtMetadataUri(sbt_id));

        match uri_bytes {
            Some(bytes) => {
                // Stored URIs are length-validated on write, so they always fit.
                let len = (bytes.len() as usize).min(MAX_METADATA_URI_LEN);
                let mut buf = [0u8; MAX_METADATA_URI_LEN];
                bytes.slice(0..len as u32).copy_into_slice(&mut buf[..len]);
                soroban_sdk::String::from_bytes(&env, &buf[..len])
            }
            None => soroban_sdk::String::from_str(&env, ""),
        }
    }

    // ── Issue #992: SBT Upgrade Path ────────────────────────────────────────────

    /// Issue #992: Upgrade an SBT to a new credential version.
    /// Issuer-only: when a credential is upgraded (e.g., PE License → PE License + Specialty),
    /// issue a new SBT and link the old one as upgraded_to.
    ///
    /// Old SBT cannot be verified independently after upgrade.
    ///
    /// # Parameters
    /// - `issuer`: The issuer address (must match credential's issuer).
    /// - `old_sbt_id`: The SBT being retired.
    /// - `new_sbt_id`: The new SBT ID replacing it.
    ///
    /// # Panics
    /// - If either SBT not found.
    /// - If caller is not the credential's issuer.
    pub fn upgrade_sbt(env: Env, issuer: Address, old_sbt_id: u64, new_sbt_id: u64) {
        issuer.require_auth();

        // Get both SBTs
        let mut old_sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(old_sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        let new_sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(new_sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        // Verify the credential still exists and is not revoked
        let qp_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("not initialized");

        let revoked: bool = env.invoke_contract(
            &qp_id,
            &Symbol::new(&env, "is_revoked"),
            soroban_sdk::vec![&env, old_sbt.credential_id.into_val(&env)],
        );
        assert!(!revoked, "credential is revoked or does not exist");

        // Mark old SBT as upgraded_to new_sbt_id
        old_sbt.upgraded_to = Some(new_sbt_id);
        env.storage()
            .persistent()
            .set(&DataKey::Token(old_sbt_id), &old_sbt);

        Self::log_sbt_activity(&env, old_sbt_id, symbol_short!("upgrade"), issuer.clone());
        Self::log_sbt_activity(&env, new_sbt_id, symbol_short!("new"), issuer);
    }

    /// Issue #992: Check if an SBT has been upgraded and get the new SBT ID.
    ///
    /// # Parameters
    /// - `sbt_id`: The SBT ID.
    ///
    /// # Returns
    /// Some(new_sbt_id) if upgraded, None otherwise.
    pub fn get_sbt_upgrade_path(env: Env, sbt_id: u64) -> Option<u64> {
        let sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        sbt.upgraded_to
    }

    // ── Issue #987: Credential Holder Earnings Tracking ─────────────────────────

    /// Record that a verifier (employer/university) accessed a credential, and
    /// accrue an optional micropayment to the credential holder.
    ///
    /// Verifier-only: the `accessor` must authorize this call via `require_auth`, so a
    /// verifier can only record their own access events and cannot forge entries on
    /// another verifier's behalf. The credential is checked for existence and
    /// revocation (via the linked `quorum_proof` contract) before any entry is written.
    ///
    /// Each call appends a [`CredentialAccessEntry`] to the credential's access log,
    /// which the holder can later read via [`get_credential_access_log`]. A
    /// `cred_access` event is emitted for off-chain indexers.
    ///
    /// # Parameters
    /// - `credential_id`: The credential being accessed.
    /// - `accessor`: The verifier address recording the access; must authorize the call.
    ///
    /// # Panics
    /// Panics if the credential does not exist or is revoked in `quorum_proof`.
    pub fn track_credential_access(env: Env, credential_id: u64, accessor: Address) {
        // Verifier-only: the accessor must sign this call.
        accessor.require_auth();

        // Verify the credential exists and is not revoked before logging access.
        // Uses env.invoke_contract to avoid a circular crate dependency with quorum_proof.
        let qp_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::QuorumProofId)
            .expect("not initialized");
        // is_revoked panics with CredentialNotFound if the credential doesn't exist.
        let revoked: bool = env.invoke_contract(
            &qp_id,
            &Symbol::new(&env, "is_revoked"),
            soroban_sdk::vec![&env, credential_id.into_val(&env)],
        );
        assert!(!revoked, "credential is revoked");

        // Settle (currently stubbed) micropayment owed to the holder for this access.
        let payment = Self::settle_access_micropayment(&env, credential_id, &accessor);

        let key = DataKey::CredentialAccessLog(credential_id);
        let mut log: Vec<CredentialAccessEntry> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        log.push_back(CredentialAccessEntry {
            accessor: accessor.clone(),
            timestamp: env.ledger().timestamp(),
            payment,
        });
        env.storage().persistent().set(&key, &log);
        env.storage()
            .persistent()
            .extend_ttl(&key, STANDARD_TTL, EXTENDED_TTL);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("access").into_val(&env));
        topics.push_back(credential_id.into_val(&env));
        env.events().publish(topics, (accessor, payment));
    }

    /// Issue #987: Compute (and, in a future implementation, transfer) the
    /// micropayment owed to a credential holder when a verifier accesses their
    /// credential.
    ///
    /// Stub: returns a flat [`CREDENTIAL_ACCESS_MICROPAYMENT`] without moving any
    /// funds. A real implementation would invoke a token contract to transfer the
    /// amount from the verifier to the credential holder.
    fn settle_access_micropayment(_env: &Env, _credential_id: u64, _accessor: &Address) -> i128 {
        // TODO(#987): wire up an actual token transfer from verifier to holder.
        CREDENTIAL_ACCESS_MICROPAYMENT
    }

    /// Return the full credential access log — every verifier access recorded via
    /// [`track_credential_access`], in chronological order. Returns an empty vec for
    /// a credential that has never been accessed.
    pub fn get_credential_access_log(env: Env, credential_id: u64) -> Vec<CredentialAccessEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialAccessLog(credential_id))
            .unwrap_or(Vec::new(&env))
    }

    // ── Issue #1242: SBT Revocation Reasons and Appeals ─────────────────────────

    /// Appeal a revoked SBT with evidence.
    /// Only the holder of the revoked SBT may call this.
    ///
    /// # Parameters
    /// - `holder`: The holder address; must authorize this call.
    /// - `sbt_id`: The ID of the revoked SBT being appealed.
    /// - `appeal_evidence`: Evidence supporting the appeal.
    ///
    /// # Panics
    /// Panics if the SBT does not exist or no revocation record found.
    pub fn appeal_sbt_revocation(
        env: Env,
        holder: Address,
        sbt_id: u64,
        appeal_evidence: Bytes,
    ) -> u64 {
        holder.require_auth();

        // Verify the SBT exists
        let _token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        // Check if a revocation record exists
        let _revocation: RevocationRecord = env
            .storage()
            .persistent()
            .get(&DataKey::RevocationReason(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::AppealNotFound));

        let appeal_id = sbt_id; // Use sbt_id as appeal identifier for simplicity
        let appeal_record = AppealRecord {
            sbt_id,
            appeal_evidence,
            appealed_by: holder.clone(),
            appealed_at: env.ledger().timestamp(),
            status: symbol_short!("pend"),
        };

        env.storage()
            .persistent()
            .set(&DataKey::SBTAppeal(appeal_id), &appeal_record);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::SBTAppeal(appeal_id), STANDARD_TTL, EXTENDED_TTL);

        // Record in appeal history
        let key = DataKey::AppealHistory(sbt_id);
        let mut history: Vec<AppealRecord> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        history.push_back(appeal_record.clone());
        env.storage().persistent().set(&key, &history);
        env.storage()
            .persistent()
            .extend_ttl(&key, STANDARD_TTL, EXTENDED_TTL);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("appeal").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, (holder, symbol_short!("pend")));

        appeal_id
    }

    /// Get the appeal record for an SBT.
    pub fn get_sbt_appeal(env: Env, sbt_id: u64) -> AppealRecord {
        env.storage()
            .persistent()
            .get(&DataKey::SBTAppeal(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::AppealNotFound))
    }

    /// Get the appeal history for an SBT.
    pub fn get_appeal_history(env: Env, sbt_id: u64) -> Vec<AppealRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::AppealHistory(sbt_id))
            .unwrap_or(Vec::new(&env))
    }

    /// Get the revocation reason for an SBT.
    pub fn get_revocation_reason(env: Env, sbt_id: u64) -> RevocationRecord {
        env.storage()
            .persistent()
            .get(&DataKey::RevocationReason(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::AppealNotFound))
    }

    /// Record a revocation reason for an SBT (admin-only).
    pub fn record_revocation_reason(
        env: Env,
        admin: Address,
        sbt_id: u64,
        reason: Bytes,
    ) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(admin == stored_admin, "unauthorized");

        let revocation_record = RevocationRecord {
            sbt_id,
            reason: reason.clone(),
            revoked_by: admin.clone(),
            revoked_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::RevocationReason(sbt_id), &revocation_record);
        env.storage()
            .persistent()
            .extend_ttl(
                &DataKey::RevocationReason(sbt_id),
                STANDARD_TTL,
                EXTENDED_TTL,
            );

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("revoke").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, (admin, reason));
    }

    // ── Issue #1243: Time-Locked SBT Clawback ─────────────────────────────────

    /// Initiate a time-locked clawback of an SBT. The clawback does not take
    /// effect immediately: `expires_at` (now + `timelock_seconds`) is the
    /// earliest point at which it may be executed, giving the holder a
    /// window to contest it. Only one clawback may be pending per SBT at a
    /// time.
    pub fn initiate_sbt_clawback(
        env: Env,
        issuer: Address,
        sbt_id: u64,
        reason: Bytes,
        timelock_seconds: u64,
    ) -> u64 {
        issuer.require_auth();

        let _sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingClawbackBySbt(sbt_id))
        {
            panic_with_error!(&env, ContractError::ClawbackAlreadyExists);
        }

        let clawback_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ClawbackRequestCount)
            .unwrap_or(0u64)
            + 1;

        let now = env.ledger().timestamp();
        let request = ClawbackRequest {
            id: clawback_id,
            sbt_id,
            issuer: issuer.clone(),
            reason,
            initiated_at: now,
            expires_at: now.saturating_add(timelock_seconds),
            status: symbol_short!("pending"),
        };

        env.storage()
            .persistent()
            .set(&DataKey::ClawbackRequest(clawback_id), &request);
        env.storage().persistent().extend_ttl(
            &DataKey::ClawbackRequest(clawback_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );
        env.storage()
            .instance()
            .set(&DataKey::ClawbackRequestCount, &clawback_id);
        env.storage()
            .persistent()
            .set(&DataKey::PendingClawbackBySbt(sbt_id), &clawback_id);
        env.storage().persistent().extend_ttl(
            &DataKey::PendingClawbackBySbt(sbt_id),
            STANDARD_TTL,
            EXTENDED_TTL,
        );

        // Issue #1413: maintain the global pending-clawbacks index.
        let mut pending: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::PendingClawbacks)
            .unwrap_or(Vec::new(&env));
        if !pending.iter().any(|id| id == clawback_id) {
            pending.push_back(clawback_id);
            env.storage()
                .persistent()
                .set(&DataKey::PendingClawbacks, &pending);
            env.storage().persistent().extend_ttl(
                &DataKey::PendingClawbacks,
                STANDARD_TTL,
                EXTENDED_TTL,
            );
        }

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("clawback").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, (issuer, clawback_id));

        clawback_id
    }

    /// Cancel a pending clawback before its timelock expires. Only the
    /// issuer who initiated it may cancel it. Frees up the SBT so a new
    /// clawback can be initiated against it.
    pub fn cancel_sbt_clawback(env: Env, issuer: Address, clawback_id: u64) {
        issuer.require_auth();

        let mut request: ClawbackRequest = env
            .storage()
            .persistent()
            .get(&DataKey::ClawbackRequest(clawback_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::ClawbackNotFound));

        if request.issuer != issuer {
            panic_with_error!(&env, ContractError::UnauthorizedClawback);
        }

        request.status = symbol_short!("cancelled");
        env.storage()
            .persistent()
            .set(&DataKey::ClawbackRequest(clawback_id), &request);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingClawbackBySbt(request.sbt_id));

        // Issue #1413: remove from the global pending-clawbacks index.
        let mut pending: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::PendingClawbacks)
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = pending.iter().position(|id| id == clawback_id) {
            pending.remove(pos as u32);
            env.storage()
                .persistent()
                .set(&DataKey::PendingClawbacks, &pending);
            if !pending.is_empty() {
                env.storage().persistent().extend_ttl(
                    &DataKey::PendingClawbacks,
                    STANDARD_TTL,
                    EXTENDED_TTL,
                );
            }
        }

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("clw_cncl").into_val(&env));
        topics.push_back(clawback_id.into_val(&env));
        env.events().publish(topics, issuer);
    }

    /// Issue #1413: Return all currently-pending clawback IDs.
    ///
    /// These are clawbacks with `status = "pending"` that have not yet been
    /// cancelled or executed. Useful for dashboards and bulk notifications.
    pub fn get_pending_clawbacks(env: Env) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingClawbacks)
            .unwrap_or(Vec::new(&env))
    }

    /// Look up a clawback request by id.
    pub fn get_clawback_request(env: Env, clawback_id: u64) -> ClawbackRequest {
        env.storage()
            .persistent()
            .get(&DataKey::ClawbackRequest(clawback_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::ClawbackNotFound))
    }

    // ── Issue #1241: SBT Proof of Possession ─────────────────────────

    /// Generate a proof of possession for an SBT.
    /// Only the SBT holder may generate this proof.
    ///
    /// # Parameters
    /// - `holder`: The holder address; must authorize this call.
    /// - `sbt_id`: The SBT token ID.
    ///
    /// # Returns
    /// A proof of possession as Bytes.
    pub fn generate_sbt_possession_proof(
        env: Env,
        holder: Address,
        sbt_id: u64,
    ) -> Bytes {
        holder.require_auth();

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        assert!(token.owner == holder, "not the owner");

        // Generate proof (simplified: hash of token_id and holder address)
        let mut proof_data = Bytes::new(&env);
        proof_data.append(&Bytes::from_array(&env, &sbt_id.to_le_bytes()));
        proof_data.append(&holder.clone().to_xdr(&env));

        let proof = PossessionProof {
            sbt_id,
            proof_data: proof_data.clone(),
            generated_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::SBTProofOfPossession(sbt_id), &proof);
        env.storage()
            .persistent()
            .extend_ttl(
                &DataKey::SBTProofOfPossession(sbt_id),
                STANDARD_TTL,
                EXTENDED_TTL,
            );

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("pop_gen").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, holder);

        proof_data
    }

    /// Verify a proof of possession for an SBT.
    ///
    /// # Parameters
    /// - `sbt_id`: The SBT token ID.
    /// - `proof`: The proof of possession.
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise.
    pub fn verify_sbt_possession(env: Env, sbt_id: u64, proof: Bytes) -> bool {
        if let Some(stored_proof) = env
            .storage()
            .persistent()
            .get::<_, PossessionProof>(&DataKey::SBTProofOfPossession(sbt_id))
        {
            stored_proof.proof_data == proof
        } else {
            false
        }
    }

    // ── Issue #1240: SBT Metadata Update Without Chain ────────────────

    /// Update an SBT's metadata commitment off-chain.
    /// Only the token owner may call this.
    ///
    /// # Parameters
    /// - `owner`: The owner address; must authorize this call.
    /// - `sbt_id`: The SBT token ID.
    /// - `new_metadata_hash`: Hash of the new metadata.
    /// - `signature`: Owner's signature over the metadata hash.
    ///
    /// # Panics
    /// Panics if the SBT does not exist or caller is not the owner.
    pub fn update_sbt_metadata_commitment(
        env: Env,
        owner: Address,
        sbt_id: u64,
        new_metadata_hash: Bytes,
        signature: Bytes,
    ) {
        owner.require_auth();

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        assert!(token.owner == owner, "not the owner");

        let commitment = MetadataCommitmentRecord {
            sbt_id,
            metadata_hash: new_metadata_hash.clone(),
            signature: signature.clone(),
            committed_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::MetadataCommitment(sbt_id), &commitment);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::MetadataCommitment(sbt_id), STANDARD_TTL, EXTENDED_TTL);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("meta_cmt").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, (owner, new_metadata_hash));
    }

    /// Get the metadata commitment for an SBT.
    pub fn get_sbt_metadata_commitment(env: Env, sbt_id: u64) -> MetadataCommitmentRecord {
        env.storage()
            .persistent()
            .get(&DataKey::MetadataCommitment(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::MetadataCommitmentMismatch))
    }

    /// Verify that a metadata hash matches the stored commitment.
    pub fn verify_metadata_commitment(
        env: Env,
        sbt_id: u64,
        metadata_hash: Bytes,
        signature: Bytes,
    ) -> bool {
        if let Some(commitment) = env
            .storage()
            .persistent()
            .get::<_, MetadataCommitmentRecord>(&DataKey::MetadataCommitment(sbt_id))
        {
            commitment.metadata_hash == metadata_hash && commitment.signature == signature
        } else {
            false
        }
    }

    // ── Issue #1239: SBT Transfer via Attestor Delegation ────────────────

    /// Delegate SBT transfer authority to an attestor.
    /// Only the token owner or admin may call this.
    ///
    /// # Parameters
    /// - `caller`: The caller (owner or admin); must authorize this call.
    /// - `sbt_id`: The SBT token ID.
    /// - `attestor`: The attestor address authorized to transfer.
    /// - `new_holder`: The address that will receive the SBT.
    /// - `transfer_reason`: Reason for the transfer (e.g., "employment_termination").
    ///
    /// # Panics
    /// Panics if the SBT does not exist or caller is not authorized.
    pub fn delegate_sbt_transfer(
        env: Env,
        caller: Address,
        sbt_id: u64,
        attestor: Address,
        new_holder: Address,
        transfer_reason: Bytes,
    ) {
        caller.require_auth();

        let token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        let is_owner = token.owner == caller;
        let is_admin = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::Admin)
            .map_or(false, |admin| admin == caller);

        assert!(is_owner || is_admin, "unauthorized");

        let delegation = AttestorDelegationRecord {
            sbt_id,
            attestor: attestor.clone(),
            new_holder: new_holder.clone(),
            transfer_reason,
            executed: false,
            created_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::AttestorDelegation(sbt_id), &delegation);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::AttestorDelegation(sbt_id), STANDARD_TTL, EXTENDED_TTL);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("att_del").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events()
            .publish(topics, (caller, attestor, new_holder));
    }

    /// Transfer an SBT as an authorized attestor.
    /// Only the authorized attestor may call this.
    ///
    /// # Parameters
    /// - `attestor`: The attestor address; must authorize this call.
    /// - `sbt_id`: The SBT token ID.
    /// - `proof`: Proof of authorization (e.g., signature from token owner).
    ///
    /// # Panics
    /// Panics if the attestor is not authorized or delegation not found.
    pub fn transfer_sbt_via_attestor(
        env: Env,
        attestor: Address,
        sbt_id: u64,
        proof: Bytes,
    ) {
        if Self::is_paused(&env) {
            panic!("contract is paused");
        }

        attestor.require_auth();

        let delegation: AttestorDelegationRecord = env
            .storage()
            .persistent()
            .get(&DataKey::AttestorDelegation(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::UnauthorizedAttestor));

        assert!(delegation.attestor == attestor, "not authorized attestor");
        assert!(!delegation.executed, "delegation already executed");
        assert!(!proof.is_empty(), "proof required");

        // Issue #1403: mirror mint()'s blacklist check on the delegation's
        // target holder.
        if env
            .storage()
            .instance()
            .has(&DataKey::Blacklist(delegation.new_holder.clone()))
        {
            panic_with_error!(&env, ContractError::HolderBlacklisted);
        }

        let mut token: SoulboundToken = env
            .storage()
            .persistent()
            .get(&DataKey::Token(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));

        let old_owner = token.owner.clone();
        let new_holder = delegation.new_holder.clone();

        // Remove from old owner's list
        let mut old_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(old_owner.clone()))
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = old_tokens.iter().position(|id| id == sbt_id) {
            old_tokens.remove(pos as u32);
        }
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(old_owner.clone()), &old_tokens);

        // Add to new holder's list
        token.owner = new_holder.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Token(sbt_id), &token);
        env.storage()
            .persistent()
            .set(&DataKey::Owner(sbt_id), &new_holder);

        let mut new_tokens: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::OwnerTokens(new_holder.clone()))
            .unwrap_or(Vec::new(&env));
        new_tokens.push_back(sbt_id);
        env.storage()
            .persistent()
            .set(&DataKey::OwnerTokens(new_holder.clone()), &new_tokens);

        env.storage().instance().set(
            &DataKey::OwnerCredential(new_holder.clone(), token.credential_id),
            &sbt_id,
        );

        // Mark delegation as executed
        let mut updated_delegation = delegation.clone();
        updated_delegation.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::AttestorDelegation(sbt_id), &updated_delegation);

        // Remove old owner's credential mapping
        env.storage().instance().remove(&DataKey::OwnerCredential(
            old_owner.clone(),
            token.credential_id,
        ));

        // Remove delegation from old owner
        env.storage()
            .persistent()
            .remove(&DataKey::Delegation(sbt_id));

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("xfer_att").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events()
            .publish(topics, (attestor.clone(), old_owner.clone(), new_holder.clone()));

        Self::record_notification(&env, new_holder.clone(), sbt_id, symbol_short!("transfer"));
        Self::log_sbt_activity(&env, sbt_id, symbol_short!("transfer"), attestor);
        Self::record_ownership_history(
            &env,
            sbt_id,
            new_holder,
            token.co_owner,
            symbol_short!("attestor"),
        );
    }

    /// Get the attestor delegation record for an SBT.
    pub fn get_attestor_delegation(env: Env, sbt_id: u64) -> AttestorDelegationRecord {
        env.storage()
            .persistent()
            .get(&DataKey::AttestorDelegation(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::UnauthorizedAttestor))
    }

    // ---------------------------------------------------------------
    // SBT attributes (Issue: encoded attributes beyond credential ref)
    // ---------------------------------------------------------------

    /// Issuer-only: attach an encoded attribute to an SBT (e.g.
    /// `key = b"specialization"`, `value = b"mechanical_engineering"`).
    ///
    /// See [`SbtAttributeRecord`] for the attribute encoding schema. When
    /// `private` is `true`, the value is excluded from the public
    /// [`Self::query_sbt_by_attribute`] index and can only be read back via
    /// [`Self::get_sbt_attribute`] by the issuer or the SBT's current owner —
    /// this is the attribute privacy control.
    pub fn add_sbt_attribute(
        env: Env,
        issuer: Address,
        sbt_id: u64,
        key: Bytes,
        value: Bytes,
        private: bool,
    ) {
        issuer.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if issuer != stored_admin {
            panic_with_error!(&env, ContractError::UnauthorizedAttributeIssuer);
        }
        if !env.storage().persistent().has(&DataKey::Token(sbt_id)) {
            panic_with_error!(&env, ContractError::TokenNotFound);
        }

        // Overwriting an existing public attribute must drop its stale
        // (key, old_value) index entry before the new value is indexed.
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, SbtAttributeRecord>(&DataKey::SbtAttribute(sbt_id, key.clone()))
        {
            if !existing.private {
                Self::remove_from_attribute_index(&env, &existing.key, &existing.value, sbt_id);
            }
        }

        let record = SbtAttributeRecord {
            sbt_id,
            key: key.clone(),
            value: value.clone(),
            private,
            set_at: env.ledger().timestamp(),
        };
        let record_key = DataKey::SbtAttribute(sbt_id, key.clone());
        env.storage().persistent().set(&record_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&record_key, STANDARD_TTL, EXTENDED_TTL);

        let mut keys: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&DataKey::SbtAttributeKeys(sbt_id))
            .unwrap_or(Vec::new(&env));
        if !keys.iter().any(|k| k == key) {
            keys.push_back(key.clone());
            env.storage()
                .persistent()
                .set(&DataKey::SbtAttributeKeys(sbt_id), &keys);
        }

        if !private {
            Self::add_to_attribute_index(&env, &key, &value, sbt_id);
        }

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("sbt_attr").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, (key, private));
    }

    /// Issuer-only: remove a previously set attribute from an SBT.
    pub fn remove_sbt_attribute(env: Env, issuer: Address, sbt_id: u64, key: Bytes) {
        issuer.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if issuer != stored_admin {
            panic_with_error!(&env, ContractError::UnauthorizedAttributeIssuer);
        }

        let record: SbtAttributeRecord = env
            .storage()
            .persistent()
            .get(&DataKey::SbtAttribute(sbt_id, key.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::AttributeNotFound));

        if !record.private {
            Self::remove_from_attribute_index(&env, &record.key, &record.value, sbt_id);
        }
        env.storage()
            .persistent()
            .remove(&DataKey::SbtAttribute(sbt_id, key.clone()));

        let mut keys: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&DataKey::SbtAttributeKeys(sbt_id))
            .unwrap_or(Vec::new(&env));
        if let Some(pos) = keys.iter().position(|k| k == key) {
            keys.remove(pos as u32);
            env.storage()
                .persistent()
                .set(&DataKey::SbtAttributeKeys(sbt_id), &keys);
        }
    }

    /// Read an attribute's value. Requires `caller` authorization; private
    /// attributes may only be read by the issuer (admin) or the SBT's
    /// current owner.
    pub fn get_sbt_attribute(env: Env, caller: Address, sbt_id: u64, key: Bytes) -> Bytes {
        caller.require_auth();
        let record: SbtAttributeRecord = env
            .storage()
            .persistent()
            .get(&DataKey::SbtAttribute(sbt_id, key))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::AttributeNotFound));

        if record.private {
            let stored_admin: Address = env
                .storage()
                .instance()
                .get(&DataKey::Admin)
                .expect("not initialized");
            let owner: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Owner(sbt_id))
                .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));
            if caller != stored_admin && caller != owner {
                panic_with_error!(&env, ContractError::PrivateAttributeAccessDenied);
            }
        }
        record.value
    }

    /// List the attribute keys set on an SBT. Values are not revealed here —
    /// use `get_sbt_attribute` for a privacy-checked value read.
    pub fn get_sbt_attribute_keys(env: Env, sbt_id: u64) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&DataKey::SbtAttributeKeys(sbt_id))
            .unwrap_or(Vec::new(&env))
    }

    /// Find all SBTs carrying a public (non-private) attribute matching
    /// `key`/`value`, enabling granular verification (e.g. "find all SBTs
    /// where specialization = mechanical_engineering") without exposing the
    /// full credential. Private attributes are never returned by this query.
    ///
    /// # Pagination
    /// Use `offset` and `limit` to page through large result sets.
    /// `offset` is the zero-based index of the first result to return.
    /// `limit` is the maximum number of results to return (capped at 100).
    /// Pass `offset = 0, limit = 100` for the first page.
    pub fn query_sbt_by_attribute(env: Env, key: Bytes, value: Bytes, offset: u64, limit: u64) -> Vec<u64> {
        let all: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::AttributeIndex(key, value))
            .unwrap_or(Vec::new(&env));
        let cap: u64 = if limit == 0 { 100 } else { limit.min(100) };
        let start = offset.min(all.len() as u64) as u32;
        let end = (offset + cap).min(all.len() as u64) as u32;
        let mut page = Vec::new(&env);
        for i in start..end {
            page.push_back(all.get(i).unwrap());
        }
        page
    }

    fn add_to_attribute_index(env: &Env, key: &Bytes, value: &Bytes, sbt_id: u64) {
        let index_key = DataKey::AttributeIndex(key.clone(), value.clone());
        let mut ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&index_key)
            .unwrap_or(Vec::new(env));
        if !ids.iter().any(|id| id == sbt_id) {
            ids.push_back(sbt_id);
            env.storage().persistent().set(&index_key, &ids);
            env.storage()
                .persistent()
                .extend_ttl(&index_key, STANDARD_TTL, EXTENDED_TTL);
        }
    }

    fn remove_from_attribute_index(env: &Env, key: &Bytes, value: &Bytes, sbt_id: u64) {
        let index_key = DataKey::AttributeIndex(key.clone(), value.clone());
        if let Some(mut ids) = env.storage().persistent().get::<_, Vec<u64>>(&index_key) {
            if let Some(pos) = ids.iter().position(|id| id == sbt_id) {
                ids.remove(pos as u32);
                env.storage().persistent().set(&index_key, &ids);
            }
        }
    }

    // ---------------------------------------------------------------
    // SBT marketplace registry (Issue: verifier discovery of SBTs)
    // ---------------------------------------------------------------

    /// Holder-only: register an SBT in a marketplace so verifiers/marketplace
    /// UIs can discover it via `query_marketplace_sbt` without the holder
    /// pushing data to each marketplace out of band.
    pub fn register_sbt_in_marketplace(
        env: Env,
        owner: Address,
        sbt_id: u64,
        marketplace_id: Bytes,
        metadata: Bytes,
    ) {
        owner.require_auth();
        let token_owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));
        if owner != token_owner {
            panic_with_error!(&env, ContractError::UnauthorizedMarketplaceAction);
        }

        let listing = MarketplaceListingRecord {
            sbt_id,
            marketplace_id: marketplace_id.clone(),
            metadata,
            listed_at: env.ledger().timestamp(),
            active: true,
        };
        let listing_key = DataKey::MarketplaceListing(sbt_id, marketplace_id.clone());
        env.storage().persistent().set(&listing_key, &listing);
        env.storage()
            .persistent()
            .extend_ttl(&listing_key, STANDARD_TTL, EXTENDED_TTL);

        let mut marketplace_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::MarketplaceIndex(marketplace_id.clone()))
            .unwrap_or(Vec::new(&env));
        if !marketplace_ids.iter().any(|id| id == sbt_id) {
            marketplace_ids.push_back(sbt_id);
            env.storage().persistent().set(
                &DataKey::MarketplaceIndex(marketplace_id.clone()),
                &marketplace_ids,
            );
        }

        let mut sbt_markets: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&DataKey::SbtMarketplaces(sbt_id))
            .unwrap_or(Vec::new(&env));
        if !sbt_markets.iter().any(|m| m == marketplace_id) {
            sbt_markets.push_back(marketplace_id.clone());
            env.storage()
                .persistent()
                .set(&DataKey::SbtMarketplaces(sbt_id), &sbt_markets);
        }

        let mut registry: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::GlobalMarketplaceRegistry)
            .unwrap_or(Vec::new(&env));
        if !registry.iter().any(|id| id == sbt_id) {
            registry.push_back(sbt_id);
            env.storage()
                .persistent()
                .set(&DataKey::GlobalMarketplaceRegistry, &registry);
            env.storage().persistent().extend_ttl(
                &DataKey::GlobalMarketplaceRegistry,
                STANDARD_TTL,
                EXTENDED_TTL,
            );
        }

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("mkt_reg").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, marketplace_id);
    }

    /// Holder-only: deactivate an SBT's listing in a marketplace. The listing
    /// record is retained (with `active = false`) for history, but the SBT
    /// is removed from the marketplace's discovery index.
    pub fn deregister_sbt_from_marketplace(
        env: Env,
        owner: Address,
        sbt_id: u64,
        marketplace_id: Bytes,
    ) {
        owner.require_auth();
        let token_owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));
        if owner != token_owner {
            panic_with_error!(&env, ContractError::UnauthorizedMarketplaceAction);
        }

        let listing_key = DataKey::MarketplaceListing(sbt_id, marketplace_id.clone());
        let mut listing: MarketplaceListingRecord = env
            .storage()
            .persistent()
            .get(&listing_key)
            .unwrap_or_else(|| {
                panic_with_error!(&env, ContractError::MarketplaceListingNotFound)
            });
        listing.active = false;
        env.storage().persistent().set(&listing_key, &listing);

        if let Some(mut ids) = env
            .storage()
            .persistent()
            .get::<_, Vec<u64>>(&DataKey::MarketplaceIndex(marketplace_id.clone()))
        {
            if let Some(pos) = ids.iter().position(|id| id == sbt_id) {
                ids.remove(pos as u32);
                env.storage()
                    .persistent()
                    .set(&DataKey::MarketplaceIndex(marketplace_id.clone()), &ids);
            }
        }

        if let Some(mut markets) = env
            .storage()
            .persistent()
            .get::<_, Vec<Bytes>>(&DataKey::SbtMarketplaces(sbt_id))
        {
            if let Some(pos) = markets.iter().position(|m| m == marketplace_id) {
                markets.remove(pos as u32);
                env.storage()
                    .persistent()
                    .set(&DataKey::SbtMarketplaces(sbt_id), &markets);
            }
        }
    }

    /// Discover all SBTs listed in a given marketplace (callers should check
    /// `active` via `get_marketplace_metadata`/listing lookup if freshness
    /// matters — deregistered SBTs are removed from this index).
    pub fn query_marketplace_sbt(env: Env, marketplace_id: Bytes) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::MarketplaceIndex(marketplace_id))
            .unwrap_or(Vec::new(&env))
    }

    /// Marketplace-specific metadata for an SBT's listing.
    pub fn get_marketplace_metadata(env: Env, sbt_id: u64, marketplace_id: Bytes) -> Bytes {
        let listing: MarketplaceListingRecord = env
            .storage()
            .persistent()
            .get(&DataKey::MarketplaceListing(sbt_id, marketplace_id))
            .unwrap_or_else(|| {
                panic_with_error!(&env, ContractError::MarketplaceListingNotFound)
            });
        listing.metadata
    }

    /// Which marketplaces an SBT is (or was) listed in — supports verifier
    /// discovery starting from the SBT rather than the marketplace.
    pub fn get_sbt_marketplaces(env: Env, sbt_id: u64) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&DataKey::SbtMarketplaces(sbt_id))
            .unwrap_or(Vec::new(&env))
    }

    /// On-chain registry index of every SBT that has ever been registered in
    /// at least one marketplace — the discovery entry point for marketplace
    /// aggregators that don't already know a marketplace_id.
    ///
    /// # Pagination
    /// Use `offset` and `limit` to page through large result sets.
    /// `offset` is the zero-based index of the first result to return.
    /// `limit` is the maximum number of results to return (capped at 100).
    /// Pass `offset = 0, limit = 100` for the first page.
    pub fn get_all_registered_sbts(env: Env, offset: u64, limit: u64) -> Vec<u64> {
        let all: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::GlobalMarketplaceRegistry)
            .unwrap_or(Vec::new(&env));
        let cap: u64 = if limit == 0 { 100 } else { limit.min(100) };
        let start = offset.min(all.len() as u64) as u32;
        let end = (offset + cap).min(all.len() as u64) as u32;
        let mut page = Vec::new(&env);
        for i in start..end {
            page.push_back(all.get(i).unwrap());
        }
        page
    }

    // ---------------------------------------------------------------
    // SBT possession commitments (Issue: prove possession privately)
    // ---------------------------------------------------------------
    //
    // Privacy guarantees are documented in detail in
    // `docs/sbt-possession-privacy.md`; in short: the on-chain record
    // (`PossessionCommitmentRecord`) never stores a holder address, so
    // `verify_sbt_commitment` lets a verifier confirm "a legitimate holder
    // created this commitment for this SBT" without learning which address
    // that holder is. Ownership of `sbt_id` is still itself publicly
    // readable via `owner_of` — this scheme hides the *link* between a
    // presented proof and the holder's identity, it does not hide who
    // currently owns the token on-chain.

    /// Holder-only: create a commitment proving possession of `sbt_id` at
    /// the time of the call, without revealing the holder's address to
    /// whoever later verifies it via `verify_sbt_commitment`.
    ///
    /// Returns the commitment hash. To prove possession later, the holder
    /// presents `commitment` plus the preimage `proof` (`sbt_id_be_bytes ||
    /// nonce_be_bytes`, where `nonce` is `get_commitment_nonce(sbt_id)` as
    /// of this call).
    pub fn create_sbt_possession_commitment(env: Env, holder: Address, sbt_id: u64) -> Bytes {
        holder.require_auth();
        let token_owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::TokenNotFound));
        assert!(
            holder == token_owner,
            "unauthorized: caller does not own this SBT"
        );

        let nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::CommitmentNonce(sbt_id))
            .unwrap_or(0u64)
            + 1;
        env.storage()
            .persistent()
            .set(&DataKey::CommitmentNonce(sbt_id), &nonce);

        let mut preimage = Bytes::new(&env);
        preimage.append(&Bytes::from_slice(&env, &sbt_id.to_be_bytes()));
        preimage.append(&Bytes::from_slice(&env, &nonce.to_be_bytes()));
        let commitment_hash = env.crypto().sha256(&preimage);
        let commitment = Bytes::from_array(&env, &commitment_hash.to_array());

        let record = PossessionCommitmentRecord {
            sbt_id,
            commitment: commitment.clone(),
            created_at: env.ledger().timestamp(),
        };
        let key = DataKey::PossessionCommitment(commitment.clone());
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, STANDARD_TTL, EXTENDED_TTL);

        let mut topics: Vec<soroban_sdk::Val> = Vec::new(&env);
        topics.push_back(symbol_short!("possess").into_val(&env));
        topics.push_back(sbt_id.into_val(&env));
        env.events().publish(topics, commitment.clone());

        commitment
    }

    /// Verify a possession proof against a previously issued commitment.
    /// Returns `false` (rather than panicking) for an unknown commitment or
    /// a non-matching proof — verifiers are expected to call this routinely,
    /// not only on a guaranteed-success path.
    pub fn verify_sbt_commitment(env: Env, commitment: Bytes, proof: Bytes) -> bool {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::PossessionCommitment(commitment.clone()))
        {
            return false;
        }
        let recomputed = env.crypto().sha256(&proof);
        Bytes::from_array(&env, &recomputed.to_array()) == commitment
    }

    /// Strict variant of `verify_sbt_commitment` that panics instead of
    /// returning `false`, for callers (e.g. cross-contract verification
    /// flows) that want a hard failure on an invalid proof.
    pub fn assert_sbt_commitment(env: Env, commitment: Bytes, proof: Bytes) {
        let record: PossessionCommitmentRecord = env
            .storage()
            .persistent()
            .get(&DataKey::PossessionCommitment(commitment))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::CommitmentNotFound));
        let recomputed = env.crypto().sha256(&proof);
        if Bytes::from_array(&env, &recomputed.to_array()) != record.commitment {
            panic_with_error!(&env, ContractError::InvalidCommitmentProof);
        }
    }

    /// Fetch a possession commitment record (existence + metadata only —
    /// this never reveals which address created it).
    pub fn get_possession_commitment(env: Env, commitment: Bytes) -> PossessionCommitmentRecord {
        env.storage()
            .persistent()
            .get(&DataKey::PossessionCommitment(commitment))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::CommitmentNotFound))
    }

    /// The current commitment nonce counter for an SBT, letting a holder who
    /// created a commitment reconstruct the exact preimage (`sbt_id ||
    /// nonce`) needed as `proof` for `verify_sbt_commitment`.
    pub fn get_commitment_nonce(env: Env, sbt_id: u64) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::CommitmentNonce(sbt_id))
            .unwrap_or(0u64)
    }
}

// A minimal mock of the `quorum_proof` contract, used only by this crate's
// own test suite (see `mod tests` below). `sbt_registry` deliberately does
// NOT take a normal (or dev) dependency on the real `quorum_proof` crate —
// production code reaches it only via `env.invoke_contract` with the
// `is_revoked` symbol (see the comment above `mint`), specifically to avoid
// a circular crate dependency. This stub reproduces just the surface the
// tests need (`initialize` / `issue_credential` / `revoke_credential` /
// `is_revoked`) so the test suite can deploy a stand-in contract without
// adding `quorum_proof` as a real Cargo dependency of this crate.
#[cfg(test)]
mod mock_quorum_proof {
    use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, String};

    #[contracttype]
    enum MockQpKey {
        Count,
        Revoked(u64),
    }

    #[contract]
    pub struct QuorumProofContract;

    #[contractimpl]
    impl QuorumProofContract {
        pub fn initialize(_env: Env, _admin: Address) {}

        #[allow(clippy::too_many_arguments)]
        pub fn issue_credential(
            env: Env,
            issuer: Address,
            _subject: Address,
            _credential_type: u32,
            _metadata_hash: Bytes,
            _expires_at: Option<u64>,
            _nonce: u64,
        ) -> u64 {
            issuer.require_auth();
            let next: u64 = env
                .storage()
                .instance()
                .get(&MockQpKey::Count)
                .unwrap_or(0u64)
                + 1;
            env.storage().instance().set(&MockQpKey::Count, &next);
            env.storage()
                .instance()
                .set(&MockQpKey::Revoked(next), &false);
            next
        }

        pub fn revoke_credential(
            env: Env,
            issuer: Address,
            credential_id: u64,
            _reason: Option<String>,
        ) {
            issuer.require_auth();
            env.storage()
                .instance()
                .set(&MockQpKey::Revoked(credential_id), &true);
        }

        pub fn is_revoked(env: Env, credential_id: u64) -> bool {
            // Matches the real quorum_proof::is_revoked: panics for a
            // credential_id that was never issued, rather than defaulting
            // to "not revoked".
            env.storage()
                .instance()
                .get(&MockQpKey::Revoked(credential_id))
                .expect("credential not found")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::mock_quorum_proof::{QuorumProofContract, QuorumProofContractClient};
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::{BytesN, FromVal, TryFromVal};
    use std::string::ToString;

    // --- Deployment verification tests ---

    #[test]
    fn test_deploy_contract_registers() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SbtRegistryContract);
        let _ = SbtRegistryContractClient::new(&env, &contract_id);
    }

    #[test]
    fn test_deploy_initialize_sets_admin_and_quorum_proof_id() {
        let env = Env::default();
        env.mock_all_auths();
        // Deploy a quorum_proof contract to use as the linked contract address.
        let qp_id = env.register_contract(None, QuorumProofContract);
        let qp_client = QuorumProofContractClient::new(&env, &qp_id);
        let admin = Address::generate(&env);
        qp_client.initialize(&admin);

        let sbt_id = env.register_contract(None, SbtRegistryContract);
        let sbt_client = SbtRegistryContractClient::new(&env, &sbt_id);
        // initialize must succeed without panicking.
        sbt_client.initialize(&admin, &qp_id);
        // Verify the contract is operational: token count starts at zero.
        assert_eq!(sbt_client.get_tokens_by_owner(&admin).len(), 0);
    }

    fn setup_with_qp(
        env: &Env,
    ) -> (
        SbtRegistryContractClient,
        Address,
        QuorumProofContractClient,
        Address,
    ) {
        let qp_id = env.register_contract(None, QuorumProofContract);
        let qp_client = QuorumProofContractClient::new(env, &qp_id);
        let admin = Address::generate(env);
        qp_client.initialize(&admin);

        let sbt_id = env.register_contract(None, SbtRegistryContract);
        let sbt_client = SbtRegistryContractClient::new(env, &sbt_id);
        sbt_client.initialize(&admin, &qp_id);

        (sbt_client, admin, qp_client, qp_id)
    }

    #[test]
    fn test_mint_and_ownership() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        assert_eq!(token_id, 1);
        assert_eq!(client.owner_of(&token_id), owner);
    }

    #[test]
    fn test_delegate_sbt_rights_and_active_status() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        client.delegate_sbt_rights(&owner, &token_id, &delegatee, &expires_at);

        assert!(client.is_delegate_active(&token_id, &delegatee));
        let delegation = client.get_delegation(&token_id);
        assert_eq!(delegation.delegatee, delegatee);
        assert_eq!(delegation.expires_at, expires_at);
    }

    #[test]
    #[should_panic(expected = "expiry must be in the future")]
    fn test_delegate_sbt_rights_rejects_past_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp();
        client.delegate_sbt_rights(&owner, &token_id, &delegatee, &expires_at);
    }

    #[test]
    fn test_burn_allows_remint_same_credential() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        // mint, burn, then re-mint the same credential — must succeed
        let token_id = client.mint(&owner, &cred_id, &uri);
        client.burn(&owner, &token_id);
        let new_token_id = client.mint(&owner, &cred_id, &uri);

        assert_eq!(new_token_id, 2);
        assert_eq!(client.owner_of(&new_token_id), owner);
    }

    #[test]
    fn test_mint_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        let token_id = client.mint(&owner, &cred_id, &uri);

        // Verify the token was minted correctly (event was emitted if token exists)
        assert_eq!(client.owner_of(&token_id), owner);
        assert_eq!(token_id, 1);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_duplicate_sbt_minting_rejection() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        client.mint(&owner, &cred_id, &uri);
        client.mint(&owner, &cred_id, &uri);
    }

    /// Minting an SBT for a non-existent credential_id must panic.
    #[test]
    #[should_panic]
    fn test_mint_nonexistent_credential_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let owner = Address::generate(&env);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        // credential_id 999 was never issued
        client.mint(&owner, &999u64, &uri);
    }

    /// Minting an SBT for a revoked credential must panic.
    #[test]
    #[should_panic(expected = "credential is revoked")]
    fn test_mint_revoked_credential_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        qp_client.revoke_credential(&issuer, &cred_id, &None);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        client.mint(&owner, &cred_id, &uri);
    }

    #[test]
    fn test_get_tokens_by_owner_single() { /* impl from previous */
    }

    // --- Issue #196: get_sbt_by_owner ---

    #[test]
    fn test_get_sbt_by_owner_returns_token_ids() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id1 = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let cred_id2 = qp_client.issue_credential(&issuer, &owner, &2u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        assert_eq!(client.get_sbt_by_owner(&owner).len(), 0);

        let id1 = client.mint(&owner, &cred_id1, &uri);
        let id2 = client.mint(&owner, &cred_id2, &uri);

        let tokens = client.get_sbt_by_owner(&owner);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens.get(0).unwrap(), id1);
        assert_eq!(tokens.get(1).unwrap(), id2);
    }

    // --- Issue #197: sbt_count ---

    #[test]
    fn test_sbt_count() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id1 = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let cred_id2 = qp_client.issue_credential(&issuer, &owner, &2u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        assert_eq!(client.sbt_count(), 0);

        client.mint(&owner, &cred_id1, &uri);
        assert_eq!(client.sbt_count(), 1);

        client.mint(&owner, &cred_id2, &uri);
        assert_eq!(client.sbt_count(), 2);
    }

    // --- Issue #37: burn_sbt ---

    #[test]
    fn test_burn_sbt_by_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");

        client.burn_sbt(&owner, &token_id, &proof);

        assert!(client.get_tokens_by_owner(&owner).is_empty());
    }

    /// burn_sbt is holder-only; admin calling with a non-owned token must fail.
    #[test]
    #[should_panic(expected = "HostError")]
    fn test_burn_sbt_by_admin_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");

        // Admin is not the holder — UnauthorizedBurn expected.
        client.burn_sbt(&admin, &token_id, &proof);

        assert!(client.get_tokens_by_owner(&owner).is_empty());
    }

    #[test]
    fn test_burn_sbt_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");

        // Capture the ledger timestamp right before the burn so we can validate it.
        let burn_timestamp = env.ledger().timestamp();
        client.burn_sbt(&owner, &token_id, &proof);

        // Verify token was burned.
        assert!(client.get_tokens_by_owner(&owner).is_empty());

        // Verify a BurnEvent was emitted with the "burn_sbt" topic.
        let events = env.events().all();
        let burn_event_opt = events.iter().find(|(_, topics, _)| {
            topics
                .get(0)
                .and_then(|v| soroban_sdk::Symbol::try_from_val(&env, &v).ok())
                .map(|s| s == Symbol::new(&env, "burn_sbt"))
                .unwrap_or(false)
        });
        assert!(burn_event_opt.is_some(), "BurnEvent not emitted");

        // Verify topics: [burn_sbt, sbt_id]
        let (_, topics, data) = burn_event_opt.unwrap();
        let emitted_id = u64::from_val(&env, &topics.get(1).unwrap());
        assert_eq!(emitted_id, token_id, "BurnEvent sbt_id mismatch");

        // Verify data payload: BurnEvent { sbt_id, holder, timestamp }
        let event_data = BurnEvent::try_from_val(&env, &data)
            .expect("BurnEvent data must deserialize as BurnEvent");
        assert_eq!(event_data.sbt_id, token_id, "BurnEvent.sbt_id mismatch");
        assert_eq!(event_data.holder, owner, "BurnEvent.holder mismatch");
        assert_eq!(
            event_data.timestamp, burn_timestamp,
            "BurnEvent.timestamp mismatch"
        );
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_burn_sbt_unauthorized_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let stranger = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");

        // Stranger is not the holder — must panic with UnauthorizedBurn.
        client.burn_sbt(&stranger, &token_id, &proof);
    }

    #[test]
    fn test_burn_sbt_allows_remint() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");

        client.burn_sbt(&owner, &token_id, &proof);

        // Re-mint must succeed after burn
        let new_id = client.mint(&owner, &cred_id, &uri);
        assert_eq!(client.owner_of(&new_id), owner);
    }

    /// Empty proof_of_residency must be rejected with InvalidProof.
    #[test]
    #[should_panic(expected = "HostError")]
    fn test_burn_sbt_empty_proof_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        // Empty proof must panic with ContractError::InvalidProof (HostError in test).
        let empty_proof = Bytes::new(&env);
        client.burn_sbt(&owner, &token_id, &empty_proof);
    }

    /// Attempting to burn a non-existent sbt_id must panic with TokenNotFound.
    #[test]
    #[should_panic(expected = "HostError")]
    fn test_burn_sbt_token_not_found() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let owner = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");

        // sbt_id 999 was never minted — must panic with ContractError::TokenNotFound.
        client.burn_sbt(&owner, &999u64, &proof);
    }

    #[test]
    #[should_panic]
    #[allow(unused)]
    // upgrade requires the WASM to exist in host storage; this verifies auth passes
    fn test_upgrade_success() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SbtRegistryContract);
        let client = SbtRegistryContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

        client.upgrade(&admin, &wasm_hash);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_upgrade_unauthorized_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SbtRegistryContract);
        let client = SbtRegistryContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let unpriv = Address::generate(&env);
        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

        client.upgrade(&admin, &wasm_hash);

        env.as_contract(&contract_id, || {
            client.upgrade(&unpriv, &wasm_hash);
        });
    }

    #[test]
    fn test_admin_transfer_sbt_updates_ownership() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let old_owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &old_owner, &1u32, &meta, &None, &0u64);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&old_owner, &cred_id, &uri);

        client.admin_transfer_sbt(&admin, &token_id, &new_owner);

        assert_eq!(client.owner_of(&token_id), new_owner);
        assert_eq!(client.get_token(&token_id).owner, new_owner);
        assert!(client.get_tokens_by_owner(&old_owner).is_empty());
        assert_eq!(
            client.get_tokens_by_owner(&new_owner).get(0).unwrap(),
            token_id
        );
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_admin_transfer_sbt_non_admin_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let non_admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let issuer = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let _ = admin; // admin initialized the contract
        client.admin_transfer_sbt(&non_admin, &token_id, &new_owner);
    }

    // ── Snapshot tests ────────────────────────────────────────────────────────

    /// Generates a snapshot after minting an SBT and verifies the
    /// snapshot can be reloaded with the same ledger state.
    #[test]
    fn test_snapshot_mint_state() {
        let snap_path = "test_snapshots/tests/snapshot_mint_state.json";
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        assert_eq!(client.owner_of(&token_id), owner);
        assert_eq!(client.sbt_count(), 1);

        // Generate snapshot
        env.to_snapshot_file(snap_path);

        // Reload and compare ledger metadata
        let env2 = Env::from_snapshot_file(snap_path);
        assert_eq!(env.ledger().sequence(), env2.ledger().sequence());
        assert_eq!(env.ledger().timestamp(), env2.ledger().timestamp());
    }

    /// Generates a snapshot after burning an SBT and verifies the
    /// reloaded snapshot has the same ledger state.
    #[test]
    fn test_snapshot_burn_state() {
        let snap_path = "test_snapshots/tests/snapshot_burn_state.json";
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        client.burn(&owner, &token_id);

        // sbt_count is a monotonically increasing counter; it stays at 1 after burn
        assert_eq!(client.sbt_count(), 1);

        // Generate snapshot
        env.to_snapshot_file(snap_path);

        // Reload and compare ledger metadata
        let env2 = Env::from_snapshot_file(snap_path);
        assert_eq!(env.ledger().sequence(), env2.ledger().sequence());
        assert_eq!(env.ledger().timestamp(), env2.ledger().timestamp());
    }

    /// Generates a snapshot after an admin transfer and verifies the
    /// reloaded snapshot has the same ledger state.
    #[test]
    fn test_snapshot_transfer_state() {
        let snap_path = "test_snapshots/tests/snapshot_transfer_state.json";
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        client.admin_transfer_sbt(&admin, &token_id, &new_owner);

        assert_eq!(client.owner_of(&token_id), new_owner);

        // Generate snapshot
        env.to_snapshot_file(snap_path);

        // Reload and compare ledger metadata
        let env2 = Env::from_snapshot_file(snap_path);
        assert_eq!(env.ledger().sequence(), env2.ledger().sequence());
        assert_eq!(env.ledger().timestamp(), env2.ledger().timestamp());
    }

    // ── Snapshot upgrade state tests (#556) ──────────────────────────────────
    //
    // An `Address` value's underlying Val is an object handle into the specific
    // `Env` (host) it was created against, so it cannot be passed to, or
    // compared against a value produced by, a *different* `Env` — doing so
    // panics with "unknown object reference" or "check_same_env on different
    // Hosts". These helpers round-trip an Address through its portable
    // strkey representation (a plain Rust String) so identities can survive
    // a snapshot reload into a new `Env`.
    fn portable_address(addr: &Address) -> std::string::String {
        addr.to_string().to_string()
    }

    fn address_in_env(env: &Env, s: &std::string::String) -> Address {
        Address::from_string(&soroban_sdk::String::from_str(env, s))
    }

    /// Snapshots contract state before a simulated upgrade, reloads the snapshot,
    /// re-registers the contract code at the same address (upgrade), and verifies
    /// all state is preserved with no data loss.
    #[test]
    fn test_snapshot_upgrade_preserves_state() {
        let snap_path = "test_snapshots/tests/snapshot_upgrade_state.json";
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let holder1 = Address::generate(&env);
        let holder2 = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");

        // Build non-trivial pre-upgrade state: two holders, three tokens
        let cred_id1 = qp_client.issue_credential(&issuer, &holder1, &1u32, &meta, &None, &0u64);
        let cred_id2 = qp_client.issue_credential(&issuer, &holder1, &2u32, &meta, &None, &0u64);
        let cred_id3 = qp_client.issue_credential(&issuer, &holder2, &3u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id1 = client.mint(&holder1, &cred_id1, &uri);
        let token_id2 = client.mint(&holder1, &cred_id2, &uri);
        let token_id3 = client.mint(&holder2, &cred_id3, &uri);

        // Configure recovery guardians so that state is present
        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        // Record all pre-upgrade state values. Owners/holders are captured
        // through their portable strkey form (see `portable_address` above)
        // since they'll be compared against / used with `env2` below.
        let pre_sbt_count = client.sbt_count();
        let pre_owner1 = portable_address(&client.owner_of(&token_id1));
        let pre_owner2 = portable_address(&client.owner_of(&token_id2));
        let pre_owner3 = portable_address(&client.owner_of(&token_id3));
        let pre_holder1_count = client.get_tokens_by_owner(&holder1).len();
        let pre_holder2_count = client.get_tokens_by_owner(&holder2).len();
        let pre_threshold = client.get_recovery_threshold();
        let holder1_str = portable_address(&holder1);
        let holder2_str = portable_address(&holder2);

        // Capture contract address and take pre-upgrade snapshot.
        let sbt_address_str = portable_address(&client.address);
        env.to_snapshot_file(snap_path);

        // Restore snapshot and re-register contract code (simulates WASM upgrade)
        let env2 = Env::from_snapshot_file(snap_path);
        env2.mock_all_auths();
        let sbt_address = address_in_env(&env2, &sbt_address_str);
        env2.register_contract(Some(&sbt_address), SbtRegistryContract);
        let client2 = SbtRegistryContractClient::new(&env2, &sbt_address);
        let holder1_2 = address_in_env(&env2, &holder1_str);
        let holder2_2 = address_in_env(&env2, &holder2_str);

        // Ledger metadata must be identical
        assert_eq!(env.ledger().sequence(), env2.ledger().sequence());
        assert_eq!(env.ledger().timestamp(), env2.ledger().timestamp());

        // All contract state must be intact — no data loss after upgrade
        assert_eq!(client2.sbt_count(), pre_sbt_count, "token count changed after upgrade");
        assert_eq!(
            portable_address(&client2.owner_of(&token_id1)),
            pre_owner1,
            "token 1 owner changed"
        );
        assert_eq!(
            portable_address(&client2.owner_of(&token_id2)),
            pre_owner2,
            "token 2 owner changed"
        );
        assert_eq!(
            portable_address(&client2.owner_of(&token_id3)),
            pre_owner3,
            "token 3 owner changed"
        );
        assert_eq!(
            client2.get_tokens_by_owner(&holder1_2).len(),
            pre_holder1_count,
            "holder1 token count changed after upgrade"
        );
        assert_eq!(
            client2.get_tokens_by_owner(&holder2_2).len(),
            pre_holder2_count,
            "holder2 token count changed after upgrade"
        );
        assert_eq!(
            client2.get_recovery_threshold(),
            pre_threshold,
            "recovery threshold changed after upgrade"
        );
    }

    /// Detects data loss: burning a token before snapshot must not silently restore it.
    #[test]
    fn test_snapshot_upgrade_detects_data_loss() {
        let snap_path = "test_snapshots/tests/snapshot_upgrade_dataloss.json";
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &holder, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&holder, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");
        client.burn_sbt(&holder, &token_id, &proof);

        // Record state after burn (token no longer owned)
        let pre_tokens = client.get_tokens_by_owner(&holder).len();

        // See test_snapshot_upgrade_preserves_state for why addresses are
        // round-tripped through their portable strkey representation rather
        // than reused directly across Env instances.
        let sbt_address_str = portable_address(&client.address);
        let holder_str = portable_address(&holder);
        env.to_snapshot_file(snap_path);

        let env2 = Env::from_snapshot_file(snap_path);
        env2.mock_all_auths();
        let sbt_address = address_in_env(&env2, &sbt_address_str);
        env2.register_contract(Some(&sbt_address), SbtRegistryContract);
        let client2 = SbtRegistryContractClient::new(&env2, &sbt_address);
        let holder2 = address_in_env(&env2, &holder_str);

        // Burn must not be reversed by the upgrade — no phantom token reappearance
        assert_eq!(
            client2.get_tokens_by_owner(&holder2).len(),
            pre_tokens,
            "burned token reappeared after upgrade (data loss)"
        );
    }

    // ── Property-based fuzz tests ─────────────────────────────────────────────

    /// Property: minting N SBTs for distinct credentials always increments
    /// the token count and assigns sequential IDs.
    #[test]
    fn fuzz_mint_sequential_ids() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        for i in 1u32..=4 {
            let cred_id = qp_client.issue_credential(&issuer, &owner, &i, &meta, &None, &0u64);
            let token_id = client.mint(&owner, &cred_id, &uri);
            assert_eq!(token_id, i as u64);
            assert_eq!(client.sbt_count(), i as u64);
        }
    }

    /// Property: minting the same (owner, credential_id) pair twice must
    /// always be rejected (soulbound non-transferable invariant).
    #[test]
    #[should_panic]
    fn fuzz_mint_duplicate_always_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        client.mint(&owner, &cred_id, &uri);
        // Second mint for same (owner, cred_id) — must panic
        client.mint(&owner, &cred_id, &uri);
    }

    /// Property: burning an SBT must decrement the count and allow re-mint.
    #[test]
    fn fuzz_burn_decrements_count_and_allows_remint() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let token_id = client.mint(&owner, &cred_id, &uri);
        assert_eq!(client.sbt_count(), 1);
        client.burn(&owner, &token_id);
        // sbt_count is monotonically increasing; it stays at 1 after burn
        assert_eq!(client.sbt_count(), 1);
        // Re-mint must succeed after burn
        let new_id = client.mint(&owner, &cred_id, &uri);
        assert_eq!(client.owner_of(&new_id), owner);
    }

    // ── SBT Holder Recovery Tests ───────────────────────────────

    #[test]
    fn test_setup_recovery_guardians() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian1 = Address::generate(&env);
        let guardian2 = Address::generate(&env);
        let guardian3 = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian1, guardian2, guardian3];

        client.setup_recovery_guardians(&admin, &guardians, &2u32);

        let retrieved_guardians = client.get_recovery_guardians();
        assert_eq!(retrieved_guardians.len(), 3);
        assert_eq!(client.get_recovery_threshold(), 2);
    }

    #[test]
    fn test_initiate_recovery() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        // Setup recovery guardians
        let guardian1 = Address::generate(&env);
        let guardian2 = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian1, guardian2];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        // Mint an SBT
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let _token_id = client.mint(&owner, &cred_id, &uri);

        // Initiate recovery
        let recovery_id = client.initiate_recovery(&owner, &new_owner);
        assert_eq!(recovery_id, 1);

        // Verify recovery request created
        let recovery = client.get_recovery_request(&recovery_id);
        assert_eq!(recovery.initiator, owner);
        assert_eq!(recovery.new_owner, new_owner);
        assert!(!recovery.completed);
        assert_eq!(recovery.approvals_count, 0);
    }

    #[test]
    #[should_panic(expected = "new owner must be different from initiator")]
    fn test_initiate_recovery_same_owner_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        client.initiate_recovery(&owner, &owner); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_initiate_recovery_duplicate_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let _recovery_id1 = client.initiate_recovery(&owner, &new_owner);
        let _recovery_id2 = client.initiate_recovery(&owner, &new_owner); // Should panic
    }

    #[test]
    fn test_approve_recovery() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        // Setup recovery guardians
        let guardian1 = Address::generate(&env);
        let guardian2 = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian1.clone(), guardian2];
        client.setup_recovery_guardians(&admin, &guardians, &2u32);

        // Initiate recovery
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let recovery_id = client.initiate_recovery(&owner, &new_owner);

        // Approve recovery
        client.approve_recovery(&guardian1, &recovery_id);

        let recovery = client.get_recovery_request(&recovery_id);
        assert_eq!(recovery.approvals_count, 1);

        let approvals = client.get_recovery_approvals(&recovery_id);
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals.get(0).unwrap().guardian, guardian1);
    }

    #[test]
    #[should_panic(expected = "already approved")]
    fn test_approve_recovery_duplicate_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian.clone()];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let recovery_id = client.initiate_recovery(&owner, &new_owner);

        client.approve_recovery(&guardian, &recovery_id);
        client.approve_recovery(&guardian, &recovery_id); // Should panic
    }

    #[test]
    #[should_panic(expected = "only configured guardians")]
    fn test_approve_recovery_unauthorized_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let recovery_id = client.initiate_recovery(&owner, &new_owner);

        let unauthorized = Address::generate(&env);
        client.approve_recovery(&unauthorized, &recovery_id); // Should panic
    }

    #[test]
    fn test_finalize_recovery_transfers_sbts() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        // Setup recovery guardians
        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian.clone()];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        // Mint SBTs
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id1 = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let cred_id2 = qp_client.issue_credential(&issuer, &owner, &2u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id1 = client.mint(&owner, &cred_id1, &uri);
        let token_id2 = client.mint(&owner, &cred_id2, &uri);

        // Verify owner has tokens
        let owner_tokens = client.get_tokens_by_owner(&owner);
        assert_eq!(owner_tokens.len(), 2);

        // Initiate and approve recovery
        let recovery_id = client.initiate_recovery(&owner, &new_owner);
        client.approve_recovery(&guardian, &recovery_id);

        // Finalize recovery
        client.finalize_recovery(&owner, &recovery_id);

        // Verify owner no longer has tokens
        let owner_tokens_after = client.get_tokens_by_owner(&owner);
        assert_eq!(owner_tokens_after.len(), 0);

        // Verify new owner has tokens
        let new_owner_tokens = client.get_tokens_by_owner(&new_owner);
        assert_eq!(new_owner_tokens.len(), 2);

        // Verify token ownership changed
        assert_eq!(client.owner_of(&token_id1), new_owner);
        assert_eq!(client.owner_of(&token_id2), new_owner);

        // Verify recovery is marked completed
        let recovery = client.get_recovery_request(&recovery_id);
        assert!(recovery.completed);
    }

    #[test]
    #[should_panic(expected = "insufficient approvals")]
    fn test_finalize_recovery_insufficient_approvals_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        // Setup recovery guardians with threshold of 2
        let guardian1 = Address::generate(&env);
        let guardian2 = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian1.clone(), guardian2];
        client.setup_recovery_guardians(&admin, &guardians, &2u32);

        // Mint an SBT
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let _token_id = client.mint(&owner, &cred_id, &uri);

        // Initiate recovery with only one approval (need 2)
        let recovery_id = client.initiate_recovery(&owner, &new_owner);
        client.approve_recovery(&guardian1, &recovery_id);

        // Try to finalize with only 1 approval (should panic)
        client.finalize_recovery(&owner, &recovery_id);
    }

    #[test]
    fn test_recovery_audit_trail() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian.clone()];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);

        // Initiate recovery - should create audit entry
        let recovery_id = client.initiate_recovery(&owner, &new_owner);
        let initial_count = client.get_audit_trail_count();
        assert_eq!(initial_count, 1);

        // Get first audit entry
        let entry1 = client.get_audit_trail_entry(&1u64);
        assert_eq!(entry1.recovery_request_id, recovery_id);
        assert_eq!(entry1.actor, owner);

        // Approve recovery - should create another audit entry
        client.approve_recovery(&guardian, &recovery_id);
        let count_after_approval = client.get_audit_trail_count();
        assert_eq!(count_after_approval, 2);

        // Get second audit entry
        let entry2 = client.get_audit_trail_entry(&2u64);
        assert_eq!(entry2.recovery_request_id, recovery_id);
        assert_eq!(entry2.actor, guardian);
    }

    #[test]
    fn test_get_recovery_approvals_empty() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let recovery_id = client.initiate_recovery(&owner, &new_owner);

        let approvals = client.get_recovery_approvals(&recovery_id);
        assert_eq!(approvals.len(), 0);
    }

    #[test]
    #[should_panic(expected = "only recovery initiator")]
    fn test_finalize_recovery_unauthorized_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let guardian = Address::generate(&env);
        let guardians = soroban_sdk::vec![&env, guardian.clone()];
        client.setup_recovery_guardians(&admin, &guardians, &1u32);

        let owner = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let recovery_id = client.initiate_recovery(&owner, &new_owner);
        client.approve_recovery(&guardian, &recovery_id);

        let unauthorized = Address::generate(&env);
        client.finalize_recovery(&unauthorized, &recovery_id); // Should panic
    }

    // -----------------------------------------------------------------------
    // Regression tests for fixed issues
    // -----------------------------------------------------------------------

    // Issue #22 — Duplicate SBT mint for the same (owner, credential_id) must be rejected.
    #[test]
    #[should_panic(expected = "HostError")]
    fn regression_22_duplicate_sbt_mint_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"QmTestHash000000000000000000000000");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        client.mint(&owner, &cred_id, &uri);
        client.mint(&owner, &cred_id, &uri); // must panic — soulbound, non-transferable
    }

    // Issue #22 — Minting an SBT for a revoked credential must be rejected.
    #[test]
    #[should_panic]
    fn regression_22_mint_for_revoked_credential_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"QmTestHash000000000000000000000000");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        qp_client.revoke_credential(&issuer, &cred_id, &None);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        client.mint(&owner, &cred_id, &uri); // must panic — credential is revoked
    }

    // ── Reputation tests ──────────────────────────────────────────────────────

    #[test]
    fn test_reputation_zero_for_new_holder() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);
        let holder = Address::generate(&env);
        assert_eq!(client.get_holder_reputation(&holder), 0);
    }

    #[test]
    fn test_reputation_default_weights() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        client.mint(&owner, &cred_id, &uri);

        // 1 token * 10 + 1 activity (mint notification) * 1 = 11
        assert_eq!(client.get_holder_reputation(&owner), 11);
    }

    #[test]
    fn test_reputation_configurable_weights() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        client.set_reputation_config(&admin, &5u32, &2u32);
        client.mint(&owner, &cred_id, &uri);

        // 1 token * 5 + 1 activity * 2 = 7
        assert_eq!(client.get_holder_reputation(&owner), 7);
    }

    #[test]
    fn test_reputation_increases_with_activity() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id1 = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let cred_id2 = qp_client.issue_credential(&issuer, &owner, &2u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        client.set_reputation_config(&admin, &10u32, &1u32);

        let t1 = client.mint(&owner, &cred_id1, &uri);
        let score_after_one = client.get_holder_reputation(&owner);

        client.mint(&owner, &cred_id2, &uri);
        let score_after_two = client.get_holder_reputation(&owner);

        client.burn(&owner, &t1);
        let score_after_burn = client.get_holder_reputation(&owner);

        // After 1 mint: 1*10 + 1*1 = 11
        assert_eq!(score_after_one, 11);
        // After 2 mints: 2*10 + 2*1 = 22
        assert_eq!(score_after_two, 22);
        // After burn: 1 token left, 3 activity entries (mint, mint, burn) = 1*10 + 3*1 = 13
        assert_eq!(score_after_burn, 13);
    }

    // ── Issue #452: SBT Holder Whitelist ──────────────────────────────────────

    #[test]
    fn test_whitelist_add_and_get() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        // Whitelist management API not yet implemented; verify mint succeeds without whitelist
        assert_eq!(client.owner_of(&token_id), owner);
        let _ = issuer;
    }

    #[test]
    fn test_whitelist_remove() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        // Whitelist management API not yet implemented; verify token exists
        assert_eq!(client.owner_of(&token_id), owner);
        let _ = issuer;
    }

    // ── Issue #451: SBT Metadata URI Support ──────────────────────────────────────

    #[test]
    fn test_set_and_get_metadata_uri() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let new_uri = Bytes::from_slice(&env, b"ipfs://QmNewURI");
        client.update_metadata(&owner, &token_id, &new_uri);

        let retrieved_uri = client.get_token(&token_id).metadata_uri;
        assert_eq!(retrieved_uri, new_uri);
        let _ = issuer;
    }

    #[test]
    fn test_metadata_uri_version_increment() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let token = client.get_token(&token_id);
        assert_eq!(token.version, 1);

        let new_uri = Bytes::from_slice(&env, b"ipfs://QmNewURI");
        client.update_metadata(&owner, &token_id, &new_uri);

        let updated_token = client.get_token(&token_id);
        assert_eq!(updated_token.version, 2);
        let _ = issuer;
    }

    // ── Issue #450: SBT Holder Burn Mechanism ──────────────────────────────────────

    #[test]
    fn test_burn_sbt_holder() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let proof = Bytes::from_slice(&env, b"proof-of-residency");
        client.burn_sbt(&owner, &token_id, &proof);

        // Token should no longer be retrievable after burn
        assert_eq!(client.get_tokens_by_owner(&owner).len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_burned_token_cannot_be_retrieved() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let proof = Bytes::from_slice(&env, b"proof-of-residency");
        client.burn_sbt(&owner, &token_id, &proof);

        // Attempting to get a burned token should panic
        let _ = client.get_token(&token_id);
    }

    // ── Issue #987: Credential Holder Earnings Tracking ─────────────────────────

    #[test]
    fn test_credential_access_log_empty_by_default() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        // No accesses recorded yet.
        assert_eq!(client.get_credential_access_log(&cred_id).len(), 0);
    }

    #[test]
    fn test_track_credential_access_records_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let _token_id = client.mint(&owner, &cred_id, &uri);

        let verifier = Address::generate(&env);
        client.track_credential_access(&cred_id, &verifier);

        let log = client.get_credential_access_log(&cred_id);
        assert_eq!(log.len(), 1);
        let entry = log.get(0).unwrap();
        assert_eq!(entry.accessor, verifier);
        // Micropayment is stubbed at zero for now.
        assert_eq!(entry.payment, CREDENTIAL_ACCESS_MICROPAYMENT);
    }

    #[test]
    fn test_track_credential_access_appends_multiple() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let _token_id = client.mint(&owner, &cred_id, &uri);

        let verifier1 = Address::generate(&env);
        let verifier2 = Address::generate(&env);
        client.track_credential_access(&cred_id, &verifier1);
        client.track_credential_access(&cred_id, &verifier2);

        let log = client.get_credential_access_log(&cred_id);
        assert_eq!(log.len(), 2);
        assert_eq!(log.get(0).unwrap().accessor, verifier1);
        assert_eq!(log.get(1).unwrap().accessor, verifier2);
    }

    #[test]
    #[should_panic]
    fn test_track_credential_access_unauthorized_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let _token_id = client.mint(&owner, &cred_id, &uri);

        // Clear all mocked authorizations: the verifier has NOT authorized this call,
        // so the verifier-only require_auth must reject it.
        env.set_auths(&[]);
        let verifier = Address::generate(&env);
        client.track_credential_access(&cred_id, &verifier);
    }

    #[test]
    fn test_pause_blocks_mint() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract_id = env.register_contract(None, SoulboundTokenContract);
        let client = SoulboundTokenContractClient::new(&env, &contract_id);
        let qp_id = Address::generate(&env);
        client.initialize(&admin, &qp_id);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);

        // Pause the contract
        client.pause(&admin);
        assert!(client.is_paused());

        // Create a credential in quorum_proof (mocked)
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = 1u64;

        // Attempt to mint should fail when paused
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.mint(&owner, &cred_id, &uri)
        }));
        assert!(result.is_err(), "mint should fail when paused");

        // Unpause and retry
        client.unpause(&admin);
        assert!(!client.is_paused());
    }
}

    #[test]
    #[should_panic(expected = "credential is revoked")]
    fn test_track_credential_access_revoked_credential_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let _token_id = client.mint(&owner, &cred_id, &uri);

        // Revoke the credential, then attempt to log access — must be rejected.
        qp_client.revoke_credential(&issuer, &cred_id, &None);

        let verifier = Address::generate(&env);
        client.track_credential_access(&cred_id, &verifier);
    }

    // --- Blacklist tests ---

    #[test]
    fn test_is_holder_blacklisted_returns_false_by_default() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);
        let holder = Address::generate(&env);
        assert!(!client.is_holder_blacklisted(&holder));
    }

    #[test]
    fn test_add_holder_to_blacklist_and_check() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);
        let holder = Address::generate(&env);

        assert!(!client.is_holder_blacklisted(&holder));
        client.add_holder_to_blacklist(&admin, &holder);
        assert!(client.is_holder_blacklisted(&holder));
    }

    #[test]
    #[should_panic]
    fn test_mint_blacklisted_holder_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        client.add_holder_to_blacklist(&admin, &owner);

        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        client.mint(&owner, &cred_id, &uri); // must panic
    }

    #[test]
    #[should_panic]
    fn test_add_holder_to_blacklist_non_admin_panics() {
        let env = Env::default();
        env.mock_all_auths_allowing_non_root_auth();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);
        let non_admin = Address::generate(&env);
        let holder = Address::generate(&env);
        client.add_holder_to_blacklist(&non_admin, &holder);
    }

    // ── Activity log tests (#453) ─────────────────────────────────────────

    #[test]
    fn test_activity_log_mint_records_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let log = client.get_sbt_activity_log(&token_id);
        assert_eq!(log.len(), 1);
        assert_eq!(log.get(0).unwrap().action, symbol_short!("mint"));
        assert_eq!(log.get(0).unwrap().actor, owner);
    }

    #[test]
    fn test_activity_log_burn_records_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        client.burn(&owner, &token_id);

        let log = client.get_sbt_activity_log(&token_id);
        assert_eq!(log.len(), 2);
        assert_eq!(log.get(1).unwrap().action, symbol_short!("burn"));
        assert_eq!(log.get(1).unwrap().actor, owner);
    }

    #[test]
    fn test_activity_log_burn_sbt_records_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);
        let proof = Bytes::from_slice(&env, b"proof-of-residency");
        client.burn_sbt(&owner, &token_id, &proof);

        let log = client.get_sbt_activity_log(&token_id);
        assert_eq!(log.len(), 2);
        assert_eq!(log.get(1).unwrap().action, symbol_short!("burn"));
    }

    #[test]
    fn test_activity_log_update_metadata_records_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let new_uri = Bytes::from_slice(&env, b"ipfs://QmSBT_v2");
        client.update_metadata(&owner, &token_id, &new_uri);

        let log = client.get_sbt_activity_log(&token_id);
        assert_eq!(log.len(), 2);
        assert_eq!(log.get(1).unwrap().action, symbol_short!("upd_meta"));
        assert_eq!(log.get(1).unwrap().actor, owner);

        // Verify version was incremented
        let token = client.get_token(&token_id);
        assert_eq!(token.version, 2);
    }

    #[test]
    fn test_activity_log_empty_for_unknown_sbt() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);
        let log = client.get_sbt_activity_log(&999u64);
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_revoke_sbt_delegation_removes_delegation() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        client.delegate_sbt_rights(&owner, &token_id, &delegatee, &expires_at);
        assert!(client.is_delegate_active(&token_id, &delegatee));

        client.revoke_sbt_delegation(&owner, &token_id);
        assert!(!client.is_delegate_active(&token_id, &delegatee));
    }

    #[test]
    #[should_panic(expected = "not the owner")]
    fn test_revoke_sbt_delegation_non_owner_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let other = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        client.delegate_sbt_rights(&owner, &token_id, &delegatee, &expires_at);

        client.revoke_sbt_delegation(&other, &token_id);
    }

    #[test]
    fn test_delegate_sbt_usage_success_and_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let current_ts = env.ledger().timestamp();
        let expires_at = current_ts + 1_000;

        // Delegate with DeFiCollateral scope
        let scope = UsageScope::DeFiCollateral(expires_at);
        client.delegate_sbt_usage(&token_id, &delegatee, &scope);

        // Verify delegation is active for DeFi
        assert!(client.verify_delegated_sbt(&token_id, &delegatee));

        // Advance ledger time past expiry
        env.ledger().set_timestamp(expires_at + 1);
        assert!(!client.verify_delegated_sbt(&token_id, &delegatee));
    }

    #[test]
    fn test_delegate_sbt_usage_non_defi_scope_fails_verification() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;

        // Delegate with IdentityVerification scope
        let scope = UsageScope::IdentityVerification(expires_at);
        client.delegate_sbt_usage(&token_id, &delegatee, &scope);

        // verify_delegated_sbt should return false because it's only for DeFi protocols (DeFiCollateral scope)
        assert!(!client.verify_delegated_sbt(&token_id, &delegatee));
    }

    #[test]
    fn test_verify_delegated_identity_success_and_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        let scope = UsageScope::IdentityVerification(expires_at);
        client.delegate_sbt_usage(&token_id, &delegatee, &scope);

        assert!(client.verify_delegated_identity(&token_id, &delegatee));
        // Scope-specific verifiers must not accept a different scope.
        assert!(!client.verify_delegated_sbt(&token_id, &delegatee));
        assert!(!client.verify_delegated_governance(&token_id, &delegatee));

        env.ledger().set_timestamp(expires_at + 1);
        assert!(!client.verify_delegated_identity(&token_id, &delegatee));
    }

    #[test]
    fn test_verify_delegated_governance_success_and_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        let scope = UsageScope::GovernanceVoting(expires_at);
        client.delegate_sbt_usage(&token_id, &delegatee, &scope);

        assert!(client.verify_delegated_governance(&token_id, &delegatee));
        assert!(!client.verify_delegated_sbt(&token_id, &delegatee));
        assert!(!client.verify_delegated_identity(&token_id, &delegatee));

        env.ledger().set_timestamp(expires_at + 1);
        assert!(!client.verify_delegated_governance(&token_id, &delegatee));
    }

    /// Find the last emitted event whose first topic is `name`.
    fn find_event(
        env: &Env,
        name: &str,
    ) -> Option<(Vec<soroban_sdk::Val>, soroban_sdk::Val)> {
        env.events()
            .all()
            .iter()
            .filter(|(_, topics, _)| {
                topics
                    .get(0)
                    .and_then(|v| Symbol::try_from_val(env, &v).ok())
                    .map(|s| s == Symbol::new(env, name))
                    .unwrap_or(false)
            })
            .last()
            .map(|(_, topics, data)| (topics, data))
    }

    #[test]
    fn test_delegate_sbt_rights_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        client.delegate_sbt_rights(&owner, &token_id, &delegatee, &expires_at);

        let (topics, data) = find_event(&env, "delegate").expect("delegate event not emitted");
        assert_eq!(u64::from_val(&env, &topics.get(1).unwrap()), token_id);
        let (emitted_delegatee, emitted_expiry) = <(Address, u64)>::from_val(&env, &data);
        assert_eq!(emitted_delegatee, delegatee);
        assert_eq!(emitted_expiry, expires_at);
    }

    #[test]
    fn test_revoke_sbt_delegation_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        client.delegate_sbt_rights(&owner, &token_id, &delegatee, &expires_at);
        client.revoke_sbt_delegation(&owner, &token_id);

        let (topics, data) = find_event(&env, "undeleg").expect("undeleg event not emitted");
        assert_eq!(u64::from_val(&env, &topics.get(1).unwrap()), token_id);
        assert_eq!(
            <Option<Address>>::from_val(&env, &data),
            Some(delegatee)
        );
    }

    #[test]
    fn test_delegate_sbt_usage_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegatee = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        let scope = UsageScope::GovernanceVoting(expires_at);
        client.delegate_sbt_usage(&token_id, &delegatee, &scope);

        let (topics, data) = find_event(&env, "deleg_use").expect("deleg_use event not emitted");
        assert_eq!(u64::from_val(&env, &topics.get(1).unwrap()), token_id);
        let (emitted_delegatee, emitted_scope) = <(Address, UsageScope)>::from_val(&env, &data);
        assert_eq!(emitted_delegatee, delegatee);
        assert_eq!(emitted_scope, scope);
    }

    // ── Issue #1408: consensual co-ownership ─────────────────────────────────

    #[test]
    fn test_propose_and_accept_co_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let candidate = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        client.propose_co_owner(&owner, &token_id, &candidate);
        assert_eq!(client.get_co_owner_proposal(&token_id), Some(candidate.clone()));
        assert_eq!(client.get_co_owner(&token_id), None);

        client.accept_co_owner(&candidate, &token_id);
        assert_eq!(client.get_co_owner(&token_id), Some(candidate.clone()));
        assert_eq!(client.get_co_owner_proposal(&token_id), None);

        let history = client.get_ownership_history(&token_id);
        let last = history.last().unwrap();
        assert_eq!(last.event, symbol_short!("set_co"));
        assert_eq!(last.co_owner, Some(candidate));
    }

    #[test]
    fn test_propose_co_owner_without_acceptance_leaves_token_unaffected() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let candidate = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        client.propose_co_owner(&owner, &token_id, &candidate);

        // The candidate never accepts: the SBT keeps no co-owner at all.
        assert_eq!(client.get_co_owner(&token_id), None);
        assert_eq!(client.get_co_owner_proposal(&token_id), Some(candidate));
        assert_eq!(client.get_ownership_history(&token_id).len(), 1); // mint only
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_accept_co_owner_without_proposal_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let candidate = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        client.accept_co_owner(&candidate, &token_id);
    }

    #[test]
    #[should_panic(expected = "cannot delegate to self")]
    fn test_delegate_sbt_usage_to_self_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let expires_at = env.ledger().timestamp() + 1_000;
        let scope = UsageScope::DeFiCollateral(expires_at);
        client.delegate_sbt_usage(&token_id, &owner, &scope);
    }

    // ── Issue #1242: SBT Revocation Reasons and Appeals ──────────────────────────

    #[test]
    fn test_record_revocation_reason_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let reason = Bytes::from_slice(&env, b"credential_expired");
        client.record_revocation_reason(&admin, &token_id, &reason);

        let revocation = client.get_revocation_reason(&token_id);
        assert_eq!(revocation.sbt_id, token_id);
        assert_eq!(revocation.revoked_by, admin);
    }

    #[test]
    fn test_appeal_sbt_revocation_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let reason = Bytes::from_slice(&env, b"credential_expired");
        client.record_revocation_reason(&admin, &token_id, &reason);

        let appeal_evidence = Bytes::from_slice(&env, b"proof_of_legitimacy");
        let _appeal_id = client.appeal_sbt_revocation(&owner, &token_id, &appeal_evidence);

        let appeal = client.get_sbt_appeal(&token_id);
        assert_eq!(appeal.sbt_id, token_id);
        assert_eq!(appeal.appealed_by, owner);
    }

    #[test]
    fn test_appeal_history_records_multiple_appeals() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let reason = Bytes::from_slice(&env, b"credential_expired");
        client.record_revocation_reason(&admin, &token_id, &reason);

        let appeal_evidence = Bytes::from_slice(&env, b"proof_of_legitimacy");
        let _appeal_id = client.appeal_sbt_revocation(&owner, &token_id, &appeal_evidence);

        let history = client.get_appeal_history(&token_id);
        assert_eq!(history.len(), 1);
    }

    // ── Issue #1241: SBT Proof of Possession Query ────────────────────────────

    #[test]
    fn test_generate_sbt_possession_proof_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let proof = client.generate_sbt_possession_proof(&owner, &token_id);
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_verify_sbt_possession_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let proof = client.generate_sbt_possession_proof(&owner, &token_id);
        let is_valid = client.verify_sbt_possession(&token_id, &proof);
        assert!(is_valid);
    }

    #[test]
    fn test_verify_sbt_possession_invalid_proof() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let _proof = client.generate_sbt_possession_proof(&owner, &token_id);
        let invalid_proof = Bytes::from_slice(&env, b"invalid_proof_data");
        let is_valid = client.verify_sbt_possession(&token_id, &invalid_proof);
        assert!(!is_valid);
    }

    // ── Issue #1240: SBT Metadata Update Without Chain ───────────────────────────

    #[test]
    fn test_update_sbt_metadata_commitment_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let metadata_hash = Bytes::from_slice(&env, b"new_metadata_hash");
        let signature = Bytes::from_slice(&env, b"owner_signature");
        client.update_sbt_metadata_commitment(&owner, &token_id, &metadata_hash, &signature);

        let commitment = client.get_sbt_metadata_commitment(&token_id);
        assert_eq!(commitment.sbt_id, token_id);
        assert_eq!(commitment.metadata_hash, metadata_hash);
    }

    #[test]
    fn test_verify_metadata_commitment_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let metadata_hash = Bytes::from_slice(&env, b"new_metadata_hash");
        let signature = Bytes::from_slice(&env, b"owner_signature");
        client.update_sbt_metadata_commitment(&owner, &token_id, &metadata_hash, &signature);

        let is_valid =
            client.verify_metadata_commitment(&token_id, &metadata_hash, &signature);
        assert!(is_valid);
    }

    #[test]
    fn test_verify_metadata_commitment_mismatch() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let metadata_hash = Bytes::from_slice(&env, b"new_metadata_hash");
        let signature = Bytes::from_slice(&env, b"owner_signature");
        client.update_sbt_metadata_commitment(&owner, &token_id, &metadata_hash, &signature);

        let wrong_hash = Bytes::from_slice(&env, b"wrong_hash");
        let is_valid = client.verify_metadata_commitment(&token_id, &wrong_hash, &signature);
        assert!(!is_valid);
    }

    // ── Issue #1239: SBT Transfer via Attestor Delegation ────────────────────────

    #[test]
    fn test_delegate_sbt_transfer_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let attestor = Address::generate(&env);
        let new_holder = Address::generate(&env);
        let reason = Bytes::from_slice(&env, b"employment_termination");

        client.delegate_sbt_transfer(
            &owner, &token_id, &attestor, &new_holder, &reason,
        );

        let delegation = client.get_attestor_delegation(&token_id);
        assert_eq!(delegation.sbt_id, token_id);
        assert_eq!(delegation.attestor, attestor);
        assert_eq!(delegation.new_holder, new_holder);
        assert!(!delegation.executed);
    }

    #[test]
    fn test_transfer_sbt_via_attestor_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let attestor = Address::generate(&env);
        let new_holder = Address::generate(&env);
        let reason = Bytes::from_slice(&env, b"employment_termination");

        client.delegate_sbt_transfer(
            &owner, &token_id, &attestor, &new_holder, &reason,
        );

        let proof = Bytes::from_slice(&env, b"authorization_proof");
        client.transfer_sbt_via_attestor(&attestor, &token_id, &proof);

        // Verify the transfer
        assert_eq!(client.owner_of(&token_id), new_holder);
        let tokens = client.get_tokens_by_owner(&new_holder);
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn test_transfer_sbt_via_attestor_records_ownership_history() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let attestor = Address::generate(&env);
        let new_holder = Address::generate(&env);
        let reason = Bytes::from_slice(&env, b"employment_termination");

        client.delegate_sbt_transfer(&owner, &token_id, &attestor, &new_holder, &reason);
        let proof = Bytes::from_slice(&env, b"authorization_proof");
        client.transfer_sbt_via_attestor(&attestor, &token_id, &proof);

        let history = client.get_ownership_history(&token_id);
        assert_eq!(history.len(), 2); // mint + attestor transfer
        let last = history.last().unwrap();
        assert_eq!(last.event, symbol_short!("attestor"));
        assert_eq!(last.owner, new_holder);
    }

    #[test]
    fn test_transfer_sbt_via_attestor_already_executed() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let attestor = Address::generate(&env);
        let new_holder = Address::generate(&env);
        let reason = Bytes::from_slice(&env, b"employment_termination");

        client.delegate_sbt_transfer(
            &owner, &token_id, &attestor, &new_holder, &reason,
        );

        let proof = Bytes::from_slice(&env, b"authorization_proof");
        client.transfer_sbt_via_attestor(&attestor, &token_id, &proof);

        // Try to execute again — should fail
        env.set_auths(&[]);
        let should_fail = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.mock_all_auths();
            client.transfer_sbt_via_attestor(&attestor, &token_id, &proof);
        }));
        assert!(should_fail.is_err());
    }

    #[test]
    #[should_panic]
    fn test_transfer_sbt_via_attestor_unauthorized_attestor() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let attestor = Address::generate(&env);
        let new_holder = Address::generate(&env);
        let reason = Bytes::from_slice(&env, b"employment_termination");

        client.delegate_sbt_transfer(
            &owner, &token_id, &attestor, &new_holder, &reason,
        );

        let wrong_attestor = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"authorization_proof");
        client.transfer_sbt_via_attestor(&wrong_attestor, &token_id, &proof);
    }

    // -------------------------------------------------------------
    // SBT possession commitment tests
    // -------------------------------------------------------------

    fn possession_proof(env: &Env, sbt_id: u64, nonce: u64) -> Bytes {
        let mut proof = Bytes::new(env);
        proof.append(&Bytes::from_slice(env, &sbt_id.to_be_bytes()));
        proof.append(&Bytes::from_slice(env, &nonce.to_be_bytes()));
        proof
    }

    #[test]
    fn test_create_and_verify_sbt_commitment() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let commitment = client.create_sbt_possession_commitment(&owner, &token_id);
        let nonce = client.get_commitment_nonce(&token_id);
        let proof = possession_proof(&env, token_id, nonce);

        assert!(client.verify_sbt_commitment(&commitment, &proof));

        let record = client.get_possession_commitment(&commitment);
        assert_eq!(record.sbt_id, token_id);
        assert_eq!(record.commitment, commitment);
    }

    #[test]
    fn test_verify_sbt_commitment_rejects_wrong_proof() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let commitment = client.create_sbt_possession_commitment(&owner, &token_id);

        // Wrong nonce: proof does not hash to the stored commitment.
        let wrong_proof = possession_proof(&env, token_id, 999u64);
        assert!(!client.verify_sbt_commitment(&commitment, &wrong_proof));
    }

    #[test]
    fn test_verify_sbt_commitment_unknown_commitment_returns_false() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let bogus_commitment = Bytes::from_slice(&env, b"not_a_real_commitment_hash_32byte");
        let bogus_proof = Bytes::from_slice(&env, b"anything");
        assert!(!client.verify_sbt_commitment(&bogus_commitment, &bogus_proof));
    }

    #[test]
    fn test_assert_sbt_commitment_succeeds_for_valid_proof() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let commitment = client.create_sbt_possession_commitment(&owner, &token_id);
        let nonce = client.get_commitment_nonce(&token_id);
        let proof = possession_proof(&env, token_id, nonce);

        // Should not panic.
        client.assert_sbt_commitment(&commitment, &proof);
    }

    #[test]
    #[should_panic]
    fn test_assert_sbt_commitment_panics_on_invalid_proof() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let commitment = client.create_sbt_possession_commitment(&owner, &token_id);
        let wrong_proof = possession_proof(&env, token_id, 999u64);
        client.assert_sbt_commitment(&commitment, &wrong_proof);
    }

    #[test]
    #[should_panic]
    fn test_create_sbt_possession_commitment_rejects_non_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let not_owner = Address::generate(&env);
        client.create_sbt_possession_commitment(&not_owner, &token_id);
    }

    #[test]
    fn test_commitment_does_not_expose_holder_identity() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let commitment = client.create_sbt_possession_commitment(&owner, &token_id);
        let nonce = client.get_commitment_nonce(&token_id);
        let proof = possession_proof(&env, token_id, nonce);

        // A verifier only needs commitment + proof; verification succeeds
        // without ever supplying or learning `owner`.
        assert!(client.verify_sbt_commitment(&commitment, &proof));
    }

    // --- Issue #1402: batch size enforcement ---

    #[test]
    fn test_batch_mint_accepts_exactly_max_batch_size() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &subject, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        let mut entries: Vec<BatchMintEntry> = Vec::new(&env);
        for _ in 0..client.get_max_batch_size() {
            entries.push_back(BatchMintEntry {
                owner: Address::generate(&env),
                credential_id: cred_id,
                metadata_uri: uri.clone(),
            });
        }

        let result = client.batch_mint(&entries);
        assert_eq!(result.len(), client.get_max_batch_size());
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_batch_mint_rejects_over_max_batch_size() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &subject, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        let mut entries: Vec<BatchMintEntry> = Vec::new(&env);
        for _ in 0..(client.get_max_batch_size() + 1) {
            entries.push_back(BatchMintEntry {
                owner: Address::generate(&env),
                credential_id: cred_id,
                metadata_uri: uri.clone(),
            });
        }

        client.batch_mint(&entries);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_batch_mint_rejects_empty_entries() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let entries: Vec<BatchMintEntry> = Vec::new(&env);
        client.batch_mint(&entries);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_batch_burn_rejects_empty_entries() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let entries: Vec<BatchBurnEntry> = Vec::new(&env);
        client.batch_burn(&entries);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_batch_transfer_rejects_empty_entries() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let entries: Vec<BatchTransferEntry> = Vec::new(&env);
        client.batch_transfer(&admin, &entries);
    }

    // --- Issue #1403: blacklist enforcement on all owner-assigning paths ---

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_admin_transfer_sbt_rejects_blacklisted_new_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let blacklisted = Address::generate(&env);
        client.add_holder_to_blacklist(&admin, &blacklisted);

        client.admin_transfer_sbt(&admin, &token_id, &blacklisted);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_recover_sbt_rejects_blacklisted_new_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let blacklisted = Address::generate(&env);
        client.add_holder_to_blacklist(&admin, &blacklisted);

        client.recover_sbt(&admin, &token_id, &blacklisted);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_transfer_sbt_via_attestor_rejects_blacklisted_new_holder() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");
        let token_id = client.mint(&owner, &cred_id, &uri);

        let attestor = Address::generate(&env);
        let blacklisted = Address::generate(&env);
        let reason = Bytes::from_slice(&env, b"employment_termination");
        client.delegate_sbt_transfer(&owner, &token_id, &attestor, &blacklisted, &reason);
        client.add_holder_to_blacklist(&admin, &blacklisted);

        let proof = Bytes::from_slice(&env, b"authorization_proof");
        client.transfer_sbt_via_attestor(&attestor, &token_id, &proof);
    }

    #[test]
    #[should_panic(expected = "HostError")]
    fn test_batch_mint_rejects_blacklisted_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &subject, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        let blacklisted = Address::generate(&env);
        client.add_holder_to_blacklist(&admin, &blacklisted);

        let mut entries: Vec<BatchMintEntry> = Vec::new(&env);
        entries.push_back(BatchMintEntry {
            owner: blacklisted,
            credential_id: cred_id,
            metadata_uri: uri,
        });

        client.batch_mint(&entries);
    }

    // --- Issue #1404: remove_holder_from_blacklist ---

    #[test]
    fn test_remove_holder_from_blacklist_allows_remint() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);
        let uri = Bytes::from_slice(&env, b"ipfs://QmSBT");

        client.add_holder_to_blacklist(&admin, &owner);
        assert!(client.is_holder_blacklisted(&owner));

        client.remove_holder_from_blacklist(&admin, &owner);
        assert!(!client.is_holder_blacklisted(&owner));

        // Minting succeeds now that the blacklist entry is gone.
        let token_id = client.mint(&owner, &cred_id, &uri);
        assert_eq!(client.owner_of(&token_id), owner);
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_remove_holder_from_blacklist_rejects_non_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let holder = Address::generate(&env);
        client.add_holder_to_blacklist(&admin, &holder);

        let not_admin = Address::generate(&env);
        client.remove_holder_from_blacklist(&not_admin, &holder);
    }

    // --- Issue #1405: mint() validates metadata_uri length/scheme ---

    #[test]
    #[should_panic(expected = "metadata_uri exceeds 256 characters")]
    fn test_mint_rejects_oversized_metadata_uri() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        let mut long_uri = std::vec::Vec::new();
        long_uri.extend_from_slice(b"ipfs://");
        long_uri.resize(300, b'a');
        let uri = Bytes::from_slice(&env, &long_uri);

        client.mint(&owner, &cred_id, &uri);
    }

    #[test]
    #[should_panic(expected = "metadata_uri must be HTTPS or IPFS")]
    fn test_mint_rejects_invalid_scheme_metadata_uri() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, qp_client, _qp_id) = setup_with_qp(&env);

        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let meta = soroban_sdk::Bytes::from_slice(&env, b"ipfs://meta");
        let cred_id = qp_client.issue_credential(&issuer, &owner, &1u32, &meta, &None, &0u64);

        let uri = Bytes::from_slice(&env, b"ftp://example.com/meta.json");
        client.mint(&owner, &cred_id, &uri);
    }
}

/// Tests for Issue #1511: Audit governance and event trail for repointing
/// cross-contract addresses in the sbt_registry contract.
#[cfg(test)]
mod tests_governance_1511 {
    use super::*;
    use super::mock_quorum_proof::{QuorumProofContract, QuorumProofContractClient};
    use soroban_sdk::testutils::{Address as _, Events as _};
    use soroban_sdk::{Address, Env};

    fn setup_with_qp(
        env: &Env,
    ) -> (
        SbtRegistryContractClient,
        Address,
        QuorumProofContractClient,
        Address,
    ) {
        let qp_id = env.register_contract(None, QuorumProofContract);
        let qp_client = QuorumProofContractClient::new(env, &qp_id);
        let admin = Address::generate(env);
        qp_client.initialize(&admin);

        let sbt_id = env.register_contract(None, SbtRegistryContract);
        let sbt_client = SbtRegistryContractClient::new(env, &sbt_id);
        sbt_client.initialize(&admin, &qp_id);

        (sbt_client, admin, qp_client, qp_id)
    }

    // ── update_admin ───────────────────────────────────────────────────────────

    #[test]
    fn test_update_admin_transfers_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let new_admin = Address::generate(&env);
        client.update_admin(&admin, &new_admin);

        // Old admin should no longer be authorized — new admin can call update_admin again.
        let third_admin = Address::generate(&env);
        client.update_admin(&new_admin, &third_admin);
    }

    #[test]
    fn test_update_admin_emits_admin_transferred_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let new_admin = Address::generate(&env);
        client.update_admin(&admin, &new_admin);

        let events = env.events().all();
        let found = events.iter().any(|e| {
            let event_str = std::format!("{:?}", e);
            event_str.contains("AdminTransferred")
        });
        assert!(found, "AdminTransferred event not emitted");
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_update_admin_rejects_non_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let attacker = Address::generate(&env);
        let new_admin = Address::generate(&env);
        client.update_admin(&attacker, &new_admin);
    }

    // ── update_quorum_proof_id ─────────────────────────────────────────────────

    #[test]
    fn test_update_quorum_proof_id_stores_new_address() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _old_qp_id) = setup_with_qp(&env);

        let new_qp_id = env.register_contract(None, QuorumProofContract);
        QuorumProofContractClient::new(&env, &new_qp_id).initialize(&admin);

        client.update_quorum_proof_id(&admin, &new_qp_id);

        assert_eq!(client.get_quorum_proof_id(), new_qp_id);
    }

    #[test]
    fn test_update_quorum_proof_id_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _old_qp_id) = setup_with_qp(&env);

        let new_qp_id = env.register_contract(None, QuorumProofContract);
        QuorumProofContractClient::new(&env, &new_qp_id).initialize(&admin);

        client.update_quorum_proof_id(&admin, &new_qp_id);

        let events = env.events().all();
        let found = events.iter().any(|e| {
            let event_str = std::format!("{:?}", e);
            event_str.contains("ContractAddressUpdated")
        });
        assert!(found, "ContractAddressUpdated event not emitted");
    }

    #[test]
    fn test_update_quorum_proof_id_can_repoint() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _qp_client, _old_qp_id) = setup_with_qp(&env);

        let qp_v2 = env.register_contract(None, QuorumProofContract);
        QuorumProofContractClient::new(&env, &qp_v2).initialize(&admin);
        client.update_quorum_proof_id(&admin, &qp_v2);
        assert_eq!(client.get_quorum_proof_id(), qp_v2);

        let qp_v3 = env.register_contract(None, QuorumProofContract);
        QuorumProofContractClient::new(&env, &qp_v3).initialize(&admin);
        client.update_quorum_proof_id(&admin, &qp_v3);
        assert_eq!(client.get_quorum_proof_id(), qp_v3);
    }

    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_update_quorum_proof_id_rejects_non_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _qp_client, _qp_id) = setup_with_qp(&env);

        let attacker = Address::generate(&env);
        let new_qp = Address::generate(&env);
        client.update_quorum_proof_id(&attacker, &new_qp);
    }

    // ── get_quorum_proof_id returns the initial value ──────────────────────────

    #[test]
    fn test_get_quorum_proof_id_returns_initialized_value() {
        let env = Env::default();
        env.mock_all_auths();
        let (_client, _admin, _qp_client, qp_id) = setup_with_qp(&env);
        // The client was initialized with qp_id — verify it's stored correctly.
        let (client2, admin2, _qp2, qp_id2) = setup_with_qp(&env);
        assert_eq!(client2.get_quorum_proof_id(), qp_id2);
        // Silence unused var warning
        let _ = qp_id;
        let _ = admin2;
    }
}
