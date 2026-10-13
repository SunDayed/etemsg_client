//! MLS adapter — the only module allowed to `use openmls`; every layer above goes through it.
//!
//! Conventions not to "optimize" away: state is persisted by serializing `MemoryStorage` wholesale (`MlsGroup`'s serde is gated behind `migration-import`, so it is unusable in production); Welcome must take the byte path `to_bytes()` -> `tls_deserialize_exact` -> `extract()` (`into_welcome()` is behind `test-utils`); receivers merge Commits with `merge_staged_commit`.

use openmls::prelude::tls_codec::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::OpenMlsRustCrypto;

use super::errors::{MlsError, MlsResult};

/// Throwaway temp file: the upstream `save_to_file`/`load_from_file` only accept `&File`, so it shuttles a `Vec<u8>` and is deleted on drop.
struct TempBlob {
    path: std::path::PathBuf,
}

impl TempBlob {
    fn new() -> MlsResult<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "etemsg_mls_{}_{}.json",
            std::process::id(),
            n
        ));
        Ok(Self { path })
    }

    fn from_bytes(bytes: &[u8]) -> MlsResult<Self> {
        let tf = Self::new()?;
        std::fs::write(tf.path(), bytes)
            .map_err(|e| MlsError::StateCorrupted(format!("failed to write the temporary state file: {e}")))?;
        Ok(tf)
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempBlob {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Group-context extension type carrying the group-name key (MLS private-use range 0xF000-0xFFFF).
/// It must stay constant across epochs: `export_secret` is epoch-bound, so encrypting the group name with it breaks
/// as soon as membership changes. Held in the group context it is set at creation, reaches new members via Welcome, survives later Commits, and stays invisible to the server.
pub const NAME_KEY_EXT_TYPE: u16 = 0xF001;

/// Group-name key length.
pub const NAME_KEY_LEN: usize = 32;

/// How many past-epoch message keys to retain (openmls `PastEpochDeletionPolicy`); must be > 0, set to 3.
/// We sync by "merge Commits, then pull messages", so an offline member jumps to the new epoch before pulling
/// messages sent in the previous one; openmls defaults to `MaxEpochs(0)`, retaining nothing, which would leave those
/// messages undecryptable forever (the leave -> owner-submits-Remove window). Retaining old keys weakens forward secrecy, so keep it small.
pub const MAX_PAST_EPOCHS: usize = 3;

/// The ciphersuite this project fixed on.
/// Chosen because X25519 + AES-128-GCM + SHA-256 + Ed25519 are all pure Rust (no C build chain) and Ed25519 signatures are small.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A local MLS session: provider (with storage) + own signature key + group instance.
/// The caller owns its lifetime; after each state change `service.rs` persists it through [`MlsAdapter::export_state`].
pub struct MlsAdapter {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

/// Everything needed to restore from disk.
/// The signature key's private part is stored separately, not mixed into the MLS state blob.
pub struct RestoreInput<'a> {
    /// Our signature key blob (the serde form returned by [`new_identity`], private+public+scheme).
    pub signer_blob: &'a [u8],
    /// MLS state blob (produced by [`MlsAdapter::export_state`]).
    pub state_blob: &'a [u8],
    /// Group ID to load.
    pub group_id: &'a [u8],
}


/// Build the group-name group-context extensions (both are mandatory): the `Unknown(0xF001)` name payload
/// plus `RequiredCapabilities` declaring the group requires it. Without the latter, openmls derives required
/// capabilities from the proposal's own extensions, leaving an empty set, so committing `GroupContextExtensions` fails with `ExtensionNotInRequiredCapabilities`; group creation needs it too.
fn name_context_extensions(name_ext: &[u8]) -> MlsResult<Extensions<GroupContext>> {
    let required = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Unknown(NAME_KEY_EXT_TYPE)],
        &[],
        &[],
    );
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(required),
        Extension::Unknown(NAME_KEY_EXT_TYPE, UnknownExtension(name_ext.to_vec())),
    ])
    .map_err(|e| MlsError::Internal(format!("failed to build the group context extension: {e:?}")))
}

impl MlsAdapter {
    /// Create a group containing only me (epoch = 0).
    /// The caller generates and persists `signer` separately — openmls offers no production-usable private-key accessor (`private()` is behind `test-utils`).
    pub fn create_group(
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        identity: &[u8],
        group_id: &[u8],
    ) -> MlsResult<Self> {
        Self::create_group_with_name_key(provider, signer, identity, group_id, &random_name_key())
    }

    /// Like [`MlsAdapter::create_group`] but with an explicit group-name extension payload.
    /// Payload = `name key (32B) || AES-GCM(name key, name)` (see [`crate::group::service::build_name_ext`]); putting the ciphertext in the group context lets new members read the current name straight from the Welcome, syncs a rename to the whole group in one Commit, and keeps it invisible to the server.
    pub fn create_group_with_name_key(
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        identity: &[u8],
        group_id: &[u8],
        name_ext: &[u8],
    ) -> MlsResult<Self> {
        signer
            .store(provider.storage())
            .map_err(|e| MlsError::Internal(format!("failed to save the signer: {e:?}")))?;

        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        // Name (key + ciphertext) goes into the group context, so new members get it from the Welcome
        let ctx_ext = name_context_extensions(name_ext)
            .map_err(|e| MlsError::CreateGroup(format!("{e}")))?;

        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            // Retain the last few epochs' keys, or messages sent before a Commit but received after it stay unreadable
            .max_past_epochs(MAX_PAST_EPOCHS)
            // New members need the ratchet tree to join from a Welcome (otherwise it is large and must be shipped out of band)
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(ctx_ext)
            // The creator's own leaf node must declare support for that extension too
            .capabilities(required_capabilities())
            .build();

        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &cfg,
            GroupId::from_slice(group_id),
            credential_with_key,
        )
        .map_err(|e| MlsError::CreateGroup(format!("{e:?}")))?;

        Ok(Self { provider, signer, group })
    }

    /// Restore from disk (loading after a restart).
    pub fn restore(input: RestoreInput<'_>) -> MlsResult<Self> {
        let signer: SignatureKeyPair = serde_json::from_slice(input.signer_blob)
            .map_err(|e| MlsError::StateCorrupted(format!("failed to deserialize the signer: {e}")))?;

        let mut storage = MemoryStorage::default();
        {
            // The upstream API only accepts `&File`, so this goes through a temp file; real persistence is the caller's job.
            let tf = TempBlob::from_bytes(input.state_blob)?;
            let f = std::fs::File::open(tf.path())
                .map_err(|e| MlsError::StateCorrupted(format!("failed to open the temporary state file: {e}")))?;
            storage
                .load_from_file(&f)
                .map_err(|e| MlsError::StateCorrupted(format!("failed to deserialize MLS state: {e}")))?;
        }

        let group = MlsGroup::load(&storage, &GroupId::from_slice(input.group_id))
            .map_err(|e| MlsError::StateCorrupted(format!("{e:?}")))?
            .ok_or_else(|| MlsError::NotInitialized("the group does not exist in the MLS state".into()))?;

        let provider = OpenMlsRustCrypto::default();
        // Inject the restored contents into the provider's own storage (`values` is a pub field); the provider
        // is created inside the adapter, so callers wanting KeyPackage work on the same provider need another entry point.
        for (k, v) in &*storage.values.read().unwrap() {
            provider
                .storage()
                .values
                .write()
                .unwrap()
                .insert(k.clone(), v.clone());
        }
        // The signature key goes into storage too; MLS needs it internally for signing
        signer
            .store(provider.storage())
            .map_err(|e| MlsError::Internal(format!("failed to save the signer: {e:?}")))?;

        Ok(Self { provider, signer, group })
    }

    /// Export the MLS state as an opaque blob (for SQLCipher).
    /// The upstream API only takes `&File`, so this writes a temp file and reads it back; the blob is self-contained (group/epoch/key schedule/psks), so restoring needs only it plus the signature key.
    pub fn export_state(&self) -> MlsResult<Vec<u8>> {
        let tf = TempBlob::new()?;
        {
            let f = std::fs::File::create(tf.path())
                .map_err(|e| MlsError::StateCorrupted(format!("failed to create the temporary state file: {e}")))?;
            self.provider
                .storage()
                .save_to_file(&f)
                .map_err(|e| MlsError::StateCorrupted(format!("failed to serialize MLS state: {e}")))?;
        }
        std::fs::read(tf.path())
            .map_err(|e| MlsError::StateCorrupted(format!("failed to read the temporary state file: {e}")))
    }

    /// Our signature public key.
    /// The private key is not read here: openmls has no production-usable private-key accessor, so its bytes are returned at creation and persisted separately.
    pub fn signer_public(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    pub fn own_identity(&self) -> &[u8] {
        self.signer.public()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }


    /// Add members (given as KeyPackage bytes) to this group.
    /// Returns `(commit_bytes, welcome_bytes)`: the commit goes to existing members, the welcome only to the new ones.
    pub fn add_members(&mut self, key_packages: &[Vec<u8>]) -> MlsResult<(Vec<u8>, Vec<u8>)> {
        // Validating a KeyPackage needs a crypto provider; it is stateless, so a fresh one will do and we need not borrow self.
        let validator = OpenMlsRustCrypto::default();
        let mut kps = Vec::with_capacity(key_packages.len());
        for raw in key_packages {
            let kp = KeyPackageIn::tls_deserialize_exact(raw.as_slice())
                .map_err(|e| MlsError::Membership(format!("failed to deserialize the KeyPackage: {e:?}")))?
                .validate(validator.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| MlsError::Membership(format!("KeyPackage validation failed: {e:?}")))?;
            kps.push(kp);
        }
        let (commit, welcome, _gi) = self
            .group
            .add_members(&self.provider, &self.signer, &kps)
            .map_err(|e| MlsError::Membership(format!("add_members failed: {e:?}")))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Membership(format!("merge failed: {e:?}")))?;

        let commit_bytes = commit
            .to_bytes()
            .map_err(|e| MlsError::Membership(format!("failed to serialize the commit: {e:?}")))?;
        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|e| MlsError::Membership(format!("failed to serialize the welcome: {e:?}")))?;
        Ok((commit_bytes, welcome_bytes))
    }

    /// Join from a Welcome (new-member side).
    /// `signer` must be the key used at request time (its KeyPackage was added to the group), or openmls rejects the signer identity mismatch.
    pub fn join_from_welcome(
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        welcome_bytes: &[u8],
        ratchet_tree: Option<Vec<u8>>,
    ) -> MlsResult<Self> {

        signer
            .store(provider.storage())
            .map_err(|e| MlsError::Internal(format!("failed to save the signer: {e:?}")))?;

        let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| MlsError::JoinGroup(format!("failed to deserialize the Welcome: {e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            other => {
                return Err(MlsError::UnexpectedMessage {
                    expected: "Welcome",
                    actual: format!("{other:?}"),
                })
            }
        };

        // The joiner's JoinConfig defines its own group config (Welcome carries none) and must match the creator's:
        //   * `max_past_epochs`, else messages sent before a Commit but received after it stay unreadable;
        //   * `use_ratchet_tree_extension(true)`, else a later Add performed by this joiner produces a Welcome with no
        //     embedded ratchet tree and the new member fails with `MissingRatchetTree` (the post-succession path; hit in practice).
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build();
        let tree = ratchet_tree.map(|raw| {
            RatchetTreeIn::tls_deserialize_exact(raw.as_slice())
                .map_err(|e| MlsError::JoinGroup(format!("failed to deserialize the ratchet tree: {e:?}")))
        });
        let tree = match tree {
            Some(Ok(t)) => Some(t),
            Some(Err(e)) => return Err(e),
            None => None,
        };

        let group = StagedWelcome::new_from_welcome(
            &provider,
            cfg.join_config(),
            welcome,
            tree,
        )
        .map_err(|e| MlsError::JoinGroup(format!("StagedWelcome failed: {e:?}")))?
        .into_group(&provider)
        .map_err(|e| MlsError::JoinGroup(format!("into_group failed: {e:?}")))?;

        Ok(Self { provider, signer, group })
    }

    /// Raw group-name extension payload (`key (32B) || ciphertext`).
    pub fn name_ext(&self) -> Option<Vec<u8>> {
        self.group
            .extensions()
            .iter()
            .find_map(|e| match e {
                Extension::Unknown(t, UnknownExtension(v)) if t == &NAME_KEY_EXT_TYPE => {
                    Some(v.clone())
                }
                _ => None,
            })
    }

    /// Group-name key (first 32 bytes of the payload).
    pub fn name_key(&self) -> Option<Vec<u8>> {
        self.name_ext()
            .filter(|v| v.len() >= NAME_KEY_LEN)
            .map(|v| v[..NAME_KEY_LEN].to_vec())
    }

    /// Rename: replace the name extension payload with a single GroupContextExtensions commit; returns the Commit bytes.
    /// This side has already `merge_pending_commit`ed, so epoch and name take effect immediately; other members follow on merge, and later joiners read the new name straight from the Welcome's group context.
    pub fn set_name_ext(&mut self, name_ext: &[u8]) -> MlsResult<Vec<u8>> {
        let ext = name_context_extensions(name_ext)
            .map_err(|e| MlsError::Membership(format!("{e}")))?;

        // `CommitBuilder` is mandatory: with `propose_*` + `commit_to_pending_proposals` the proposal enters by
        // reference, other members do not hold it, and merging fails with `InvalidCommit(MissingProposal)`. `CommitBuilder`
        // inlines the proposal by value so the commit is self-contained; the extensions must still carry `RequiredCapabilities` (see `name_context_extensions`).
        let (commit, _welcome, _gi) = self
            .group
            .commit_builder()
            .propose_group_context_extensions(ext)
            .map_err(|e| MlsError::Membership(format!("failed to propose the group rename: {e:?}")))?
            .load_psks(self.provider.storage())
            .map_err(|e| MlsError::Membership(format!("failed to load the PSK: {e:?}")))?
            .build(self.provider.rand(), self.provider.crypto(), &self.signer, |_| true)
            .map_err(|e| MlsError::Membership(format!("failed to commit the group rename: {e:?}")))?
            .stage_commit(&self.provider)
            .map_err(|e| MlsError::Membership(format!("failed to commit the group rename: {e:?}")))?
            .into_contents();
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Membership(format!("merge failed: {e:?}")))?;

        commit
            .to_bytes()
            .map_err(|e| MlsError::Membership(format!("failed to serialize the commit: {e:?}")))
    }


    /// All member identities of the MLS group (credential identity bytes -> user_id).
    /// This is the cryptographically authoritative roster: ratchet-tree leaves win, and the server's `group_members` is not trusted (it only forwards opaque data).
    pub fn member_identities(&self) -> Vec<Vec<u8>> {
        self.group
            .members()
            .filter_map(|m| BasicCredential::try_from(m.credential).ok())
            .map(|c| c.identity().to_vec())
            .collect()
    }

    /// Member (leaf index, credential identity bytes).
    /// Removing a member requires a `LeafNodeIndex`, and leaf indices are not "member numbers" (the tree has blank leaves), so MLS must supply them.
    pub fn member_leaf_indices(&self) -> Vec<(LeafNodeIndex, Vec<u8>)> {
        self.group
            .members()
            .filter_map(|m| {
                BasicCredential::try_from(m.credential)
                    .ok()
                    .map(|c| (m.index, c.identity().to_vec()))
            })
            .collect()
    }

    /// Our own leaf index (used by Remove and similar operations).
    pub fn own_leaf_index(&self) -> LeafNodeIndex {
        self.group.own_leaf_index()
    }


    /// Remove members by leaf index; openmls refuses removing oneself (`CannotRemoveSelf`), so leaving must be
    /// completed by another owner/admin. Returns the commit bytes (a Remove normally yields no Welcome).
    pub fn remove_members(&mut self, indices: &[LeafNodeIndex]) -> MlsResult<Option<Vec<u8>>> {
        let (commit, _welcome, _gi) = self
            .group
            .remove_members(&self.provider, &self.signer, indices)
            .map_err(|e| MlsError::Membership(format!("remove_members failed: {e:?}")))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Membership(format!("merge failed: {e:?}")))?;
        Ok(Some(
            commit
                .to_bytes()
                .map_err(|e| MlsError::Membership(format!("failed to serialize the commit: {e:?}")))?,
        ))
    }

    /// Encrypt one application message (plaintext -> a single ciphertext the whole group can open).
    pub fn seal_text(&mut self, plaintext: &[u8]) -> MlsResult<Vec<u8>> {
        let out = self
            .group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| MlsError::ProcessMessage(format!("create_message failed: {e:?}")))?;
        out.to_bytes()
            .map_err(|e| MlsError::ProcessMessage(format!("failed to serialize the message: {e:?}")))
    }

    /// Process a received MLS message and return its meaning.
    pub fn open(&mut self, payload: &[u8]) -> MlsResult<Opened> {
        let msg = MlsMessageIn::tls_deserialize_exact(payload)
            .map_err(|e| MlsError::ProcessMessage(format!("failed to deserialize the message: {e:?}")))?;
        let proto = msg
            .try_into_protocol_message()
            .map_err(|e| MlsError::ProcessMessage(format!("not a protocol message: {e:?}")))?;
        // Validation failures (tampering, wrong epoch, bad signature) return Err here -- callers must stop and warn
        let processed = self
            .group
            .process_message(&self.provider, proto)
            .map_err(|e| MlsError::ProcessMessage(format!("validation failed: {e:?}")))?;

        let epoch = self.group.epoch().as_u64();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(Opened::Application { plaintext: app.into_bytes(), epoch })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                Ok(Opened::Commit { staged: Box::new(*staged), epoch })
            }
            ProcessedMessageContent::ProposalMessage(_) => Ok(Opened::Proposal { epoch }),
            _ => Ok(Opened::Other { epoch }),
        }
    }

    /// Merge a Commit received from someone else (receiver path).
    /// Must use `merge_staged_commit`; `merge_pending_commit` only applies to commits we produced ourselves.
    pub fn merge_staged(&mut self, staged: StagedCommit) -> MlsResult<u64> {
        self.group
            .merge_staged_commit(&self.provider, staged)
            .map_err(|e| MlsError::Membership(format!("merge_staged_commit failed: {e:?}")))?;
        Ok(self.group.epoch().as_u64())
    }
}

/// Export the provider's whole storage state as a blob.
/// A join request builds a KeyPackage on the provider (init_key and friends land in storage) before any group exists, so
/// [`MlsAdapter::export_state`] does not apply here; without re-importing this storage into the same provider, `join_from_welcome` fails with `NoMatchingKeyPackage`.
pub fn export_provider_state(provider: &OpenMlsRustCrypto) -> MlsResult<Vec<u8>> {
    let tf = TempBlob::new()?;
    {
        let f = std::fs::File::create(tf.path())
            .map_err(|e| MlsError::StateCorrupted(format!("failed to create the temporary file: {e}")))?;
        provider
            .storage()
            .save_to_file(&f)
            .map_err(|e| MlsError::StateCorrupted(format!("failed to serialize provider state: {e}")))?;
    }
    std::fs::read(tf.path())
        .map_err(|e| MlsError::StateCorrupted(format!("failed to read the temporary file: {e}")))
}

/// Restore a provider from a blob (see [`export_provider_state`]).
pub fn import_provider_state(blob: &[u8]) -> MlsResult<OpenMlsRustCrypto> {
    let mut storage = MemoryStorage::default();
    {
        let tf = TempBlob::from_bytes(blob)?;
        let f = std::fs::File::open(tf.path())
            .map_err(|e| MlsError::StateCorrupted(format!("failed to open the temporary file: {e}")))?;
        storage
            .load_from_file(&f)
            .map_err(|e| MlsError::StateCorrupted(format!("failed to deserialize provider state: {e}")))?;
    }
    let provider = OpenMlsRustCrypto::default();
    for (k, v) in &*storage.values.read().unwrap() {
        provider
            .storage()
            .values
            .write()
            .unwrap()
            .insert(k.clone(), v.clone());
    }
    Ok(provider)
}

/// Restore a `SignatureKeyPair` from its blob.
pub fn signer_from_blob(blob: &[u8]) -> MlsResult<SignatureKeyPair> {
    serde_json::from_slice(blob)
        .map_err(|e| MlsError::StateCorrupted(format!("failed to deserialize the signer: {e}")))
}


/// Leaf-node capabilities this project requires.
/// Every leaf node must declare the group-context extension the group uses, or openmls rejects Add with `InsufficientCapabilities`; as the group context carries the name key, all KeyPackages and the creator's leaf declare it.
pub fn required_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(NAME_KEY_EXT_TYPE)]),
        None,
        None,
    )
}

/// Read the credential identity out of KeyPackage bytes (an applicant is not yet a member at approval time, so the nickname is only available here).
/// Returns None when the bytes are invalid or the credential is not Basic.
pub fn key_package_identity(kp_bytes: &[u8]) -> Option<String> {
    let kp_in = KeyPackageIn::tls_deserialize_exact(kp_bytes).ok()?;
    // validate needs a crypto provider; it is stateless, so a throwaway one will do
    let provider = OpenMlsRustCrypto::default();
    let kp = kp_in.validate(provider.crypto(), ProtocolVersion::Mls10).ok()?;
    let cred = BasicCredential::try_from(kp.leaf_node().credential().clone()).ok()?;
    String::from_utf8(cred.identity().to_vec()).ok()
}

/// Generate a random group-name key of length [`NAME_KEY_LEN`].
pub fn random_name_key() -> Vec<u8> {
    use rand::RngCore;
    let mut k = vec![0u8; NAME_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// Create a new "identity": a signature key plus a provider with that key injected; returns `(provider, signer, key blob, public bytes)`.
/// The provider must come back with it, since KeyPackage private material (`init_key` etc.) lives in provider storage and joining with a different provider yields `NoMatchingKeyPackage`.
/// The blob is `SignatureKeyPair`'s serde form (restore with `serde_json::from_slice`), stored because `private()` is behind `test-utils`; never split fields or feed it to `from_raw` as a raw key ("Signing failed").
#[allow(clippy::type_complexity)]
pub fn new_identity() -> MlsResult<(OpenMlsRustCrypto, SignatureKeyPair, Vec<u8>, Vec<u8>)> {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::Internal(format!("failed to generate the signer: {e:?}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::Internal(format!("failed to save the signer: {e:?}")))?;
    let public = signer.to_public_vec();
    let key_blob = serde_json::to_vec(&signer)
        .map_err(|e| MlsError::Internal(format!("failed to serialize the signer: {e}")))?;
    Ok((provider, signer, key_blob, public))
}

/// Build KeyPackage bytes for the given identity; it must be built on the provider that will later join (see [`new_identity`]).
pub fn make_key_package_with(
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    identity: &[u8],
) -> MlsResult<Vec<u8>> {
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(required_capabilities())
        .build(
            CIPHERSUITE,
            provider,
            signer,
            CredentialWithKey {
                credential: BasicCredential::new(identity.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .map_err(|e| MlsError::Internal(format!("failed to generate the KeyPackage: {e:?}")))?;
    bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| MlsError::Internal(format!("failed to serialize the KeyPackage: {e:?}")))
}

/// Result of [`MlsAdapter::open`].
pub enum Opened {
    /// Application message (group chat body); `plaintext` is already decrypted.
    Application { plaintext: Vec<u8>, epoch: u64 },
    /// Membership Commit; the caller must call [`MlsAdapter::merge_staged`] after its own checks.
    Commit { staged: Box<StagedCommit>, epoch: u64 },
    /// Proposal (not yet applied).
    Proposal { epoch: u64 },
    Other { epoch: u64 },
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use openmls::versions::ProtocolVersion;

    /// An "identity": provider (holding KeyPackage private material) + signature key + key blob.
    struct Identity {
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        key_blob: Vec<u8>,
    }

    fn identity() -> Identity {
        let (provider, signer, key_blob, _pub) = new_identity().unwrap();
        Identity { provider, signer, key_blob }
    }

    /// Guards the full adapter API path: create -> KeyPackage -> Add -> join via Welcome -> both-way decrypt -> state blob round-trip.
    #[test]
    fn adapter_full_flow() {
        let a = identity();
        let mut alice =
            MlsAdapter::create_group(a.provider, a.signer, b"alice-identity", b"group-0001")
                .unwrap();
        assert_eq!(alice.epoch(), 0);
        assert!(!alice.export_state().unwrap().is_empty(), "the state blob must not be empty");

        let b = identity();
        let bob_kp =
            make_key_package_with(&b.provider, &b.signer, b"bob-identity").unwrap();

        // Alice adds Bob (Commit to existing members, Welcome to the new one)
        let (commit_bytes, welcome_bytes) = alice.add_members(&[bob_kp]).unwrap();
        assert_eq!(alice.epoch(), 1, "epoch 1 should be reached after Add");
        assert!(!commit_bytes.is_empty() && !welcome_bytes.is_empty());

        let tree_bytes = alice
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .unwrap();
        let mut bob =
            MlsAdapter::join_from_welcome(b.provider, b.signer, &welcome_bytes, Some(tree_bytes))
                .unwrap();
        assert_eq!(bob.epoch(), 1, "Bob should be at the same epoch as Alice");

        // Both directions decrypt (one ciphertext the whole group can open)
        let ct = alice.seal_text(b"hello bob").unwrap();
        match bob.open(&ct).unwrap() {
            Opened::Application { plaintext, epoch } => {
                assert_eq!(plaintext, b"hello bob");
                assert_eq!(epoch, 1);
            }
            _ => panic!("Bob should receive the application message"),
        }
        let ct2 = bob.seal_text(b"hi alice").unwrap();
        match alice.open(&ct2).unwrap() {
            Opened::Application { plaintext, .. } => assert_eq!(plaintext, b"hi alice"),
            _ => panic!("Alice should receive the application message"),
        }

        // State blob round-trip: simulating a restart and restore from SQLCipher
        let blob = alice.export_state().unwrap();
        let mut restored = MlsAdapter::restore(RestoreInput {
            signer_blob: &a.key_blob,
            state_blob: &blob,
            group_id: b"group-0001",
        })
        .expect("should be restored from the blob");
        assert_eq!(restored.epoch(), 1, "the epoch should be preserved after the restore");
        // The restored instance can still send (ratchet works, so this is not a metadata-only restore)
        let ct3 = restored.seal_text(b"after restore").unwrap();
        match bob.open(&ct3).unwrap() {
            Opened::Application { plaintext, .. } => assert_eq!(plaintext, b"after restore"),
            _ => panic!("Bob should decrypt the message sent after the restore"),
        }
    }

    /// Guards that a tampered Commit is rejected; each attempt needs its own receiver state, since reusing one Bob hits `SecretReuseError` once the ratchet is consumed.
    #[test]
    fn adapter_rejects_tampered_commit() {
        /// Build a joined (Alice, Bob) pair; returns Bob's adapter and one valid Commit from Alice.
        fn setup() -> (MlsAdapter, Vec<u8>) {
            let a = identity();
            let mut alice =
                MlsAdapter::create_group(a.provider, a.signer, b"alice", b"g-tamper").unwrap();
            let b = identity();
            let bob_kp = make_key_package_with(&b.provider, &b.signer, b"bob").unwrap();
            let (_c, welcome) = alice.add_members(&[bob_kp]).unwrap();
            let tree = alice.group.export_ratchet_tree().tls_serialize_detached().unwrap();
            let bob =
                MlsAdapter::join_from_welcome(b.provider, b.signer, &welcome, Some(tree)).unwrap();

            let bundle = alice
                .group
                .self_update(&alice.provider, &alice.signer, LeafNodeParameters::default())
                .unwrap();
            let commit = bundle.commit().to_bytes().unwrap();
            alice.group.merge_pending_commit(&alice.provider).unwrap();
            (bob, commit)
        }

        // Tampered -> must Err and leave the epoch unchanged
        let (mut bob1, commit) = setup();
        let epoch_before = bob1.epoch();
        let mut bad = commit.clone();
        let n = bad.len();
        bad[n / 2] ^= 0xff;
        assert!(bob1.open(&bad).is_err(), "a tampered Commit was accepted");
        assert_eq!(bob1.epoch(), epoch_before, "the epoch must not change after rejection");

        // Independent state + untampered -> must be accepted and advance the epoch
        let (mut bob2, commit2) = setup();
        let epoch_before2 = bob2.epoch();
        match bob2.open(&commit2).expect("an untampered Commit should be accepted") {
            Opened::Commit { staged, .. } => {
                let ep = bob2.merge_staged(*staged).unwrap();
                assert!(ep > epoch_before2, "the epoch should advance after the merge");
            }
            _ => panic!("a Commit should be produced"),
        }
    }
}
