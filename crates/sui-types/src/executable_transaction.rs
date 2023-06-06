// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{committee::EpochId, crypto::AuthorityStrongQuorumSignInfo};

/// CertificateProof is a proof that a transaction certs existed at a given epoch and hence can be executed.
/// There are two types of proofs: one that is proven by inclusion in a checkpoint and one that is proven by quorum signature.
// #[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CertificateProof {
    /// Validity was proven by inclusion in the given checkpoint
    // Checkpoint(EpochId, CheckpointSequenceNumber),
    /// Validity was proven by transaction certificate signature
    Certified(AuthorityStrongQuorumSignInfo),
    /// At least f+1 validators have executed this transaction.
    /// In practice, we will always get 2f+1 (effects cert), but theoretically f+1 is enough to prove
    /// that the transaction is valid.
    QuorumExecuted(EpochId),
    /// Transaction generated by the system, for example Clock update transaction
    SystemTransaction(EpochId),
}

impl CertificateProof {
    pub fn new_from_cert_sig(sig: AuthorityStrongQuorumSignInfo) -> Self {
        Self::Certified(sig)
    }

    pub fn new_system(epoch: EpochId) -> Self {
        Self::SystemTransaction(epoch)
    }

    pub fn epoch(&self) -> EpochId {
        match self {
            // Self::Checkpoint(epoch, _) |
            Self::QuorumExecuted(epoch)
            | Self::SystemTransaction(epoch) => *epoch,
            Self::Certified(sig) => sig.epoch,
        }
    }
}
