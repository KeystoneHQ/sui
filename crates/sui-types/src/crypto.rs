use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use anyhow::{anyhow, Error};
use derive_more::{AsMut, AsRef, From};
use eyre::eyre;
use fastcrypto::bls12381::min_sig::{
    BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
    BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::ed25519::{
    Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519PublicKeyAsBytes, Ed25519Signature,
    Ed25519SignatureAsBytes,
};
use fastcrypto::secp256k1::{
    Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1PublicKeyAsBytes, Secp256k1Signature,
    Secp256k1SignatureAsBytes,
};
use fastcrypto::secp256r1::{
    Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1PublicKeyAsBytes, Secp256r1Signature,
    Secp256r1SignatureAsBytes,
};
pub use fastcrypto::traits::KeyPair as KeypairTraits;
pub use fastcrypto::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, SigningKey, ToFromBytes,
    VerifyingKey,
};
use roaring::RoaringBitmap;
use serde::ser::Serializer;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{serde_as, Bytes};
use alloc::fmt::{Display, Formatter};
use core::hash::Hash;
use alloc::str::FromStr;
use strum::EnumString;

use crate::base_types::SuiAddress;
use crate::committee::EpochId;
use crate::error::{SuiError, SuiResult};
use crate::sui_serde::{Readable, SuiBitmap};
pub use enum_dispatch::enum_dispatch;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction};
pub use fastcrypto::traits::Signer;
use alloc::fmt::Debug;

// Authority Objects
pub type AuthorityKeyPair = BLS12381KeyPair;
pub type AuthorityPublicKey = BLS12381PublicKey;
pub type AuthorityPrivateKey = BLS12381PrivateKey;
pub type AuthoritySignature = BLS12381Signature;
pub type AggregateAuthoritySignature = BLS12381AggregateSignature;
pub type AggregateAuthoritySignatureAsBytes = BLS12381AggregateSignatureAsBytes;

// TODO(joyqvq): prefix these types with Default, DefaultAccountKeyPair etc
pub type AccountKeyPair = Ed25519KeyPair;
pub type AccountPublicKey = Ed25519PublicKey;
pub type AccountPrivateKey = Ed25519PrivateKey;
pub type AccountSignature = Ed25519Signature;

pub type NetworkKeyPair = Ed25519KeyPair;
pub type NetworkPublicKey = Ed25519PublicKey;
pub type NetworkPrivateKey = Ed25519PrivateKey;

pub type DefaultHash = Blake2b256;

pub const DEFAULT_EPOCH_ID: EpochId = 0;

///////////////////////////////////////////////
/// Account Keys
///
/// * The following section defines the keypairs that are used by
/// * accounts to interact with Sui.
/// * Currently we support eddsa and ecdsa on Sui.
///

#[allow(clippy::large_enum_variant)]
#[derive(Debug, From, PartialEq, Eq)]
pub enum SuiKeyPair {
    Ed25519(Ed25519KeyPair),
    Secp256k1(Secp256k1KeyPair),
    Secp256r1(Secp256r1KeyPair),
}

impl SuiKeyPair {
    pub fn public(&self) -> PublicKey {
        match self {
            SuiKeyPair::Ed25519(kp) => PublicKey::Ed25519(kp.public().into()),
            SuiKeyPair::Secp256k1(kp) => PublicKey::Secp256k1(kp.public().into()),
            SuiKeyPair::Secp256r1(kp) => PublicKey::Secp256r1(kp.public().into()),
        }
    }
}

impl Signer<Signature> for SuiKeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            SuiKeyPair::Ed25519(kp) => kp.sign(msg),
            SuiKeyPair::Secp256k1(kp) => kp.sign(msg),
            SuiKeyPair::Secp256r1(kp) => kp.sign(msg),
        }
    }
}

impl FromStr for SuiKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl EncodeDecodeBase64 for SuiKeyPair {
    /// Encode a SuiKeyPair as `flag || privkey` in Base64. Note that the pubkey is not encoded.
    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(self.public().flag());

        match self {
            SuiKeyPair::Ed25519(kp) => {
                bytes.extend_from_slice(kp.as_bytes());
            }
            SuiKeyPair::Secp256k1(kp) => {
                bytes.extend_from_slice(kp.as_bytes());
            }
            SuiKeyPair::Secp256r1(kp) => {
                bytes.extend_from_slice(kp.as_bytes());
            }
        }
        Base64::encode(&bytes[..])
    }

    /// Decode a SuiKeyPair from `flag || privkey` in Base64. The public key is computed directly from the private key bytes.
    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode(value).map_err(|e| eyre!("{}", e.to_string()))?;
        match SignatureScheme::from_flag_byte(bytes.first().ok_or_else(|| eyre!("Invalid length"))?)
        {
            Ok(x) => match x {
                SignatureScheme::ED25519 => Ok(SuiKeyPair::Ed25519(Ed25519KeyPair::from_bytes(
                    bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                )?)),
                SignatureScheme::Secp256k1 => {
                    Ok(SuiKeyPair::Secp256k1(Secp256k1KeyPair::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?))
                }
                SignatureScheme::Secp256r1 => {
                    Ok(SuiKeyPair::Secp256r1(Secp256r1KeyPair::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?))
                }
                _ => Err(eyre!("Invalid flag byte")),
            },
            _ => Err(eyre!("Invalid bytes")),
        }
    }
}

impl Serialize for SuiKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.encode_base64();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SuiKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        <SuiKeyPair as EncodeDecodeBase64>::decode_base64(&s)
            .map_err(|e| Error::custom(e.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(Ed25519PublicKeyAsBytes),
    Secp256k1(Secp256k1PublicKeyAsBytes),
    Secp256r1(Secp256r1PublicKeyAsBytes),
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(pk) => &pk.0,
            PublicKey::Secp256k1(pk) => &pk.0,
            PublicKey::Secp256r1(pk) => &pk.0,
        }
    }
}

impl EncodeDecodeBase64 for PublicKey {
    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[self.flag()]);
        bytes.extend_from_slice(self.as_ref());
        Base64::encode(&bytes[..])
    }

    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode(value).map_err(|e| eyre!("{}", e.to_string()))?;
        match bytes.first() {
            Some(x) => {
                if x == &SignatureScheme::ED25519.flag() {
                    let pk: Ed25519PublicKey = Ed25519PublicKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?;
                    Ok(PublicKey::Ed25519((&pk).into()))
                } else if x == &SignatureScheme::Secp256k1.flag() {
                    let pk = Secp256k1PublicKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?;
                    Ok(PublicKey::Secp256k1((&pk).into()))
                } else if x == &SignatureScheme::Secp256r1.flag() {
                    let pk = Secp256r1PublicKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?;
                    Ok(PublicKey::Secp256r1((&pk).into()))
                } else {
                    Err(eyre!("Invalid flag byte"))
                }
            }
            _ => Err(eyre!("Invalid bytes")),
        }
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.encode_base64();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        <PublicKey as EncodeDecodeBase64>::decode_base64(&s)
            .map_err(|e| Error::custom(e.to_string()))
    }
}

impl PublicKey {
    pub fn flag(&self) -> u8 {
        self.scheme().flag()
    }

    pub fn try_from_bytes(
        curve: SignatureScheme,
        key_bytes: &[u8],
    ) -> Result<PublicKey, eyre::Report> {
        match curve {
            SignatureScheme::ED25519 => Ok(PublicKey::Ed25519(
                (&Ed25519PublicKey::from_bytes(key_bytes)?).into(),
            )),
            SignatureScheme::Secp256k1 => Ok(PublicKey::Secp256k1(
                (&Secp256k1PublicKey::from_bytes(key_bytes)?).into(),
            )),
            SignatureScheme::Secp256r1 => Ok(PublicKey::Secp256r1(
                (&Secp256r1PublicKey::from_bytes(key_bytes)?).into(),
            )),
            _ => Err(eyre!("Unsupported curve")),
        }
    }

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            PublicKey::Ed25519(_) => Ed25519SuiSignature::SCHEME,
            PublicKey::Secp256k1(_) => Secp256k1SuiSignature::SCHEME,
            PublicKey::Secp256r1(_) => Secp256r1SuiSignature::SCHEME,
        }
    }
}

/// Defines the compressed version of the public key that we pass around
/// in Sui
#[serde_as]
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    AsRef,
)]
#[as_ref(forward)]
pub struct AuthorityPublicKeyBytes(
    #[serde_as(as = "Readable<Base64, Bytes>")]
    pub [u8; AuthorityPublicKey::LENGTH],
);

impl AuthorityPublicKeyBytes {
    fn fmt_impl(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        let s = Hex::encode(self.0);
        write!(f, "k#{}", s)?;
        Ok(())
    }

    /// Get a ConciseAuthorityPublicKeyBytesRef. Usage:
    ///
    ///   debug!(name = ?authority.concise());
    ///   format!("{:?}", authority.concise());
    pub fn concise(&self) -> ConciseAuthorityPublicKeyBytesRef<'_> {
        ConciseAuthorityPublicKeyBytesRef(self)
    }

    pub fn into_concise(self) -> ConciseAuthorityPublicKeyBytes {
        ConciseAuthorityPublicKeyBytes(self)
    }
}

/// A wrapper around AuthorityPublicKeyBytes that provides a concise Debug impl.
pub struct ConciseAuthorityPublicKeyBytesRef<'a>(&'a AuthorityPublicKeyBytes);

impl Debug for ConciseAuthorityPublicKeyBytesRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        let s = Hex::encode(self.0 .0.get(0..4).ok_or(alloc::fmt::Error)?);
        write!(f, "k#{}..", s)
    }
}

impl Display for ConciseAuthorityPublicKeyBytesRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        Debug::fmt(self, f)
    }
}

/// A wrapper around AuthorityPublicKeyBytes but owns it.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConciseAuthorityPublicKeyBytes(AuthorityPublicKeyBytes);

impl Debug for ConciseAuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        let s = Hex::encode(self.0 .0.get(0..4).ok_or(alloc::fmt::Error)?);
        write!(f, "k#{}..", s)
    }
}

impl Display for ConciseAuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        Debug::fmt(self, f)
    }
}

impl TryFrom<AuthorityPublicKeyBytes> for AuthorityPublicKey {
    type Error = FastCryptoError;

    fn try_from(bytes: AuthorityPublicKeyBytes) -> Result<AuthorityPublicKey, Self::Error> {
        AuthorityPublicKey::from_bytes(bytes.as_ref())
    }
}

impl From<&AuthorityPublicKey> for AuthorityPublicKeyBytes {
    fn from(pk: &AuthorityPublicKey) -> AuthorityPublicKeyBytes {
        AuthorityPublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

impl Debug for AuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        self.fmt_impl(f)
    }
}

impl Display for AuthorityPublicKeyBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), alloc::fmt::Error> {
        self.fmt_impl(f)
    }
}

impl ToFromBytes for AuthorityPublicKeyBytes {
    fn from_bytes(bytes: &[u8]) -> Result<Self, fastcrypto::error::FastCryptoError> {
        let bytes: [u8; AuthorityPublicKey::LENGTH] = bytes
            .try_into()
            .map_err(|_| fastcrypto::error::FastCryptoError::InvalidInput)?;
        Ok(AuthorityPublicKeyBytes(bytes))
    }
}

impl AuthorityPublicKeyBytes {
    pub const ZERO: Self = Self::new([0u8; AuthorityPublicKey::LENGTH]);

    /// This ensures it's impossible to construct an instance with other than registered lengths
    pub const fn new(bytes: [u8; AuthorityPublicKey::LENGTH]) -> AuthorityPublicKeyBytes
where {
        AuthorityPublicKeyBytes(bytes)
    }
}

impl FromStr for AuthorityPublicKeyBytes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = Hex::decode(s).map_err(|e| anyhow!(e))?;
        Self::from_bytes(&value[..]).map_err(|e| anyhow!(e))
    }
}

impl Default for AuthorityPublicKeyBytes {
    fn default() -> Self {
        Self::ZERO
    }
}

// TODO: C-GETTER
pub fn get_key_pair_from_bytes<KP: KeypairTraits>(bytes: &[u8]) -> SuiResult<(SuiAddress, KP)>
where
    <KP as KeypairTraits>::PubKey: SuiPublicKey,
{
    let priv_length = <KP as KeypairTraits>::PrivKey::LENGTH;
    let pub_key_length = <KP as KeypairTraits>::PubKey::LENGTH;
    if bytes.len() != priv_length + pub_key_length {
        return Err(SuiError::KeyConversionError(format!(
            "Invalid input byte length, expected {}: {}",
            priv_length,
            bytes.len()
        )));
    }
    let sk = <KP as KeypairTraits>::PrivKey::from_bytes(
        bytes
            .get(..priv_length)
            .ok_or(SuiError::InvalidPrivateKey)?,
    )
    .map_err(|_| SuiError::InvalidPrivateKey)?;
    let kp: KP = sk.into();
    Ok((kp.public().into(), kp))
}

//
// Account Signatures
//

// Enums for signature scheme signatures
#[enum_dispatch]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Signature {
    Ed25519SuiSignature,
    Secp256k1SuiSignature,
    Secp256r1SuiSignature,
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref();

        if serializer.is_human_readable() {
            let s = Base64::encode(bytes);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(bytes)
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Base64::decode(&s).map_err(|e| Error::custom(e.to_string()))?
        } else {
            let data: Vec<u8> = Vec::deserialize(deserializer)?;
            data
        };

        Self::from_bytes(&bytes).map_err(|e| Error::custom(e.to_string()))
    }
}

impl Signature {
    /// The messaged passed in is already hashed form.
    pub fn new_hashed(hashed_msg: &[u8], secret: &dyn Signer<Signature>) -> Self {
        Signer::sign(secret, hashed_msg)
    }

    /// Parse [enum CompressedSignature] from trait SuiSignature `flag || sig || pk`.
    /// This is useful for the MultiSig to combine partial signature into a MultiSig public key.
    pub fn to_compressed(&self) -> Result<CompressedSignature, SuiError> {
        let bytes = self.signature_bytes();
        match self.scheme() {
            SignatureScheme::ED25519 => Ok(CompressedSignature::Ed25519(
                (&Ed25519Signature::from_bytes(bytes).map_err(|_| SuiError::InvalidSignature {
                    error: "Cannot parse sig".to_string(),
                })?)
                    .into(),
            )),
            SignatureScheme::Secp256k1 => Ok(CompressedSignature::Secp256k1(
                (&Secp256k1Signature::from_bytes(bytes).map_err(|_| {
                    SuiError::InvalidSignature {
                        error: "Cannot parse sig".to_string(),
                    }
                })?)
                    .into(),
            )),
            SignatureScheme::Secp256r1 => Ok(CompressedSignature::Secp256r1(
                (&Secp256r1Signature::from_bytes(bytes).map_err(|_| {
                    SuiError::InvalidSignature {
                        error: "Cannot parse sig".to_string(),
                    }
                })?)
                    .into(),
            )),
            _ => Err(SuiError::UnsupportedFeatureError {
                error: "Unsupported signature scheme in MultiSig".to_string(),
            }),
        }
    }

    /// Parse [struct PublicKey] from trait SuiSignature `flag || sig || pk`.
    /// This is useful for the MultiSig to construct the bitmap in [struct MultiPublicKey].
    pub fn to_public_key(&self) -> Result<PublicKey, SuiError> {
        let bytes = self.public_key_bytes();
        match self.scheme() {
            SignatureScheme::ED25519 => Ok(PublicKey::Ed25519(
                (&Ed25519PublicKey::from_bytes(bytes)
                    .map_err(|_| SuiError::KeyConversionError("Cannot parse pk".to_string()))?)
                    .into(),
            )),
            SignatureScheme::Secp256k1 => Ok(PublicKey::Secp256k1(
                (&Secp256k1PublicKey::from_bytes(bytes)
                    .map_err(|_| SuiError::KeyConversionError("Cannot parse pk".to_string()))?)
                    .into(),
            )),
            SignatureScheme::Secp256r1 => Ok(PublicKey::Secp256r1(
                (&Secp256r1PublicKey::from_bytes(bytes)
                    .map_err(|_| SuiError::KeyConversionError("Cannot parse pk".to_string()))?)
                    .into(),
            )),
            _ => Err(SuiError::UnsupportedFeatureError {
                error: "Unsupported signature scheme in MultiSig".to_string(),
            }),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ed25519SuiSignature(sig) => sig.as_ref(),
            Signature::Secp256k1SuiSignature(sig) => sig.as_ref(),
            Signature::Secp256r1SuiSignature(sig) => sig.as_ref(),
        }
    }
}
impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Signature::Ed25519SuiSignature(sig) => sig.as_mut(),
            Signature::Secp256k1SuiSignature(sig) => sig.as_mut(),
            Signature::Secp256r1SuiSignature(sig) => sig.as_mut(),
        }
    }
}

impl ToFromBytes for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match bytes.first() {
            Some(x) => {
                if x == &Ed25519SuiSignature::SCHEME.flag() {
                    Ok(<Ed25519SuiSignature as ToFromBytes>::from_bytes(bytes)?.into())
                } else if x == &Secp256k1SuiSignature::SCHEME.flag() {
                    Ok(<Secp256k1SuiSignature as ToFromBytes>::from_bytes(bytes)?.into())
                } else if x == &Secp256r1SuiSignature::SCHEME.flag() {
                    Ok(<Secp256r1SuiSignature as ToFromBytes>::from_bytes(bytes)?.into())
                } else {
                    Err(FastCryptoError::InvalidInput)
                }
            }
            _ => Err(FastCryptoError::InvalidInput),
        }
    }
}

//
// BLS Port
//

impl SuiPublicKey for BLS12381PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::BLS12381;
}

//
// Ed25519 Sui Signature port
//

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, AsRef, AsMut)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct Ed25519SuiSignature(
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1],
);

// Implementation useful for simplify testing when mock signature is needed
impl Default for Ed25519SuiSignature {
    fn default() -> Self {
        Self([0; Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1])
    }
}

impl SuiSignatureInner for Ed25519SuiSignature {
    type Sig = Ed25519Signature;
    type PubKey = Ed25519PublicKey;
    type KeyPair = Ed25519KeyPair;
    const LENGTH: usize = Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1;
}

impl SuiPublicKey for Ed25519PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;
}

impl ToFromBytes for Ed25519SuiSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(FastCryptoError::InputLengthWrong(Self::LENGTH));
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl Signer<Signature> for Ed25519KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        Ed25519SuiSignature::new(self, msg).into()
    }
}

//
// Secp256k1 Sui Signature port
//
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, AsRef, AsMut)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct Secp256k1SuiSignature(
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1],
);

impl SuiSignatureInner for Secp256k1SuiSignature {
    type Sig = Secp256k1Signature;
    type PubKey = Secp256k1PublicKey;
    type KeyPair = Secp256k1KeyPair;
    const LENGTH: usize = Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1;
}

impl SuiPublicKey for Secp256k1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256k1;
}

impl ToFromBytes for Secp256k1SuiSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(FastCryptoError::InputLengthWrong(Self::LENGTH));
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl Signer<Signature> for Secp256k1KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        Secp256k1SuiSignature::new(self, msg).into()
    }
}

//
// Secp256r1 Sui Signature port
//
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, AsRef, AsMut)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct Secp256r1SuiSignature(
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Secp256r1PublicKey::LENGTH + Secp256r1Signature::LENGTH + 1],
);

impl SuiSignatureInner for Secp256r1SuiSignature {
    type Sig = Secp256r1Signature;
    type PubKey = Secp256r1PublicKey;
    type KeyPair = Secp256r1KeyPair;
    const LENGTH: usize = Secp256r1PublicKey::LENGTH + Secp256r1Signature::LENGTH + 1;
}

impl SuiPublicKey for Secp256r1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256r1;
}

impl ToFromBytes for Secp256r1SuiSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(FastCryptoError::InputLengthWrong(Self::LENGTH));
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl Signer<Signature> for Secp256r1KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        Secp256r1SuiSignature::new(self, msg).into()
    }
}

//
// This struct exists due to the limitations of the `enum_dispatch` library.
//
pub trait SuiSignatureInner: Sized + ToFromBytes + PartialEq + Eq + Hash {
    type Sig: Authenticator<PubKey = Self::PubKey>;
    type PubKey: VerifyingKey<Sig = Self::Sig> + SuiPublicKey;
    type KeyPair: KeypairTraits<PubKey = Self::PubKey, Sig = Self::Sig>;

    const LENGTH: usize = Self::Sig::LENGTH + Self::PubKey::LENGTH + 1;
    const SCHEME: SignatureScheme = Self::PubKey::SIGNATURE_SCHEME;

    /// Returns the deserialized signature and deserialized pubkey.
    fn get_verification_inputs(&self) -> SuiResult<(Self::Sig, Self::PubKey)> {
        let pk = Self::PubKey::from_bytes(self.public_key_bytes())
            .map_err(|_| SuiError::KeyConversionError("Invalid public key".to_string()))?;

        // deserialize the signature
        let signature = Self::Sig::from_bytes(self.signature_bytes()).map_err(|_| {
            SuiError::InvalidSignature {
                error: "Fail to get pubkey and sig".to_string(),
            }
        })?;

        Ok((signature, pk))
    }

    fn new(kp: &Self::KeyPair, message: &[u8]) -> Self {
        let sig = Signer::sign(kp, message);

        let mut signature_bytes: Vec<u8> = Vec::new();
        signature_bytes
            .extend_from_slice(&[<Self::PubKey as SuiPublicKey>::SIGNATURE_SCHEME.flag()]);
        signature_bytes.extend_from_slice(sig.as_ref());
        signature_bytes.extend_from_slice(kp.public().as_ref());
        Self::from_bytes(&signature_bytes[..])
            .expect("Serialized signature did not have expected size")
    }
}

pub trait SuiPublicKey: VerifyingKey {
    const SIGNATURE_SCHEME: SignatureScheme;
}

#[enum_dispatch(Signature)]
pub trait SuiSignature: Sized + ToFromBytes {
    fn signature_bytes(&self) -> &[u8];
    fn public_key_bytes(&self) -> &[u8];
    fn scheme(&self) -> SignatureScheme;
}

impl<S: SuiSignatureInner + Sized> SuiSignature for S {
    fn signature_bytes(&self) -> &[u8] {
        // Access array slice is safe because the array bytes is initialized as
        // flag || signature || pubkey with its defined length.
        &self.as_ref()[1..1 + S::Sig::LENGTH]
    }

    fn public_key_bytes(&self) -> &[u8] {
        // Access array slice is safe because the array bytes is initialized as
        // flag || signature || pubkey with its defined length.
        &self.as_ref()[S::Sig::LENGTH + 1..]
    }

    fn scheme(&self) -> SignatureScheme {
        S::PubKey::SIGNATURE_SCHEME
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EmptySignInfo {}

/// Represents at least a quorum (could be more) of authority signatures.
/// STRONG_THRESHOLD indicates whether to use the quorum threshold for quorum check.
/// When STRONG_THRESHOLD is true, the quorum is valid when the total stake is
/// at least the quorum threshold (2f+1) of the committee; when STRONG_THRESHOLD is false,
/// the quorum is valid when the total stake is at least the validity threshold (f+1) of
/// the committee.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityQuorumSignInfo<const STRONG_THRESHOLD: bool> {
    pub epoch: EpochId,
    pub signature: AggregateAuthoritySignature,
    #[serde_as(as = "SuiBitmap")]
    pub signers_map: RoaringBitmap,
}

pub type AuthorityStrongQuorumSignInfo = AuthorityQuorumSignInfo<true>;

// Variant of [AuthorityStrongQuorumSignInfo] but with a serialized signature, to be used in
// external APIs.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuiAuthorityStrongQuorumSignInfo {
    pub epoch: EpochId,
    pub signature: AggregateAuthoritySignatureAsBytes,
    #[serde_as(as = "SuiBitmap")]
    pub signers_map: RoaringBitmap,
}

impl From<&AuthorityStrongQuorumSignInfo> for SuiAuthorityStrongQuorumSignInfo {
    fn from(info: &AuthorityStrongQuorumSignInfo) -> Self {
        Self {
            epoch: info.epoch,
            signature: (&info.signature).into(),
            signers_map: info.signers_map.clone(),
        }
    }
}

impl TryFrom<&SuiAuthorityStrongQuorumSignInfo> for AuthorityStrongQuorumSignInfo {
    type Error = FastCryptoError;

    fn try_from(info: &SuiAuthorityStrongQuorumSignInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            epoch: info.epoch,
            signature: (&info.signature).try_into()?,
            signers_map: info.signers_map.clone(),
        })
    }
}

// Note: if you meet an error due to this line it may be because you need an Eq implementation for `CertifiedTransaction`,
// or one of the structs that include it, i.e. `ConfirmationTransaction`, `TransactionInfoResponse` or `ObjectInfoResponse`.
//
// Please note that any such implementation must be agnostic to the exact set of signatures in the certificate, as
// clients are allowed to equivocate on the exact nature of valid certificates they send to the system. This assertion
// is a simple tool to make sure certificates are accounted for correctly - should you remove it, you're on your own to
// maintain the invariant that valid certificates with distinct signatures are equivalent, but yet-unchecked
// certificates that differ on signers aren't.
//
// see also https://github.com/MystenLabs/sui/issues/266
static_assertions::assert_not_impl_any!(AuthorityStrongQuorumSignInfo: Hash, Eq, PartialEq);

impl<const S: bool> Display for AuthorityQuorumSignInfo<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> alloc::fmt::Result {
        writeln!(
            f,
            "{} {{ epoch: {:?}, signers_map: {:?} }}",
            if S {
                "AuthorityStrongQuorumSignInfo"
            } else {
                "AuthorityWeakQuorumSignInfo"
            },
            self.epoch,
            self.signers_map,
        )?;
        Ok(())
    }
}

mod private {
    pub trait SealedAuthoritySignInfoTrait {}
    impl SealedAuthoritySignInfoTrait for super::EmptySignInfo {}
    impl<const S: bool> SealedAuthoritySignInfoTrait for super::AuthorityQuorumSignInfo<S> {}
}

/// Something that we know how to hash and sign.
pub trait Signable<W> {
    fn write(&self, writer: &mut W);
}

pub trait SignableBytes
where
    Self: Sized,
{
    fn from_signable_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

/// Activate the blanket implementation of `Signable` based on serde and BCS.
/// * We use `serde_name` to extract a seed from the name of structs and enums.
/// * We use `BCS` to generate canonical bytes suitable for hashing and signing.
///
/// # Safety
/// We protect the access to this marker trait through a "sealed trait" pattern:
/// impls must be add added here (nowehre else) which lets us note those impls
/// MUST be on types that comply with the `serde_name` machinery
/// for the below implementations not to panic. One way to check they work is to write
/// a unit test for serialization to / deserialization from signable bytes.
mod bcs_signable {

    pub trait BcsSignable: serde::Serialize + serde::de::DeserializeOwned {}

    impl BcsSignable for crate::transaction::TransactionData {}
    impl BcsSignable for crate::object::Object {}

}

impl<T, W> Signable<W> for T
where
    T: bcs_signable::BcsSignable,
    W: core2::io::Write,
{
    fn write(&self, writer: &mut W) {
        let name = serde_name::trace_name::<Self>().expect("Self must be a struct or an enum");
        // Note: This assumes that names never contain the separator `::`.
        write!(writer, "{}::", name).expect("Hasher should not fail");
        // bcs::serialize_into(writer, &self).expect("Message serialization should not fail");
    }
}

impl<W> Signable<W> for EpochId
where
    W: core2::io::Write,
{
    fn write(&self, _writer: &mut W) {
        // bcs::serialize_into(writer, &self).expect("Message serialization should not fail");
    }
}

impl<T> SignableBytes for T
where
    T: bcs_signable::BcsSignable,
{
    fn from_signable_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Remove name tag before deserialization using BCS
        let name = serde_name::trace_name::<Self>().expect("Self should be a struct or an enum");
        let name_byte_len = format!("{}::", name).bytes().len();
        Ok(bcs::from_bytes(bytes.get(name_byte_len..).ok_or_else(
            || anyhow!("Failed to deserialize to {name}."),
        )?)?)
    }
}

fn hash<S: Signable<H>, H: HashFunction<DIGEST_SIZE>, const DIGEST_SIZE: usize>(
    signable: &S,
) -> [u8; DIGEST_SIZE] {
    let mut digest = H::default();
    signable.write(&mut digest);
    let hash = digest.finalize();
    hash.into()
}

pub fn default_hash<S: Signable<DefaultHash>>(signable: &S) -> [u8; 32] {
    hash::<S, DefaultHash, 32>(signable)
}

#[derive(Deserialize, Serialize, Debug, EnumString, strum_macros::Display)]
#[strum(serialize_all = "lowercase")]
pub enum SignatureScheme {
    ED25519,
    Secp256k1,
    Secp256r1,
    BLS12381, // This is currently not supported for user Sui Address.
    MultiSig,
    ZkLoginAuthenticator,
}

impl SignatureScheme {
    pub fn flag(&self) -> u8 {
        match self {
            SignatureScheme::ED25519 => 0x00,
            SignatureScheme::Secp256k1 => 0x01,
            SignatureScheme::Secp256r1 => 0x02,
            SignatureScheme::MultiSig => 0x03,
            SignatureScheme::BLS12381 => 0x04, // This is currently not supported for user Sui Address.
            SignatureScheme::ZkLoginAuthenticator => 0x05,
        }
    }

    pub fn from_flag(flag: &str) -> Result<SignatureScheme, SuiError> {
        let byte_int = flag
            .parse::<u8>()
            .map_err(|_| SuiError::KeyConversionError("Invalid key scheme".to_string()))?;
        Self::from_flag_byte(&byte_int)
    }

    pub fn from_flag_byte(byte_int: &u8) -> Result<SignatureScheme, SuiError> {
        match byte_int {
            0x00 => Ok(SignatureScheme::ED25519),
            0x01 => Ok(SignatureScheme::Secp256k1),
            0x02 => Ok(SignatureScheme::Secp256r1),
            0x03 => Ok(SignatureScheme::MultiSig),
            0x04 => Ok(SignatureScheme::BLS12381),
            0x05 => Ok(SignatureScheme::ZkLoginAuthenticator),
            _ => Err(SuiError::KeyConversionError(
                "Invalid key scheme".to_string(),
            )),
        }
    }
}

/// Unlike [enum Signature], [enum CompressedSignature] does not contain public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompressedSignature {
    Ed25519(Ed25519SignatureAsBytes),
    Secp256k1(Secp256k1SignatureAsBytes),
    Secp256r1(Secp256r1SignatureAsBytes),
}

impl AsRef<[u8]> for CompressedSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            CompressedSignature::Ed25519(sig) => &sig.0,
            CompressedSignature::Secp256k1(sig) => &sig.0,
            CompressedSignature::Secp256r1(sig) => &sig.0,
        }
    }
}

impl FromStr for Signature {
    type Err = eyre::Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s).map_err(|e| eyre!("Fail to decode base64 {}", e.to_string()))
    }
}

impl FromStr for PublicKey {
    type Err = eyre::Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s).map_err(|e| eyre!("Fail to decode base64 {}", e.to_string()))
    }
}
