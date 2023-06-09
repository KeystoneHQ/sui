// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use alloc::borrow::ToOwned;
use alloc::fmt::{Debug, Display, Formatter};
use alloc::string::ToString;
use alloc::vec::Vec;
use core::mem::size_of;

use move_binary_format::CompiledModule;
use move_core_types::language_storage::StructTag;
use move_core_types::language_storage::TypeTag;
use move_core_types::value::{MoveStruct, MoveStructLayout};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::Bytes;

use crate::base_types::{MoveObjectType, ObjectIDParseError};
use crate::coin::Coin;
use crate::error::{ExecutionError, ExecutionErrorKind, UserInputError, UserInputResult};
use crate::error::{SuiError, SuiResult};
use crate::move_package::MovePackage;
use crate::{
    base_types::{
        ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest,
    },
    gas_coin::GasCoin,
};

pub const GAS_VALUE_FOR_TESTING: u64 = 300_000_000_000_000;
pub const OBJECT_START_VERSION: SequenceNumber = SequenceNumber::from_u64(1);

/// Return `true` if `id` is a special system package that can be upgraded at epoch boundaries
/// All new system package ID's must be added here
pub fn is_system_package(id: ObjectID) -> bool {
    matches!(
        id,
        crate::MOVE_STDLIB_PACKAGE_ID
            |crate::SUI_FRAMEWORK_PACKAGE_ID
            | crate::SUI_SYSTEM_PACKAGE_ID
            | crate::DEEPBOOK_PACKAGE_ID
    )
}

#[serde_as]
#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash)]
pub struct MoveObject {
    /// The type of this object. Immutable
    type_: MoveObjectType,
    /// Determines if it is usable with the TransferObject command
    /// Derived from the type_
    has_public_transfer: bool,
    /// Number that increases each time a tx takes this object as a mutable input
    /// This is a lamport timestamp, not a sequentially increasing version
    version: SequenceNumber,
    /// BCS bytes of a Move struct value
    #[serde_as(as = "Bytes")]
    contents: Vec<u8>,
}

/// Index marking the end of the object's ID + the beginning of its version
pub const ID_END_INDEX: usize = ObjectID::LENGTH;

/// Different schemes for converting a Move value into a structured representation
#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash)]
pub struct ObjectFormatOptions {
    /// If true, include the type of each object as well as its fields; e.g.:
    /// `{ "fields": { "f": 20, "g": { "fields" { "h": true }, "type": "0x0::MyModule::MyNestedType" }, "type": "0x0::MyModule::MyType" }`
    ///  If false, include field names only; e.g.:
    /// `{ "f": 20, "g": { "h": true } }`
    include_types: bool,
}

impl ObjectFormatOptions {
    pub fn with_types() -> Self {
        ObjectFormatOptions {
            include_types: true,
        }
    }

    pub fn include_types(&self) -> bool {
        self.include_types
    }
}

impl MoveObject {
    /// # Safety
    /// This function should ONLY be called if has_public_transfer has been determined by the type_
    pub unsafe fn new_from_execution_with_limit(
        type_: MoveObjectType,
        has_public_transfer: bool,
        version: SequenceNumber,
        contents: Vec<u8>,
        max_move_object_size: u64,
    ) -> Result<Self, ExecutionError> {
        // coins should always have public transfer, as they always should have store.
        // Thus, type_ == GasCoin::type_() ==> has_public_transfer
        // TODO: think this can be generalized to is_coin
        debug_assert!(!type_.is_gas_coin() || has_public_transfer);
        if contents.len() as u64 > max_move_object_size {
            return Err(ExecutionError::from_kind(
                ExecutionErrorKind::MoveObjectTooBig {
                    object_size: contents.len() as u64,
                    max_object_size: max_move_object_size,
                },
            ));
        }
        Ok(Self {
            type_,
            has_public_transfer,
            version,
            contents,
        })
    }

    pub fn new_gas_coin(version: SequenceNumber, id: ObjectID, value: u64) -> Self {
        // unwrap safe because coins are always smaller than the max object size
        unsafe {
            Self::new_from_execution_with_limit(
                GasCoin::type_().into(),
                true,
                version,
                GasCoin::new(id, value).to_bcs_bytes(),
                256,
            )
            .unwrap()
        }
    }

    pub fn new_coin(
        coin_type: MoveObjectType,
        version: SequenceNumber,
        id: ObjectID,
        value: u64,
    ) -> Self {
        // unwrap safe because coins are always smaller than the max object size
        unsafe {
            Self::new_from_execution_with_limit(
                coin_type,
                true,
                version,
                GasCoin::new(id, value).to_bcs_bytes(),
                256,
            )
            .unwrap()
        }
    }

    pub fn type_(&self) -> &MoveObjectType {
        &self.type_
    }

    pub fn is_type(&self, s: &StructTag) -> bool {
        self.type_.is(s)
    }

    pub fn has_public_transfer(&self) -> bool {
        self.has_public_transfer
    }

    pub fn id(&self) -> ObjectID {
        Self::id_opt(&self.contents).unwrap()
    }

    pub fn id_opt(contents: &[u8]) -> Result<ObjectID, ObjectIDParseError> {
        if ID_END_INDEX > contents.len() {
            return Err(ObjectIDParseError::TryFromSliceError);
        }
        ObjectID::try_from(&contents[0..ID_END_INDEX])
    }

    /// Return the `value: u64` field of a `Coin<T>` type.
    /// Useful for reading the coin without deserializing the object into a Move value
    /// It is the caller's responsibility to check that `self` is a coin--this function
    /// may panic or do something unexpected otherwise.
    pub fn get_coin_value_unsafe(&self) -> u64 {
        debug_assert!(self.type_.is_coin());
        // 32 bytes for object ID, 8 for balance
        debug_assert!(self.contents.len() == 40);

        // unwrap safe because we checked that it is a coin
        u64::from_le_bytes(<[u8; 8]>::try_from(&self.contents[ID_END_INDEX..]).unwrap())
    }

    /// Update the `value: u64` field of a `Coin<T>` type.
    /// Useful for updating the coin without deserializing the object into a Move value
    /// It is the caller's responsibility to check that `self` is a coin--this function
    /// may panic or do something unexpected otherwise.
    pub fn set_coin_value_unsafe(&mut self, value: u64) {
        debug_assert!(self.type_.is_coin());
        // 32 bytes for object ID, 8 for balance
        debug_assert!(self.contents.len() == 40);

        self.contents.splice(ID_END_INDEX.., value.to_le_bytes());
    }

    pub fn is_coin(&self) -> bool {
        self.type_.is_coin()
    }

    pub fn version(&self) -> SequenceNumber {
        self.version
    }

    /// Contents of the object that are specific to its type--i.e., not its ID and version, which all objects have
    /// For example if the object was declared as `struct S has key { id: ID, f1: u64, f2: bool },
    /// this returns the slice containing `f1` and `f2`.
    #[cfg(test)]
    pub fn type_specific_contents(&self) -> &[u8] {
        &self.contents[ID_END_INDEX..]
    }

    /// Sets the version of this object to a new value which is assumed to be higher (and checked to
    /// be higher in debug).
    pub fn increment_version_to(&mut self, next: SequenceNumber) {
        self.version.increment_to(next);
    }

    pub fn decrement_version_to(&mut self, prev: SequenceNumber) {
        self.version.decrement_to(prev);
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn into_contents(self) -> Vec<u8> {
        self.contents
    }

    pub fn into_type(self) -> MoveObjectType {
        self.type_
    }

    pub fn into_inner(self) -> (MoveObjectType, Vec<u8>) {
        (self.type_, self.contents)
    }

    /// Convert `self` to the JSON representation dictated by `layout`.
    pub fn to_move_struct(&self, layout: &MoveStructLayout) -> Result<MoveStruct, SuiError> {
        MoveStruct::simple_deserialize(&self.contents, layout).map_err(|e| {
            SuiError::ObjectSerializationError {
                error: e.to_string(),
            }
        })
    }

    /// Approximate size of the object in bytes. This is used for gas metering.
    /// For the type tag field, we serialize it on the spot to get the accurate size.
    /// This should not be very expensive since the type tag is usually simple, and
    /// we only do this once per object being mutated.
    pub fn object_size_for_gas_metering(&self) -> usize {
        let serialized_type_tag_size =
            bcs::serialized_size(&self.type_).expect("Serializing type tag should not fail");
        // + 1 for 'has_public_transfer'
        // + 8 for `version`
        self.contents.len() + serialized_type_tag_size + 1 + 8
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum Data {
    /// An object whose governing logic lives in a published Move module
    Move(MoveObject),
    /// Map from each module name to raw serialized Move module bytes
    Package(MovePackage),
    // ... Sui "native" types go here
}

impl Data {
    pub fn try_as_move(&self) -> Option<&MoveObject> {
        use Data::*;
        match self {
            Move(m) => Some(m),
            Package(_) => None,
        }
    }

    pub fn try_as_move_mut(&mut self) -> Option<&mut MoveObject> {
        use Data::*;
        match self {
            Move(m) => Some(m),
            Package(_) => None,
        }
    }

    pub fn try_as_package(&self) -> Option<&MovePackage> {
        use Data::*;
        match self {
            Move(_) => None,
            Package(p) => Some(p),
        }
    }

    pub fn try_as_package_mut(&mut self) -> Option<&mut MovePackage> {
        use Data::*;
        match self {
            Move(_) => None,
            Package(p) => Some(p),
        }
    }

    pub fn try_into_package(self) -> Option<MovePackage> {
        use Data::*;
        match self {
            Move(_) => None,
            Package(p) => Some(p),
        }
    }

    pub fn type_(&self) -> Option<&MoveObjectType> {
        use Data::*;
        match self {
            Move(m) => Some(m.type_()),
            Package(_) => None,
        }
    }

    pub fn struct_tag(&self) -> Option<StructTag> {
        use Data::*;
        match self {
            Move(m) => Some(m.type_().clone().into()),
            Package(_) => None,
        }
    }

    pub fn id(&self) -> ObjectID {
        match self {
            Self::Move(v) => v.id(),
            Self::Package(m) => m.id(),
        }
    }
}

#[derive(
    Eq, PartialEq, Debug, Clone, Copy, Deserialize, Serialize, Hash, Ord, PartialOrd,
)]
pub enum Owner {
    /// Object is exclusively owned by a single address, and is mutable.
    AddressOwner(SuiAddress),
    /// Object is exclusively owned by a single object, and is mutable.
    /// The object ID is converted to SuiAddress as SuiAddress is universal.
    ObjectOwner(SuiAddress),
    /// Object is shared, can be used by any address, and is mutable.
    Shared {
        /// The version at which the object became shared
        initial_shared_version: SequenceNumber,
    },
    /// Object is immutable, and hence ownership doesn't matter.
    Immutable,
}

impl Owner {
    // NOTE: only return address of AddressOwner, otherwise return error,
    // ObjectOwner's address is converted from object id, thus we will skip it.
    pub fn get_address_owner_address(&self) -> SuiResult<SuiAddress> {
        match self {
            Self::AddressOwner(address) => Ok(*address),
            Self::Shared { .. } | Self::Immutable | Self::ObjectOwner(_) => {
                Err(SuiError::UnexpectedOwnerType)
            }
        }
    }

    // NOTE: this function will return address of both AddressOwner and ObjectOwner,
    // address of ObjectOwner is converted from object id, even though the type is SuiAddress.
    pub fn get_owner_address(&self) -> SuiResult<SuiAddress> {
        match self {
            Self::AddressOwner(address) | Self::ObjectOwner(address) => Ok(*address),
            Self::Shared { .. } | Self::Immutable => Err(SuiError::UnexpectedOwnerType),
        }
    }

    pub fn is_immutable(&self) -> bool {
        matches!(self, Owner::Immutable)
    }

    pub fn is_address_owned(&self) -> bool {
        matches!(self, Owner::AddressOwner(_))
    }

    pub fn is_child_object(&self) -> bool {
        matches!(self, Owner::ObjectOwner(_))
    }

    pub fn is_shared(&self) -> bool {
        matches!(self, Owner::Shared { .. })
    }
}

impl PartialEq<SuiAddress> for Owner {
    fn eq(&self, other: &SuiAddress) -> bool {
        match self {
            Self::AddressOwner(address) => address == other,
            Self::ObjectOwner(_) | Self::Shared { .. } | Self::Immutable => false,
        }
    }
}

impl PartialEq<ObjectID> for Owner {
    fn eq(&self, other: &ObjectID) -> bool {
        let other_id: SuiAddress = (*other).into();
        match self {
            Self::ObjectOwner(id) => id == &other_id,
            Self::AddressOwner(_) | Self::Shared { .. } | Self::Immutable => false,
        }
    }
}

impl Display for Owner {
    fn fmt(&self, f: &mut Formatter<'_>) -> alloc::fmt::Result {
        match self {
            Self::AddressOwner(address) => {
                write!(f, "Account Address ( {} )", address)
            }
            Self::ObjectOwner(address) => {
                write!(f, "Object ID: ( {} )", address)
            }
            Self::Immutable => {
                write!(f, "Immutable")
            }
            Self::Shared { .. } => {
                write!(f, "Shared")
            }
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash)]
pub struct Object {
    /// The meat of the object
    pub data: Data,
    /// The owner that unlocks this object
    pub owner: Owner,
    /// The digest of the transaction that created or last mutated this object
    pub previous_transaction: TransactionDigest,
    /// The amount of SUI we would rebate if this object gets deleted.
    /// This number is re-calculated each time the object is mutated based on
    /// the present storage gas price.
    pub storage_rebate: u64,
}

impl Object {
    /// Create a new Move object
    pub fn new_move(o: MoveObject, owner: Owner, previous_transaction: TransactionDigest) -> Self {
        Object {
            data: Data::Move(o),
            owner,
            previous_transaction,
            storage_rebate: 0,
        }
    }

    /// Returns true if the object is a system package.
    pub fn is_system_package(&self) -> bool {
        self.is_package() && is_system_package(self.id())
    }

    pub fn new_package_from_data(data: Data, previous_transaction: TransactionDigest) -> Self {
        Object {
            data,
            owner: Owner::Immutable,
            previous_transaction,
            storage_rebate: 0,
        }
    }

    // Note: this will panic if `modules` is empty
    pub fn new_package<'p>(
        modules: &[CompiledModule],
        previous_transaction: TransactionDigest,
        max_move_package_size: u64,
        dependencies: impl IntoIterator<Item = &'p MovePackage>,
    ) -> Result<Self, ExecutionError> {
        Ok(Self::new_package_from_data(
            Data::Package(MovePackage::new_initial(
                modules,
                max_move_package_size,
                dependencies,
            )?),
            previous_transaction,
        ))
    }

    pub fn is_immutable(&self) -> bool {
        self.owner.is_immutable()
    }

    pub fn is_address_owned(&self) -> bool {
        self.owner.is_address_owned()
    }

    pub fn is_child_object(&self) -> bool {
        self.owner.is_child_object()
    }

    pub fn is_shared(&self) -> bool {
        self.owner.is_shared()
    }

    pub fn get_single_owner(&self) -> Option<SuiAddress> {
        self.owner.get_owner_address().ok()
    }

    // It's a common pattern to retrieve both the owner and object ID
    // together, if it's owned by a singler owner.
    pub fn get_owner_and_id(&self) -> Option<(Owner, ObjectID)> {
        Some((self.owner, self.id()))
    }

    /// Return true if this object is a Move package, false if it is a Move value
    pub fn is_package(&self) -> bool {
        matches!(&self.data, Data::Package(_))
    }

    pub fn id(&self) -> ObjectID {
        use Data::*;

        match &self.data {
            Move(v) => v.id(),
            Package(m) => m.id(),
        }
    }

    pub fn version(&self) -> SequenceNumber {
        use Data::*;

        match &self.data {
            Move(o) => o.version(),
            Package(p) => p.version(),
        }
    }

    pub fn type_(&self) -> Option<&MoveObjectType> {
        self.data.type_()
    }

    pub fn struct_tag(&self) -> Option<StructTag> {
        self.data.struct_tag()
    }

    pub fn is_coin(&self) -> bool {
        if let Some(move_object) = self.data.try_as_move() {
            move_object.type_().is_coin()
        } else {
            false
        }
    }

    pub fn is_gas_coin(&self) -> bool {
        if let Some(move_object) = self.data.try_as_move() {
            move_object.type_().is_gas_coin()
        } else {
            false
        }
    }

    // TODO: use `MoveObj::get_balance_unsafe` instead.
    // context: https://github.com/MystenLabs/sui/pull/10679#discussion_r1165877816
    pub fn as_coin_maybe(&self) -> Option<Coin> {
        if let Some(move_object) = self.data.try_as_move() {
            let coin: Coin = bcs::from_bytes(move_object.contents()).ok()?;
            Some(coin)
        } else {
            None
        }
    }

    pub fn coin_type_maybe(&self) -> Option<TypeTag> {
        if let Some(move_object) = self.data.try_as_move() {
            move_object.type_().coin_type_maybe()
        } else {
            None
        }
    }
    /// Approximate size of the object in bytes. This is used for gas metering.
    /// This will be slgihtly different from the serialized size, but
    /// we also don't want to serialize the object just to get the size.
    /// This approximation should be good enough for gas metering.
    pub fn object_size_for_gas_metering(&self) -> usize {
        let meta_data_size = size_of::<Owner>() + size_of::<TransactionDigest>() + size_of::<u64>();
        let data_size = match &self.data {
            Data::Move(m) => m.object_size_for_gas_metering(),
            Data::Package(p) => p.object_size_for_gas_metering(),
        };
        meta_data_size + data_size
    }

    /// Change the owner of `self` to `new_owner`.
    pub fn transfer(&mut self, new_owner: SuiAddress) {
        self.owner = Owner::AddressOwner(new_owner);
    }

    /// Treat the object type as a Move struct with one type parameter,
    /// like this: `S<T>`.
    /// Returns the inner parameter type `T`.
    pub fn get_move_template_type(&self) -> SuiResult<TypeTag> {
        let move_struct = self.data.struct_tag().ok_or_else(|| SuiError::TypeError {
            error: "Object must be a Move object".to_owned(),
        })?;
        fp_ensure!(
            move_struct.type_params.len() == 1,
            SuiError::TypeError {
                error: "Move object struct must have one type parameter".to_owned()
            }
        );
        // Index access safe due to checks above.
        let type_tag = move_struct.type_params[0].clone();
        Ok(type_tag)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", content = "details")]
pub enum ObjectRead {
    NotExists(ObjectID),
    Exists(ObjectRef, Object, Option<MoveStructLayout>),
    Deleted(ObjectRef),
}

impl ObjectRead {
    /// Returns the object value if there is any, otherwise an Err if
    /// the object does not exist or is deleted.
    pub fn into_object(self) -> UserInputResult<Object> {
        match self {
            Self::Deleted(oref) => Err(UserInputError::ObjectDeleted { object_ref: oref }),
            Self::NotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: id,
                version: None,
            }),
            Self::Exists(_, o, _) => Ok(o),
        }
    }

    pub fn object(&self) -> UserInputResult<&Object> {
        match self {
            Self::Deleted(oref) => Err(UserInputError::ObjectDeleted { object_ref: *oref }),
            Self::NotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: *id,
                version: None,
            }),
            Self::Exists(_, o, _) => Ok(o),
        }
    }

    pub fn object_id(&self) -> ObjectID {
        match self {
            Self::Deleted(oref) => oref.0,
            Self::NotExists(id) => *id,
            Self::Exists(oref, _, _) => oref.0,
        }
    }
}

impl Default for ObjectFormatOptions {
    fn default() -> Self {
        ObjectFormatOptions {
            include_types: true,
        }
    }
}

impl Display for ObjectRead {
    fn fmt(&self, f: &mut Formatter<'_>) -> alloc::fmt::Result {
        match self {
            Self::Deleted(oref) => {
                write!(f, "ObjectRead::Deleted ({:?})", oref)
            }
            Self::NotExists(id) => {
                write!(f, "ObjectRead::NotExists ({:?})", id)
            }
            Self::Exists(oref, _, _) => {
                write!(f, "ObjectRead::Exists ({:?})", oref)
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", content = "details")]
pub enum PastObjectRead {
    /// The object does not exist
    ObjectNotExists(ObjectID),
    /// The object is found to be deleted with this version
    ObjectDeleted(ObjectRef),
    /// The object exists and is found with this version
    VersionFound(ObjectRef, Object, Option<MoveStructLayout>),
    /// The object exists but not found with this version
    VersionNotFound(ObjectID, SequenceNumber),
    /// The asked object version is higher than the latest
    VersionTooHigh {
        object_id: ObjectID,
        asked_version: SequenceNumber,
        latest_version: SequenceNumber,
    },
}

impl PastObjectRead {
    /// Returns the object value if there is any, otherwise an Err
    pub fn into_object(self) -> UserInputResult<Object> {
        match self {
            Self::ObjectDeleted(oref) => Err(UserInputError::ObjectDeleted { object_ref: oref }),
            Self::ObjectNotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: id,
                version: None,
            }),
            Self::VersionFound(_, o, _) => Ok(o),
            Self::VersionNotFound(object_id, version) => Err(UserInputError::ObjectNotFound {
                object_id,
                version: Some(version),
            }),
            Self::VersionTooHigh {
                object_id,
                asked_version,
                latest_version,
            } => Err(UserInputError::ObjectSequenceNumberTooHigh {
                object_id,
                asked_version,
                latest_version,
            }),
        }
    }
}

impl Display for PastObjectRead {
    fn fmt(&self, f: &mut Formatter<'_>) -> alloc::fmt::Result {
        match self {
            Self::ObjectDeleted(oref) => {
                write!(f, "PastObjectRead::ObjectDeleted ({:?})", oref)
            }
            Self::ObjectNotExists(id) => {
                write!(f, "PastObjectRead::ObjectNotExists ({:?})", id)
            }
            Self::VersionFound(oref, _, _) => {
                write!(f, "PastObjectRead::VersionFound ({:?})", oref)
            }
            Self::VersionNotFound(object_id, version) => {
                write!(
                    f,
                    "PastObjectRead::VersionNotFound ({:?}, asked sequence number {:?})",
                    object_id, version
                )
            }
            Self::VersionTooHigh {
                object_id,
                asked_version,
                latest_version,
            } => {
                write!(f, "PastObjectRead::VersionTooHigh ({:?}, asked sequence number {:?}, latest sequence number {:?})", object_id, asked_version, latest_version)
            }
        }
    }
}

#[test]
fn test_get_coin_value_unsafe() {
    fn test_for_value(v: u64) {
        let g = GasCoin::new_for_testing(v).to_object(OBJECT_START_VERSION);
        assert_eq!(g.get_coin_value_unsafe(), v);
        assert_eq!(GasCoin::try_from(&g).unwrap().value(), v);
    }

    test_for_value(0);
    test_for_value(1);
    test_for_value(8);
    test_for_value(9);
    test_for_value(u8::MAX as u64);
    test_for_value(u8::MAX as u64 + 1);
    test_for_value(u16::MAX as u64);
    test_for_value(u16::MAX as u64 + 1);
    test_for_value(u32::MAX as u64);
    test_for_value(u32::MAX as u64 + 1);
    test_for_value(u64::MAX);
}

#[test]
fn test_set_coin_value_unsafe() {
    fn test_for_value(v: u64) {
        let mut g = GasCoin::new_for_testing(u64::MAX).to_object(OBJECT_START_VERSION);
        g.set_coin_value_unsafe(v);
        assert_eq!(g.get_coin_value_unsafe(), v);
        assert_eq!(GasCoin::try_from(&g).unwrap().value(), v);
        assert_eq!(g.version(), OBJECT_START_VERSION);
        assert_eq!(g.contents().len(), 40);
    }

    test_for_value(0);
    test_for_value(1);
    test_for_value(8);
    test_for_value(9);
    test_for_value(u8::MAX as u64);
    test_for_value(u8::MAX as u64 + 1);
    test_for_value(u16::MAX as u64);
    test_for_value(u16::MAX as u64 + 1);
    test_for_value(u32::MAX as u64);
    test_for_value(u32::MAX as u64 + 1);
    test_for_value(u64::MAX);
}
