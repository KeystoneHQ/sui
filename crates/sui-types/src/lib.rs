// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![feature(error_in_core)]

extern crate alloc;

use base_types::{SequenceNumber, SuiAddress};
use move_core_types::{account_address::AccountAddress, language_storage::StructTag};
pub use move_core_types::{identifier::Identifier, language_storage::TypeTag};
use object::OBJECT_START_VERSION;

use base_types::ObjectID;

#[macro_use]
pub mod error;

pub mod fastcrypto;
pub mod balance;
pub mod base_types;
pub mod coin;
pub mod committee;
pub mod digests;
pub mod effects;
pub mod event;
pub mod execution_status;
pub mod gas;
pub mod gas_coin;
pub mod governance;
pub mod id;
pub mod move_package;
pub mod object;
pub mod programmable_transaction_builder;
pub mod sui_protocol_config;
pub mod sui_serde;

pub mod transaction;

/// 0x1-- account address where Move stdlib modules are stored
/// Same as the ObjectID
pub const MOVE_STDLIB_ADDRESS: AccountAddress = AccountAddress::ONE;
pub const MOVE_STDLIB_PACKAGE_ID: ObjectID = ObjectID::from_address(MOVE_STDLIB_ADDRESS);

/// 0x2-- account address where sui framework modules are stored
/// Same as the ObjectID
pub const SUI_FRAMEWORK_ADDRESS: AccountAddress = address_from_single_byte(2);
pub const SUI_FRAMEWORK_PACKAGE_ID: ObjectID = ObjectID::from_address(SUI_FRAMEWORK_ADDRESS);

/// 0x3-- account address where sui system modules are stored
/// Same as the ObjectID
pub const SUI_SYSTEM_ADDRESS: AccountAddress = address_from_single_byte(3);
pub const SUI_SYSTEM_PACKAGE_ID: ObjectID = ObjectID::from_address(SUI_SYSTEM_ADDRESS);

/// 0xdee9-- account address where DeepBook modules are stored
/// Same as the ObjectID
pub const DEEPBOOK_ADDRESS: AccountAddress = deepbook_addr();
pub const DEEPBOOK_PACKAGE_ID: ObjectID = ObjectID::from_address(DEEPBOOK_ADDRESS);

/// 0x5: hardcoded object ID for the singleton sui system state object.
pub const SUI_SYSTEM_STATE_ADDRESS: AccountAddress = address_from_single_byte(5);
pub const SUI_SYSTEM_STATE_OBJECT_ID: ObjectID = ObjectID::from_address(SUI_SYSTEM_STATE_ADDRESS);
pub const SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION: SequenceNumber = OBJECT_START_VERSION;

/// 0x6: hardcoded object ID for the singleton clock object.
pub const SUI_CLOCK_ADDRESS: AccountAddress = address_from_single_byte(6);
pub const SUI_CLOCK_OBJECT_ID: ObjectID = ObjectID::from_address(SUI_CLOCK_ADDRESS);
pub const SUI_CLOCK_OBJECT_SHARED_VERSION: SequenceNumber = OBJECT_START_VERSION;

const fn address_from_single_byte(b: u8) -> AccountAddress {
    let mut addr = [0u8; AccountAddress::LENGTH];
    addr[AccountAddress::LENGTH - 1] = b;
    AccountAddress::new(addr)
}

/// return 0x0...dee9
const fn deepbook_addr() -> AccountAddress {
    let mut addr = [0u8; AccountAddress::LENGTH];
    addr[AccountAddress::LENGTH - 2] = 0xde;
    addr[AccountAddress::LENGTH - 1] = 0xe9;
    AccountAddress::new(addr)
}

pub fn parse_sui_struct_tag(s: &str) -> anyhow::Result<StructTag> {
    use move_command_line_common::types::ParsedStructType;
    ParsedStructType::parse(s)?.into_struct_tag(&resolve_address)
}

pub fn parse_sui_type_tag(s: &str) -> anyhow::Result<TypeTag> {
    use move_command_line_common::types::ParsedType;
    ParsedType::parse(s)?.into_type_tag(&resolve_address)
}

fn resolve_address(addr: &str) -> Option<AccountAddress> {
    match addr {
        "deepbook" => Some(DEEPBOOK_ADDRESS),
        "std" => Some(MOVE_STDLIB_ADDRESS),
        "sui" => Some(SUI_FRAMEWORK_ADDRESS),
        "sui_system" => Some(SUI_SYSTEM_ADDRESS),
        _ => None,
    }
}

pub trait MoveTypeTagTrait {
    fn get_type_tag() -> TypeTag;
}

impl MoveTypeTagTrait for u64 {
    fn get_type_tag() -> TypeTag {
        TypeTag::U64
    }
}

impl MoveTypeTagTrait for ObjectID {
    fn get_type_tag() -> TypeTag {
        TypeTag::Address
    }
}

impl MoveTypeTagTrait for SuiAddress {
    fn get_type_tag() -> TypeTag {
        TypeTag::Address
    }
}
