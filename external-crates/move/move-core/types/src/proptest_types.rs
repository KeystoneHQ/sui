// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{StructTag, TypeTag},
    transaction_argument::TransactionArgument,
};
use alloc::boxed::Box;
use proptest::{collection::vec, prelude::*};
