// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![no_std]

use alloc::string::String;

extern crate alloc;

pub trait EnumOrderMap {
    fn order_to_variant_map() -> alloc::collections::BTreeMap<u64, String>;
}
