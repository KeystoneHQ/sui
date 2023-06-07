// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Since `std::mem::size_of` may not be stable across platforms, we use rough constants
// We need these for estimating effects sizes
// Approximate size of `ObjectRef` type in bytes
pub const APPROX_SIZE_OF_OBJECT_REF: usize = 80;
// Approximate size of `ExecutionStatus` type in bytes
pub const APPROX_SIZE_OF_EXECUTION_STATUS: usize = 120;
// Approximate size of `EpochId` type in bytes
pub const APPROX_SIZE_OF_EPOCH_ID: usize = 10;
// Approximate size of `GasCostSummary` type in bytes
pub const APPROX_SIZE_OF_GAS_COST_SUMMARY: usize = 40;
// Approximate size of `Option<TransactionEventsDigest>` type in bytes
pub const APPROX_SIZE_OF_OPT_TX_EVENTS_DIGEST: usize = 40;
// Approximate size of `TransactionDigest` type in bytes
pub const APPROX_SIZE_OF_TX_DIGEST: usize = 40;
// Approximate size of `Owner` type in bytes
pub const APPROX_SIZE_OF_OWNER: usize = 48;
