// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::sui_serde::BigInt;
use crate::sui_serde::Readable;
use crate::{
    error::{UserInputError, UserInputResult},
    object::Object,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

sui_macros::checked_arithmetic! {

/// Summary of the charges in a transaction.
/// Storage is charged independently of computation.
/// There are 3 parts to the storage charges:
/// `storage_cost`: it is the charge of storage at the time the transaction is executed.
///                 The cost of storage is the number of bytes of the objects being mutated
///                 multiplied by a variable storage cost per byte
/// `storage_rebate`: this is the amount a user gets back when manipulating an object.
///                   The `storage_rebate` is the `storage_cost` for an object minus fees.
/// `non_refundable_storage_fee`: not all the value of the object storage cost is
///                               given back to user and there is a small fraction that
///                               is kept by the system. This value tracks that charge.
///
/// When looking at a gas cost summary the amount charged to the user is
/// `computation_cost + storage_cost - storage_rebate`
/// and that is the amount that is deducted from the gas coins.
/// `non_refundable_storage_fee` is collected from the objects being mutated/deleted
/// and it is tracked by the system in storage funds.
///
/// Objects deleted, including the older versions of objects mutated, have the storage field
/// on the objects added up to a pool of "potential rebate". This rebate then is reduced
/// by the "nonrefundable rate" such that:
/// `potential_rebate(storage cost of deleted/mutated objects) =
/// storage_rebate + non_refundable_storage_fee`

#[serde_as]
#[derive(Eq, PartialEq, Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GasCostSummary {
    /// Cost of computation/execution
    #[schemars(with = "BigInt<u64>")]
    #[serde_as(as = "Readable<BigInt<u64>, _>")]
    pub computation_cost: u64,
    /// Storage cost, it's the sum of all storage cost for all objects created or mutated.
    #[schemars(with = "BigInt<u64>")]
    #[serde_as(as = "Readable<BigInt<u64>, _>")]
    pub storage_cost: u64,
    /// The amount of storage cost refunded to the user for all objects deleted or mutated in the
    /// transaction.
    #[schemars(with = "BigInt<u64>")]
    #[serde_as(as = "Readable<BigInt<u64>, _>")]
    pub storage_rebate: u64,
    /// The fee for the rebate. The portion of the storage rebate kept by the system.
    #[schemars(with = "BigInt<u64>")]
    #[serde_as(as = "Readable<BigInt<u64>, _>")]
    pub non_refundable_storage_fee: u64,
}

impl GasCostSummary {
    pub fn new(computation_cost: u64, storage_cost: u64, storage_rebate: u64, non_refundable_storage_fee: u64) -> GasCostSummary {
        GasCostSummary {
            computation_cost,
            storage_cost,
            storage_rebate,
            non_refundable_storage_fee,
        }
    }

    pub fn gas_used(&self) -> u64 {
        self.computation_cost + self.storage_cost
    }

    /// Portion of the storage rebate that gets passed on to the transaction sender. The remainder
    /// will be burned, then re-minted + added to the storage fund at the next epoch change
    pub fn sender_rebate(&self, storage_rebate_rate: u64) -> u64 {
        // we round storage rebate such that `>= x.5` goes to x+1 (rounds up) and
        // `< x.5` goes to x (truncates). We replicate `f32/64::round()`
        const BASIS_POINTS: u128 = 10000;
        (((self.storage_rebate as u128 * storage_rebate_rate as u128)
            + (BASIS_POINTS / 2)) // integer rounding adds half of the BASIS_POINTS (denominator)
            / BASIS_POINTS) as u64
    }

    /// Get net gas usage, positive number means used gas; negative number means refund.
    pub fn net_gas_usage(&self) -> i64 {
        self.gas_used() as i64 - self.storage_rebate as i64
    }
}

impl alloc::fmt::Display for GasCostSummary {
    fn fmt(&self, f: &mut alloc::fmt::Formatter<'_>) -> alloc::fmt::Result {
        write!(
            f,
            "computation_cost: {}, storage_cost: {},  storage_rebate: {}, non_refundable_storage_fee: {}",
            self.computation_cost, self.storage_cost, self.storage_rebate, self.non_refundable_storage_fee,
        )
    }
}

/// Subtract the gas balance of \p gas_object by \p amount.
/// This function should never fail, since we checked that the budget is always
/// less than balance, and the amount is capped at the budget.

pub fn deduct_gas_legacy(gas_object: &mut Object, deduct_amount: u64, rebate_amount: u64) {
    // The object must be a gas coin as we have checked in transaction handle phase.
    let gas_coin = gas_object.data.try_as_move_mut().unwrap();
    let balance = gas_coin.get_coin_value_unsafe();
    assert!(balance >= deduct_amount);
    gas_coin.set_coin_value_unsafe(balance + rebate_amount - deduct_amount)
}

pub fn deduct_gas(gas_object: &mut Object, charge_or_rebate: i64) {
    // The object must be a gas coin as we have checked in transaction handle phase.
    let gas_coin = gas_object.data.try_as_move_mut().unwrap();
    let balance = gas_coin.get_coin_value_unsafe();
    let new_balance = if charge_or_rebate < 0 {
        balance + (-charge_or_rebate as u64)
    } else {
        assert!(balance >= charge_or_rebate as u64);
        balance - charge_or_rebate as u64
    };
    gas_coin.set_coin_value_unsafe(new_balance)
}

pub fn refund_gas(gas_object: &mut Object, amount: u64) {
    // The object must be a gas coin as we have checked in transaction handle phase.
    let gas_coin = gas_object.data.try_as_move_mut().unwrap();
    let balance = gas_coin.get_coin_value_unsafe();
    gas_coin.set_coin_value_unsafe(balance + amount)
}

pub fn get_gas_balance(gas_object: &Object) -> UserInputResult<u64> {
    if let Some(move_obj) = gas_object.data.try_as_move() {
        if !move_obj.type_().is_gas_coin() {
            return Err(UserInputError::InvalidGasObject {
                object_id: gas_object.id(),
            })
        }
        Ok(move_obj.get_coin_value_unsafe())
    } else {
        Err(UserInputError::InvalidGasObject {
            object_id: gas_object.id(),
        })
    }
}

}
