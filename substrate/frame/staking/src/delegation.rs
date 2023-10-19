// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! An implementation of a delegation system for nominators.
//!
//! This allows an account (called delegator) to delegate their funds to another account
//! (delegatee). Multiple delegators can delegate to the same delegatee. The delegatee is then able
//! to use the funds of all delegators to nominate a set of validators.

use crate::{BalanceOf, Config, Delegatees, Delegators, Error};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
	dispatch::DispatchResult,
	ensure,
	traits::{Currency, LockIdentifier, LockableCurrency, WithdrawReasons},
};
use scale_info::TypeInfo;
use sp_runtime::{DispatchError, RuntimeDebug, Saturating};

/// Lock identifier for funds delegated to another account.
///
/// This helps us differentiate the locks used for direct nomination and delegation based nomination
/// and technically allows a direct nominator to be a delegator as well. We don't strictly need to
/// support this but before delegation based staking were a thing, above was possible and we would
/// like to keep things consistent and compatible once user of this pallet (NominationPools) moves
/// to delegation based staking.
const DELEGATING_ID: LockIdentifier = *b"delegate";

/// An aggregate ledger of a delegator.
///
/// This keeps track of the active balance of the delegator that is made up from the funds that are
/// currently delegated to a delegatee. It also tracks the slashes yet to be applied.
#[derive(Default, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct DelegationAggregate<T: Config> {
	/// Sum of all delegated funds to this delegatee.
	#[codec(compact)]
	pub balance: BalanceOf<T>,
	/// Slashes that are not yet applied.
	#[codec(compact)]
	pub pending_slash: BalanceOf<T>,
}

/// Total balance delegated to the given delegatee.
pub(crate) fn delegated_balance<T: Config>(delegatee: &T::AccountId) -> BalanceOf<T> {
	<Delegatees<T>>::get(delegatee).map_or_else(|| 0u32.into(), |aggregate| aggregate.balance)
}
/// Delegate some amount from delegator to delegatee.
pub(crate) fn delegate<T: Config>(
	delegator: T::AccountId,
	delegatee: T::AccountId,
	value: BalanceOf<T>,
) -> DispatchResult {
	let delegator_balance = T::Currency::free_balance(&delegator);
	ensure!(value >= T::Currency::minimum_balance(), Error::<T>::InsufficientBond);
	ensure!(delegator_balance >= value, Error::<T>::InsufficientBond);
	ensure!(delegatee != delegator, Error::<T>::InvalidDelegation);

	// A delegator cannot receive delegations.
	if <Delegators<T>>::contains_key(&delegatee) {
		return Err(Error::<T>::InvalidDelegation.into())
	}

	// A delegatee cannot delegate to another account
	if <Delegatees<T>>::contains_key(&delegator) {
		return Err(Error::<T>::InvalidDelegation.into())
	}

	let mut new_delegation_amount = value;

	let delegation = <Delegators<T>>::get(&delegator);
	if delegation.is_some() {
		// add to existing delegation.
		let (current_delegatee, current_delegation) =
			delegation.expect("checked delegation exists above; qed");
		ensure!(current_delegatee == delegatee, Error::<T>::InvalidDelegation);
		new_delegation_amount = new_delegation_amount.saturating_add(current_delegation);
	}

	<Delegators<T>>::insert(&delegator, (&delegatee, new_delegation_amount));
	<Delegatees<T>>::mutate(&delegatee, |maybe_aggregate| match maybe_aggregate {
		Some(ledger) => ledger.balance.saturating_accrue(value),
		None =>
			*maybe_aggregate = Some(DelegationAggregate {
				balance: new_delegation_amount,
				pending_slash: Default::default(),
			}),
	});
	T::Currency::set_lock(DELEGATING_ID, &delegator, value, WithdrawReasons::all());

	Ok(())
}

pub(crate) fn withdraw<T: Config>(
	delegatee: T::AccountId,
	delegator: T::AccountId,
	value: BalanceOf<T>,
) -> Result<bool, DispatchError> {
	todo!()
}
