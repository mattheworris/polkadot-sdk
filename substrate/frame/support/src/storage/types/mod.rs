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

//! Storage types to build abstraction on storage, they implements storage traits such as
//! StorageMap and others.

use codec::FullCodec;
use sp_metadata_ir::{StorageEntryMetadataIR, StorageEntryModifierIR};
use sp_std::prelude::*;

mod counted_map;
mod counted_nmap;
mod double_map;
mod key;
mod map;
mod nmap;
mod value;

pub use counted_map::{CountedStorageMap, CountedStorageMapInstance};
pub use counted_nmap::{CountedStorageNMap, CountedStorageNMapInstance};
pub use double_map::StorageDoubleMap;
pub use key::{
	EncodeLikeTuple, HasKeyPrefix, HasReversibleKeyPrefix, Key, KeyGenerator,
	KeyGeneratorMaxEncodedLen, ReversibleKeyGenerator, TupleToEncodedIter,
};
pub use map::StorageMap;
pub use nmap::StorageNMap;
pub use value::StorageValue;

/// Trait implementing how the storage optional value is converted into the queried type.
///
/// It is implemented by:
/// * [`OptionQuery`] which converts an optional value to an optional value, used when querying
///   storage returns an optional value.
/// * [`ResultQuery`] which converts an optional value to a result value, used when querying storage
///   returns a result value.
/// * [`ValueQuery`] which converts an optional value to a value, used when querying storage returns
///   a value.
pub trait QueryKindTrait<Value, OnEmpty> {
	/// Metadata for the storage kind.
	const METADATA: StorageEntryModifierIR;

	/// Type returned on query
	type Query: FullCodec + 'static;

	/// Convert an optional value (i.e. some if trie contains the value or none otherwise) to the
	/// query.
	fn from_optional_value_to_query(v: Option<Value>) -> Self::Query;

	/// Convert a query to an optional value.
	fn from_query_to_optional_value(v: Self::Query) -> Option<Value>;
}

/// Implements [`QueryKindTrait`](frame_support::storage::types::QueryKindTrait) with `Query`
/// type being `Option<Value>`.
///
/// NOTE: it doesn't support a generic `OnEmpty`. This means only `None` can be returned when no
/// value is found. To use another `OnEmpty` implementation, `ValueQuery` can be used instead.
pub struct OptionQuery;
impl<Value> QueryKindTrait<Value, crate::traits::GetDefault> for OptionQuery
where
	Value: FullCodec + 'static,
{
	const METADATA: StorageEntryModifierIR = StorageEntryModifierIR::Optional;

	type Query = Option<Value>;

	fn from_optional_value_to_query(v: Option<Value>) -> Self::Query {
		// NOTE: OnEmpty is fixed to GetDefault, thus it returns `None` on no value.
		v
	}

	fn from_query_to_optional_value(v: Self::Query) -> Option<Value> {
		v
	}
}

/// Implements [`QueryKindTrait`](frame_support::storage::types::QueryKindTrait) with `Query`
/// type being `Result<Value, PalletError>`.
pub struct ResultQuery<Error>(sp_std::marker::PhantomData<Error>);
impl<Value, Error, OnEmpty> QueryKindTrait<Value, OnEmpty> for ResultQuery<Error>
where
	Value: FullCodec + 'static,
	Error: FullCodec + 'static,
	OnEmpty: crate::traits::Get<Result<Value, Error>>,
{
	const METADATA: StorageEntryModifierIR = StorageEntryModifierIR::Optional;

	type Query = Result<Value, Error>;

	fn from_optional_value_to_query(v: Option<Value>) -> Self::Query {
		match v {
			Some(v) => Ok(v),
			None => OnEmpty::get(),
		}
	}

	fn from_query_to_optional_value(v: Self::Query) -> Option<Value> {
		v.ok()
	}
}

/// Implements [`QueryKindTrait`](frame_support::storage::types::QueryKindTrait) with `Query` type
/// being `Value`.
///
/// ## Example
///
/// The `ValueQuery` implementation accommodates two generic type parameters defined by
/// [`QueryKindTrait`]: `Value` and `OnEmpty`. By default, all FRAME storage items set `OnEmpty` to
/// [`GetDefault`](frame_support::traits::GetDefault). This returns `Default::default()` for `Value`
/// types implementing [`Default`](core::default::Default) when the queried value is absent.
/// However, the behavior for missing values can be altered with a custom `OnEmpty` implementation.
#[doc = docify::embed!("src/storage/types/mod.rs", custom_onempty_implementation)]
/// Using `QueryKind = ValueQuery` in conjunction with `OnEmpty = ADefault` causes storage items to
/// return `42` when values are absent. This is demonstrated in the following example with a
/// [`StorageValue`]. For an overview of FRAME storage items and their use, refer to
/// [crate::pallet_macros::storage].
#[doc = docify::embed!("src/storage/types/mod.rs", test_valuequery_with_custom_onempty)]
pub struct ValueQuery;
impl<Value, OnEmpty> QueryKindTrait<Value, OnEmpty> for ValueQuery
where
	Value: FullCodec + 'static,
	OnEmpty: crate::traits::Get<Value>,
{
	const METADATA: StorageEntryModifierIR = StorageEntryModifierIR::Default;

	type Query = Value;

	fn from_optional_value_to_query(v: Option<Value>) -> Self::Query {
		v.unwrap_or_else(|| OnEmpty::get())
	}

	fn from_query_to_optional_value(v: Self::Query) -> Option<Value> {
		Some(v)
	}
}

/// Build the metadata of a storage.
///
/// Implemented by each of the storage types: value, map, countedmap, doublemap and nmap.
pub trait StorageEntryMetadataBuilder {
	/// Build into `entries` the storage metadata entries of a storage given some `docs`.
	fn build_metadata(doc: Vec<&'static str>, entries: &mut Vec<StorageEntryMetadataIR>);
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		storage::types::ValueQuery,
		traits::{Get, StorageInstance},
	};
	use sp_io::TestExternalities;

	// A custom `OnEmpty` implementation returning 42 consistently
	struct ADefault;
	#[docify::export(custom_onempty_implementation)]
	impl Get<u32> for ADefault {
		fn get() -> u32 {
			42
		}
	}

	struct Prefix;
	impl StorageInstance for Prefix {
		fn pallet_prefix() -> &'static str {
			"test"
		}
		const STORAGE_PREFIX: &'static str = "foo";
	}

	#[docify::export]
	#[test]
	pub fn test_valuequery_with_custom_onempty() {
		type A = StorageValue<Prefix, u32, ValueQuery, ADefault>;
		TestExternalities::default().execute_with(|| {
			// Unset StorageValue should default to 42
			assert_eq!(A::get(), 42);
		});
	}
}
