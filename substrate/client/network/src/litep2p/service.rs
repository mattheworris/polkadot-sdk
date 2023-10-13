// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! `NetworkService` implementation for `litep2p`.

use crate::{
	config::MultiaddrWithPeerId,
	litep2p::shim::notification::peerset::PeersetCommand,
	network_state::NetworkState,
	peer_store::{PeerStoreHandle, PeerStoreProvider},
	service::traits::NotificationSender,
	Event, IfDisconnected, NetworkDHTProvider, NetworkEventStream, NetworkNotification,
	NetworkPeers, NetworkRequest, NetworkSigner, NetworkStateInfo, NetworkStatus,
	NetworkStatusProvider, NotificationSenderError, ProtocolName, RequestFailure, Signature,
};

use codec::DecodeAll;
use futures::{channel::oneshot, stream::BoxStream};
use libp2p::{identity::SigningError, kad::record::Key as KademliaKey, Multiaddr};
use litep2p::crypto::ed25519::Keypair;

use sc_network_common::{
	role::{ObservedRole, Roles},
	types::ReputationChange,
};
use sc_network_types::PeerId;
use sc_utils::mpsc::TracingUnboundedSender;

use std::collections::{HashMap, HashSet};

/// Logging target for the file.
const LOG_TARGET: &str = "sub-libp2p";

/// Commands sent by [`Litep2pNetworkService`] to
/// [`Litep2pNetworkBackend`](super::Litep2pNetworkBackend).
#[derive(Debug)]
pub enum NetworkServiceCommand {
	/// Get value from DHT.
	GetValue {
		/// Record key.
		key: KademliaKey,
	},

	/// Put value to DHT.
	PutValue {
		/// Record key.
		key: KademliaKey,
		/// Record value.
		value: Vec<u8>,
	},

	/// Query network status.
	Status {
		/// `oneshot::Sender` for sending the status.
		tx: oneshot::Sender<NetworkStatus>,
	},

	/// Send request to remote peer.
	StartRequest {
		/// Peer Id.
		peer: PeerId,

		/// Protocol.
		protocol: ProtocolName,

		/// Request.
		request: Vec<u8>,

		/// Oneshot channel for sending the response.
		tx: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,

		/// Whether the dial or immediately fail the request if `peer` is not connected.
		connect: IfDisconnected,
	},

	/// Add `peers` to `protocol`'s reserved set.
	AddPeersToReservedSet {
		/// Protocol.
		protocol: ProtocolName,

		/// Reserved peers.
		peers: HashSet<Multiaddr>,
	},

	/// Report peer.
	ReportPeer {
		/// Peer ID.
		peer: PeerId,

		/// Reputation change.
		cost_benefit: ReputationChange,
	},

	/// Add known address for peer.
	AddKnownAddress {
		/// Peer ID.
		peer: PeerId,

		/// Address.
		address: Multiaddr,
	},

	/// Set reserved peers for `protocol`.
	SetReservedPeers {
		/// Protocol.
		protocol: ProtocolName,

		/// Reserved peers.
		peers: HashSet<Multiaddr>,
	},
}

/// `NetworkService` implementation for `litep2p`.
#[derive(Debug, Clone)]
pub struct Litep2pNetworkService {
	/// Local peer ID.
	local_peer_id: litep2p::PeerId,

	/// The `KeyPair` that defines the `PeerId` of the local node.
	keypair: Keypair,

	/// TX channel for sending commands to [`Litep2pNetworkBackend`](super::Litep2pNetworkBackend).
	cmd_tx: TracingUnboundedSender<NetworkServiceCommand>,

	/// Handle to `PeerStore`.
	peer_store_handle: PeerStoreHandle,

	/// Peerset handles.
	peerset_handles: HashMap<ProtocolName, TracingUnboundedSender<PeersetCommand>>,

	/// Name for the block announce protocol.
	block_announce_protocol: ProtocolName,
}

impl Litep2pNetworkService {
	/// Create new [`Litep2pNetworkService`].
	pub fn new(
		local_peer_id: litep2p::PeerId,
		keypair: Keypair,
		cmd_tx: TracingUnboundedSender<NetworkServiceCommand>,
		peer_store_handle: PeerStoreHandle,
		peerset_handles: HashMap<ProtocolName, TracingUnboundedSender<PeersetCommand>>,
		block_announce_protocol: ProtocolName,
	) -> Self {
		Self {
			local_peer_id,
			keypair,
			cmd_tx,
			peer_store_handle,
			peerset_handles,
			block_announce_protocol,
		}
	}
}

impl NetworkSigner for Litep2pNetworkService {
	fn sign_with_local_identity(&self, _msg: Vec<u8>) -> Result<Signature, SigningError> {
		// TODO(aaro): implement
		let _public_key = self.keypair.public();
		todo!();
		// let bytes = self.keypair.sign(message.as_ref())?;
		// Ok(Signature { public_key, bytes })
	}
}

impl NetworkDHTProvider for Litep2pNetworkService {
	fn get_value(&self, key: &KademliaKey) {
		let _ = self.cmd_tx.unbounded_send(NetworkServiceCommand::GetValue { key: key.clone() });
	}

	fn put_value(&self, key: KademliaKey, value: Vec<u8>) {
		let _ = self.cmd_tx.unbounded_send(NetworkServiceCommand::PutValue { key, value });
	}
}

#[async_trait::async_trait]
impl NetworkStatusProvider for Litep2pNetworkService {
	async fn status(&self) -> Result<NetworkStatus, ()> {
		let (tx, rx) = oneshot::channel();
		self.cmd_tx
			.unbounded_send(NetworkServiceCommand::Status { tx })
			.map_err(|_| ())?;

		rx.await.map_err(|_| ())
	}

	async fn network_state(&self) -> Result<NetworkState, ()> {
		// TODO(aaro): implement
		todo!();
	}
}

// Manual implementation to avoid extra boxing here
impl NetworkPeers for Litep2pNetworkService {
	fn set_authorized_peers(&self, peers: HashSet<PeerId>) {
		match self.peerset_handles.get(&self.block_announce_protocol) {
			None => log::warn!(target: LOG_TARGET, "block announce protocol hasn't been enabled"),
			Some(tx) => {
				let _ = tx.unbounded_send(PeersetCommand::SetReservedPeers { peers });
			},
		}
	}

	fn set_authorized_only(&self, reserved_only: bool) {
		match self.peerset_handles.get(&self.block_announce_protocol) {
			None => log::warn!(target: LOG_TARGET, "block announce protocol hasn't been enabled"),
			Some(tx) => {
				let _ = tx.unbounded_send(PeersetCommand::SetReservedOnly { reserved_only });
			},
		}
	}

	fn add_known_address(&self, peer: PeerId, address: Multiaddr) {
		let _ = self
			.cmd_tx
			.unbounded_send(NetworkServiceCommand::AddKnownAddress { peer, address });
	}

	fn report_peer(&self, peer: PeerId, cost_benefit: ReputationChange) {
		let _ = self
			.cmd_tx
			.unbounded_send(NetworkServiceCommand::ReportPeer { peer, cost_benefit });
	}

	fn disconnect_peer(&self, peer: PeerId, protocol: ProtocolName) {
		match self.peerset_handles.get(&protocol) {
			None => log::warn!(target: LOG_TARGET, "protocol {protocol:?} doens't exist"),
			Some(tx) => {
				let _ = tx.unbounded_send(PeersetCommand::DisconnectPeer { peer });
			},
		}
	}

	fn accept_unreserved_peers(&self) {
		match self.peerset_handles.get(&self.block_announce_protocol) {
			None => log::warn!(target: LOG_TARGET, "block announce protocol hasn't been enabled"),
			Some(tx) => {
				let _ = tx.unbounded_send(PeersetCommand::SetReservedOnly { reserved_only: false });
			},
		}
	}

	fn deny_unreserved_peers(&self) {
		match self.peerset_handles.get(&self.block_announce_protocol) {
			None => log::warn!(target: LOG_TARGET, "block announce protocol hasn't been enabled"),
			Some(tx) => {
				let _ = tx.unbounded_send(PeersetCommand::SetReservedOnly { reserved_only: true });
			},
		}
	}

	fn add_reserved_peer(&self, peer: MultiaddrWithPeerId) -> Result<(), String> {
		log::trace!(target: LOG_TARGET, "add reserved peer {peer:?} for block announce protocol");

		let _ = self.cmd_tx.unbounded_send(NetworkServiceCommand::AddPeersToReservedSet {
			protocol: self.block_announce_protocol.clone(),
			peers: HashSet::from_iter([peer.concat()]),
		});

		Ok(())
	}

	fn remove_reserved_peer(&self, peer: PeerId) {
		log::trace!(target: LOG_TARGET, "remove reserved peer {peer:?} from block announce protocol");

		match self.peerset_handles.get(&self.block_announce_protocol) {
			None => log::warn!(target: LOG_TARGET, "block announce protocol hasn't been enabled"),
			Some(tx) => {
				let _ = tx.unbounded_send(PeersetCommand::RemoveReservedPeers {
					peers: HashSet::from_iter([peer]),
				});
			},
		}
	}

	fn set_reserved_peers(
		&self,
		protocol: ProtocolName,
		peers: HashSet<Multiaddr>,
	) -> Result<(), String> {
		let _ = self
			.cmd_tx
			.unbounded_send(NetworkServiceCommand::SetReservedPeers { protocol, peers });
		Ok(())
	}

	fn add_peers_to_reserved_set(
		&self,
		protocol: ProtocolName,
		peers: HashSet<Multiaddr>,
	) -> Result<(), String> {
		let _ = self
			.cmd_tx
			.unbounded_send(NetworkServiceCommand::AddPeersToReservedSet { protocol, peers });
		Ok(())
	}

	fn remove_peers_from_reserved_set(
		&self,
		protocol: ProtocolName,
		peers: Vec<PeerId>,
	) -> Result<(), String> {
		let Some(tx) = self.peerset_handles.get(&protocol) else {
			log::warn!(target: LOG_TARGET, "protocol {protocol} doesn't exist");
			return Err(String::from("protocol doens't exist"))
		};

		let _ = tx.unbounded_send(PeersetCommand::RemoveReservedPeers {
			peers: peers.into_iter().collect(),
		});
		Ok(())
	}

	fn sync_num_connected(&self) -> usize {
		// TODO(aaro): implement
		todo!();
	}

	fn peer_role(&self, peer: PeerId, handshake: Vec<u8>) -> Option<ObservedRole> {
		match Roles::decode_all(&mut &handshake[..]) {
			Ok(role) => Some(role.into()),
			Err(_) => {
				log::debug!(target: LOG_TARGET, "handshake doesn't contain peer role: {handshake:?}");
				self.peer_store_handle.peer_role(&(peer.into()))
			},
		}
	}
}

impl NetworkEventStream for Litep2pNetworkService {
	fn event_stream(&self, _stream_name: &'static str) -> BoxStream<'static, Event> {
		// TODO(aaro): implement
		todo!();
	}
}

impl NetworkStateInfo for Litep2pNetworkService {
	fn external_addresses(&self) -> Vec<Multiaddr> {
		// TODO(aaro): implement
		todo!();
	}

	fn listen_addresses(&self) -> Vec<Multiaddr> {
		// TODO(aaro): implement
		todo!();
	}

	fn local_peer_id(&self) -> PeerId {
		self.local_peer_id.into()
	}
}

// Manual implementation to avoid extra boxing here
#[async_trait::async_trait]
impl NetworkRequest for Litep2pNetworkService {
	async fn request(
		&self,
		_peer: PeerId,
		_protocol: ProtocolName,
		_request: Vec<u8>,
		_connect: IfDisconnected,
	) -> Result<Vec<u8>, RequestFailure> {
		unimplemented!();
	}

	fn start_request(
		&self,
		peer: PeerId,
		protocol: ProtocolName,
		request: Vec<u8>,
		tx: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
		connect: IfDisconnected,
	) {
		let _ = self.cmd_tx.unbounded_send(NetworkServiceCommand::StartRequest {
			peer,
			protocol,
			request,
			tx,
			connect,
		});
	}
}

// NOTE: not implemented by `litep2p`
impl NetworkNotification for Litep2pNetworkService {
	fn write_notification(&self, _: PeerId, protocol: ProtocolName, _: Vec<u8>) {
		// log::error!(target: LOG_TARGET, "write_notificatoin called for {protocol:?}");
		// unimplemented!();
	}

	fn notification_sender(
		&self,
		_: PeerId,
		_: ProtocolName,
	) -> Result<Box<dyn NotificationSender>, NotificationSenderError> {
		unimplemented!();
	}

	fn set_notification_handshake(&self, _: ProtocolName, _: Vec<u8>) {
		unimplemented!();
	}
}
