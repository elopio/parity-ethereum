// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;
use std::collections::{BTreeMap, BTreeSet};
use parking_lot::RwLock;
use tokio::runtime::TaskExecutor;
use ethkey::{Public, Signature, Random, Generator};
use ethereum_types::{Address, H256};
use key_server_cluster::{Error, NodeId, SessionId, Requester, AclStorage, KeyStorage, KeyServerSet, NodeKeyPair};
use key_server_cluster::cluster_sessions::{ClusterSession, AdminSession, ClusterSessions, SessionIdWithSubSession,
	ClusterSessionsContainer, SERVERS_SET_CHANGE_SESSION_ID, create_cluster_view, AdminSessionCreationData, ClusterSessionsListener};
use key_server_cluster::cluster_sessions_creator::ClusterSessionCreator;
use key_server_cluster::cluster_connections::{ConnectionProvider, ConnectionManager};
use key_server_cluster::cluster_connections_net::{NetConnectionsManager, NetConnectionsContainer};
use key_server_cluster::cluster_message_processor::{MessageProcessor, SessionsMessageProcessor};
use key_server_cluster::message::Message;
use key_server_cluster::generation_session::{SessionImpl as GenerationSession};
use key_server_cluster::decryption_session::{SessionImpl as DecryptionSession};
use key_server_cluster::encryption_session::{SessionImpl as EncryptionSession};
use key_server_cluster::signing_session_ecdsa::{SessionImpl as EcdsaSigningSession};
use key_server_cluster::signing_session_schnorr::{SessionImpl as SchnorrSigningSession};
use key_server_cluster::key_version_negotiation_session::{SessionImpl as KeyVersionNegotiationSession,
	IsolatedSessionTransport as KeyVersionNegotiationSessionTransport, ContinueAction};
use key_server_cluster::connection_trigger::{ConnectionTrigger, SimpleConnectionTrigger, ServersSetChangeSessionCreatorConnector};
use key_server_cluster::connection_trigger_with_migration::ConnectionTriggerWithMigration;

/// Cluster interface for external clients.
pub trait ClusterClient: Send + Sync {
	/// Start new generation session.
	fn new_generation_session(&self, session_id: SessionId, origin: Option<Address>, author: Address, threshold: usize) -> Result<Arc<GenerationSession>, Error>;
	/// Start new encryption session.
	fn new_encryption_session(&self, session_id: SessionId, author: Requester, common_point: Public, encrypted_point: Public) -> Result<Arc<EncryptionSession>, Error>;
	/// Start new decryption session.
	fn new_decryption_session(&self, session_id: SessionId, origin: Option<Address>, requester: Requester, version: Option<H256>, is_shadow_decryption: bool, is_broadcast_decryption: bool) -> Result<Arc<DecryptionSession>, Error>;
	/// Start new Schnorr signing session.
	fn new_schnorr_signing_session(&self, session_id: SessionId, requester: Requester, version: Option<H256>, message_hash: H256) -> Result<Arc<SchnorrSigningSession>, Error>;
	/// Start new ECDSA session.
	fn new_ecdsa_signing_session(&self, session_id: SessionId, requester: Requester, version: Option<H256>, message_hash: H256) -> Result<Arc<EcdsaSigningSession>, Error>;
	/// Start new key version negotiation session.
	fn new_key_version_negotiation_session(&self, session_id: SessionId) -> Result<Arc<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>, Error>;
	/// Start new servers set change session.
	fn new_servers_set_change_session(&self, session_id: Option<SessionId>, migration_id: Option<H256>, new_nodes_set: BTreeSet<NodeId>, old_set_signature: Signature, new_set_signature: Signature) -> Result<Arc<AdminSession>, Error>;

	/// Listen for new generation sessions.
	fn add_generation_listener(&self, listener: Arc<ClusterSessionsListener<GenerationSession>>);
	/// Listen for new decryption sessions.
	fn add_decryption_listener(&self, listener: Arc<ClusterSessionsListener<DecryptionSession>>);
	/// Listen for new key version negotiation sessions.
	fn add_key_version_negotiation_listener(&self, listener: Arc<ClusterSessionsListener<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>>);

	/// Ask node to make 'faulty' generation sessions.
	#[cfg(test)]
	fn make_faulty_generation_sessions(&self);
	/// Get active generation session with given id.
	#[cfg(test)]
	fn generation_session(&self, session_id: &SessionId) -> Option<Arc<GenerationSession>>;
	#[cfg(test)]
	fn is_fully_connected(&self) -> bool;
	/// Try connect to disconnected nodes.
	#[cfg(test)]
	fn connect(&self);
}

/// Cluster access for single session participant.
pub trait Cluster: Send + Sync {
	/// Broadcast message to all other nodes.
	fn broadcast(&self, message: Message) -> Result<(), Error>;
	/// Send message to given node.
	fn send(&self, to: &NodeId, message: Message) -> Result<(), Error>;
	/// Is connected to given node?
	fn is_connected(&self, node: &NodeId) -> bool;
	/// Get a set of connected nodes.
	fn nodes(&self) -> BTreeSet<NodeId>;
	/// Get total count of configured key server nodes (valid at the time of ClusterView creation).
	fn configured_nodes_count(&self) -> usize;
	/// Get total count of connected key server nodes (valid at the time of ClusterView creation).
	fn connected_nodes_count(&self) -> usize;
}

/// Cluster initialization parameters.
#[derive(Clone)]
pub struct ClusterConfiguration {
	/// Number of threads reserved by cluster.
	pub threads: usize,
	/// Allow connecting to 'higher' nodes.
	pub allow_connecting_to_higher_nodes: bool,
	/// KeyPair this node holds.
	pub self_key_pair: Arc<NodeKeyPair>,
	/// Interface to listen to.
	pub listen_address: (String, u16),
	/// Cluster nodes set.
	pub key_server_set: Arc<KeyServerSet>,
	/// Reference to key storage
	pub key_storage: Arc<KeyStorage>,
	/// Reference to ACL storage
	pub acl_storage: Arc<AclStorage>,
	/// Administrator public key.
	pub admin_public: Option<Public>,
	/// Should key servers set change session when servers set changes? This
	/// will only work when servers set is configured using KeyServerSet
	/// contract.
	pub auto_migrate_enabled: bool,
}

/// Network cluster implementation.
pub struct ClusterCore<C: ConnectionManager> {
	/// Cluster data.
	data: Arc<ClusterData<C>>,
}

/// Network cluster client interface implementation.
pub struct ClusterClientImpl<C: ConnectionManager> {
	/// Cluster data.
	data: Arc<ClusterData<C>>,
}

/// Network cluster view. It is a communication channel, required in single session.
pub struct ClusterView {
	configured_nodes_count: usize,
	connected_nodes: BTreeSet<NodeId>,
	connections: Arc<ConnectionProvider>,
	self_key_pair: Arc<NodeKeyPair>,
}

/// Cross-thread shareable cluster data.
pub struct ClusterData<C: ConnectionManager> {
	/// Cluster configuration.
	pub config: ClusterConfiguration,
	/// KeyPair this node holds.
	pub self_key_pair: Arc<NodeKeyPair>,
	/// Connections data.
	pub connections: C,
	/// Active sessions data.
	pub sessions: Arc<ClusterSessions>,
	// Messages processor.
	pub message_processor: Arc<MessageProcessor>,
	pub servers_set_change_creator_connector: Arc<ServersSetChangeSessionCreatorConnector>,
}

pub fn new_network(executor: TaskExecutor, config: ClusterConfiguration) -> Result<Arc<ClusterCore<NetConnectionsManager>>, Error> {
	let connection_trigger: Box<ConnectionTrigger> = match config.auto_migrate_enabled {
		false => Box::new(SimpleConnectionTrigger::new(config.key_server_set.clone(), config.self_key_pair.clone(), config.admin_public.clone())),
		true if config.admin_public.is_none() => Box::new(ConnectionTriggerWithMigration::new(config.key_server_set.clone(), config.self_key_pair.clone())),
		true => return Err(Error::Internal("secret store admininstrator public key is specified with auto-migration enabled".into())),
	};
	let servers_set_change_creator_connector = connection_trigger.servers_set_change_creator_connector();
	let sessions = Arc::new(ClusterSessions::new(&config, servers_set_change_creator_connector.clone()));

	let mut nodes = config.key_server_set.snapshot().current_set;
	let is_isolated = nodes.remove(config.self_key_pair.public()).is_none();
	let connections_data = Arc::new(RwLock::new(NetConnectionsContainer {
		is_isolated,
		nodes,
		connections: BTreeMap::new(),
	}));

	let message_processor = Arc::new(SessionsMessageProcessor::new(
		config.self_key_pair.clone(),
		servers_set_change_creator_connector.clone(),
		sessions.clone(),
		connections_data.clone(),
	));

	let connections = NetConnectionsManager::new(executor.clone(), message_processor.clone(), connection_trigger, connections_data, &config)?;
	connections.start()?;
	ClusterCore::new(sessions, message_processor, connections, servers_set_change_creator_connector, config)
}

#[cfg(test)]
use key_server_cluster::cluster_connections::tests::{MessagesQueue, TestConnections, new_test_cluster};

#[cfg(test)]
pub fn new_test(messages: MessagesQueue, config: ClusterConfiguration) -> Result<Arc<ClusterCore<Arc<TestConnections>>>, Error> {
	let connection_trigger: Box<ConnectionTrigger> = Box::new(SimpleConnectionTrigger::new(config.key_server_set.clone(), config.self_key_pair.clone(), config.admin_public.clone()));
	let servers_set_change_creator_connector = connection_trigger.servers_set_change_creator_connector();
	let sessions = Arc::new(ClusterSessions::new(&config, servers_set_change_creator_connector.clone()));

	let nodes = config.key_server_set.snapshot().current_set;
	let connections = new_test_cluster(messages, config.self_key_pair.public().clone(), nodes.keys().cloned().collect());

	let message_processor = Arc::new(SessionsMessageProcessor::new(
		config.self_key_pair.clone(),
		servers_set_change_creator_connector.clone(),
		sessions.clone(),
		connections.provider(),
	));

	ClusterCore::new(sessions, message_processor, connections, servers_set_change_creator_connector, config)
}

impl<C: ConnectionManager> ClusterCore<C> {
	pub fn new(
		sessions: Arc<ClusterSessions>,
		message_processor: Arc<MessageProcessor>,
		connections: C,
		servers_set_change_creator_connector: Arc<ServersSetChangeSessionCreatorConnector>,
		config: ClusterConfiguration,
	) -> Result<Arc<Self>, Error> {
		let data = ClusterData::new(config, connections, sessions, message_processor, servers_set_change_creator_connector);

		Ok(Arc::new(ClusterCore {
			data: data,
		}))
	}

	/// Create new client interface.
	pub fn client(&self) -> Arc<ClusterClient> {
		Arc::new(ClusterClientImpl::new(self.data.clone()))
	}

	/// Run cluster.
	pub fn run(&self) -> Result<(), Error> {
		self.data.connections.connect();
		Ok(())
	}
}

impl<C: ConnectionManager> ClusterData<C> {
	pub fn new(config: ClusterConfiguration, connections: C, sessions: Arc<ClusterSessions>, message_processor: Arc<MessageProcessor>, servers_set_change_creator_connector: Arc<ServersSetChangeSessionCreatorConnector>) -> Arc<Self> {
		Arc::new(ClusterData {
			self_key_pair: config.self_key_pair.clone(),
			connections: connections,
			sessions: sessions.clone(),
			config: config,
			message_processor,
			servers_set_change_creator_connector
		})
	}
}

impl ClusterView {
	pub fn new(self_key_pair: Arc<NodeKeyPair>, connections: Arc<ConnectionProvider>, nodes: BTreeSet<NodeId>, configured_nodes_count: usize) -> Self {
		ClusterView {
			configured_nodes_count: configured_nodes_count,
			connected_nodes: nodes,
			connections,
			self_key_pair,
		}
	}
}

impl Cluster for ClusterView {
	fn broadcast(&self, message: Message) -> Result<(), Error> {
		for node in self.connected_nodes.iter().filter(|n| *n != self.self_key_pair.public()) {
			trace!(target: "secretstore_net", "{}: sent message {} to {}", self.self_key_pair.public(), message, node);
			let connection = self.connections.connection(node).ok_or(Error::NodeDisconnected)?;
			connection.send_message(message.clone());
		}
		Ok(())
	}

	fn send(&self, to: &NodeId, message: Message) -> Result<(), Error> {
		trace!(target: "secretstore_net", "{}: sent message {} to {}", self.self_key_pair.public(), message, to);
		let connection = self.connections.connection(to).ok_or(Error::NodeDisconnected)?;
		connection.send_message(message);
		Ok(())
	}

	fn is_connected(&self, node: &NodeId) -> bool {
		self.connected_nodes.contains(node)
	}

	fn nodes(&self) -> BTreeSet<NodeId> {
		self.connected_nodes.clone()
	}

	fn configured_nodes_count(&self) -> usize {
		self.configured_nodes_count
	}

	fn connected_nodes_count(&self) -> usize {
		self.connected_nodes.len()
	}
}

impl<C: ConnectionManager> ClusterClientImpl<C> {
	pub fn new(data: Arc<ClusterData<C>>) -> Self {
		ClusterClientImpl {
			data: data,
		}
	}

	fn create_key_version_negotiation_session(&self, session_id: SessionId) -> Result<Arc<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>, Error> {
		let mut connected_nodes = self.data.connections.provider().connected_nodes()?;
		connected_nodes.insert(self.data.self_key_pair.public().clone());

		let access_key = Random.generate()?.secret().clone();
		let session_id = SessionIdWithSubSession::new(session_id, access_key);
		let cluster = create_cluster_view(self.data.self_key_pair.clone(), self.data.connections.provider(), false)?;
		let session = self.data.sessions.negotiation_sessions.insert(cluster, self.data.self_key_pair.public().clone(), session_id.clone(), None, false, None)?;
		match session.initialize(connected_nodes) {
			Ok(()) => Ok(session),
			Err(error) => {
				self.data.sessions.negotiation_sessions.remove(&session.id());
				Err(error)
			}
		}
	}
}

impl<C: ConnectionManager> ClusterClient for ClusterClientImpl<C> {
	fn new_generation_session(&self, session_id: SessionId, origin: Option<Address>, author: Address, threshold: usize) -> Result<Arc<GenerationSession>, Error> {
		let mut connected_nodes = self.data.connections.provider().connected_nodes()?;
		connected_nodes.insert(self.data.self_key_pair.public().clone());

		let cluster = create_cluster_view(self.data.self_key_pair.clone(), self.data.connections.provider(), true)?;
		let session = self.data.sessions.generation_sessions.insert(cluster, self.data.self_key_pair.public().clone(), session_id, None, false, None)?;
		process_initialization_result(
			session.initialize(origin, author, false, threshold, connected_nodes.into()),
			session, &self.data.sessions.generation_sessions)
	}

	fn new_encryption_session(&self, session_id: SessionId, requester: Requester, common_point: Public, encrypted_point: Public) -> Result<Arc<EncryptionSession>, Error> {
		let mut connected_nodes = self.data.connections.provider().connected_nodes()?;
		connected_nodes.insert(self.data.self_key_pair.public().clone());

		let cluster = create_cluster_view(self.data.self_key_pair.clone(), self.data.connections.provider(), true)?;
		let session = self.data.sessions.encryption_sessions.insert(cluster, self.data.self_key_pair.public().clone(), session_id, None, false, None)?;
		process_initialization_result(
			session.initialize(requester, common_point, encrypted_point),
			session, &self.data.sessions.encryption_sessions)
	}

	fn new_decryption_session(&self, session_id: SessionId, origin: Option<Address>, requester: Requester, version: Option<H256>, is_shadow_decryption: bool, is_broadcast_decryption: bool) -> Result<Arc<DecryptionSession>, Error> {
		let mut connected_nodes = self.data.connections.provider().connected_nodes()?;
		connected_nodes.insert(self.data.self_key_pair.public().clone());

		let access_key = Random.generate()?.secret().clone();
		let session_id = SessionIdWithSubSession::new(session_id, access_key);
		let cluster = create_cluster_view(self.data.self_key_pair.clone(), self.data.connections.provider(), false)?;
		let session = self.data.sessions.decryption_sessions.insert(cluster, self.data.self_key_pair.public().clone(),
			session_id.clone(), None, false, Some(requester))?;

		let initialization_result = match version {
			Some(version) => session.initialize(origin, version, is_shadow_decryption, is_broadcast_decryption),
			None => {
				self.create_key_version_negotiation_session(session_id.id.clone())
					.map(|version_session| {
						version_session.set_continue_action(ContinueAction::Decrypt(session.clone(), origin, is_shadow_decryption, is_broadcast_decryption));
						self.data.message_processor.try_continue_session(Some(version_session));
					})
			},
		};

		process_initialization_result(
			initialization_result,
			session, &self.data.sessions.decryption_sessions)
	}

	fn new_schnorr_signing_session(&self, session_id: SessionId, requester: Requester, version: Option<H256>, message_hash: H256) -> Result<Arc<SchnorrSigningSession>, Error> {
		let mut connected_nodes = self.data.connections.provider().connected_nodes()?;
		connected_nodes.insert(self.data.self_key_pair.public().clone());

		let access_key = Random.generate()?.secret().clone();
		let session_id = SessionIdWithSubSession::new(session_id, access_key);
		let cluster = create_cluster_view(self.data.self_key_pair.clone(), self.data.connections.provider(), false)?;
		let session = self.data.sessions.schnorr_signing_sessions.insert(cluster, self.data.self_key_pair.public().clone(), session_id.clone(), None, false, Some(requester))?;

		let initialization_result = match version {
			Some(version) => session.initialize(version, message_hash),
			None => {
				self.create_key_version_negotiation_session(session_id.id.clone())
					.map(|version_session| {
						version_session.set_continue_action(ContinueAction::SchnorrSign(session.clone(), message_hash));
						self.data.message_processor.try_continue_session(Some(version_session));
					})
			},
		};

		process_initialization_result(
			initialization_result,
			session, &self.data.sessions.schnorr_signing_sessions)
	}

	fn new_ecdsa_signing_session(&self, session_id: SessionId, requester: Requester, version: Option<H256>, message_hash: H256) -> Result<Arc<EcdsaSigningSession>, Error> {
		let mut connected_nodes = self.data.connections.provider().connected_nodes()?;
		connected_nodes.insert(self.data.self_key_pair.public().clone());

		let access_key = Random.generate()?.secret().clone();
		let session_id = SessionIdWithSubSession::new(session_id, access_key);
		let cluster = create_cluster_view(self.data.self_key_pair.clone(), self.data.connections.provider(), false)?;
		let session = self.data.sessions.ecdsa_signing_sessions.insert(cluster, self.data.self_key_pair.public().clone(), session_id.clone(), None, false, Some(requester))?;

		let initialization_result = match version {
			Some(version) => session.initialize(version, message_hash),
			None => {
				self.create_key_version_negotiation_session(session_id.id.clone())
					.map(|version_session| {
						version_session.set_continue_action(ContinueAction::EcdsaSign(session.clone(), message_hash));
						self.data.message_processor.try_continue_session(Some(version_session));
					})
			},
		};

		process_initialization_result(
			initialization_result,
			session, &self.data.sessions.ecdsa_signing_sessions)
	}

	fn new_key_version_negotiation_session(&self, session_id: SessionId) -> Result<Arc<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>, Error> {
		let session = self.create_key_version_negotiation_session(session_id)?;
		Ok(session)
	}

	fn new_servers_set_change_session(&self, session_id: Option<SessionId>, migration_id: Option<H256>, new_nodes_set: BTreeSet<NodeId>, old_set_signature: Signature, new_set_signature: Signature) -> Result<Arc<AdminSession>, Error> {
		new_servers_set_change_session(
			self.data.self_key_pair.clone(),
			&self.data.sessions,
			self.data.connections.provider(),
			self.data.servers_set_change_creator_connector.clone(),
			ServersSetChangeParams {
				session_id,
				migration_id,
				new_nodes_set,
				old_set_signature,
				new_set_signature,
			})
	}

	fn add_generation_listener(&self, listener: Arc<ClusterSessionsListener<GenerationSession>>) {
		self.data.sessions.generation_sessions.add_listener(listener);
	}

	fn add_decryption_listener(&self, listener: Arc<ClusterSessionsListener<DecryptionSession>>) {
		self.data.sessions.decryption_sessions.add_listener(listener);
	}

	fn add_key_version_negotiation_listener(&self, listener: Arc<ClusterSessionsListener<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>>) {
		self.data.sessions.negotiation_sessions.add_listener(listener);
	}

	#[cfg(test)]
	fn make_faulty_generation_sessions(&self) {
		self.data.sessions.make_faulty_generation_sessions();
	}

	#[cfg(test)]
	fn generation_session(&self, session_id: &SessionId) -> Option<Arc<GenerationSession>> {
		self.data.sessions.generation_sessions.get(session_id, false)
	}

	#[cfg(test)]
	fn is_fully_connected(&self) -> bool {
		self.data.connections.provider().disconnected_nodes().is_empty()
	}

	#[cfg(test)]
	fn connect(&self) {
		self.data.connections.connect()
	}
}

pub struct ServersSetChangeParams {
	pub session_id: Option<SessionId>,
	pub migration_id: Option<H256>,
	pub new_nodes_set: BTreeSet<NodeId>,
	pub old_set_signature: Signature,
	pub new_set_signature: Signature,
}

pub fn new_servers_set_change_session(
	self_key_pair: Arc<NodeKeyPair>,
	sessions: &ClusterSessions,
	connections: Arc<ConnectionProvider>,
	servers_set_change_creator_connector: Arc<ServersSetChangeSessionCreatorConnector>,
	params: ServersSetChangeParams,
) -> Result<Arc<AdminSession>, Error> {
	let session_id = match params.session_id {
		Some(session_id) if session_id == *SERVERS_SET_CHANGE_SESSION_ID => session_id,
		Some(_) => return Err(Error::InvalidMessage),
		None => *SERVERS_SET_CHANGE_SESSION_ID,
	};

	let cluster = create_cluster_view(self_key_pair.clone(), connections, true)?;
	let creation_data = Some(AdminSessionCreationData::ServersSetChange(params.migration_id, params.new_nodes_set.clone()));
	let session = sessions.admin_sessions.insert(cluster, self_key_pair.public().clone(), session_id, None, true, creation_data)?;
	let initialization_result = session.as_servers_set_change().expect("servers set change session is created; qed")
		.initialize(params.new_nodes_set, params.old_set_signature, params.new_set_signature);

	if initialization_result.is_ok() {
		servers_set_change_creator_connector.set_key_servers_set_change_session(session.clone());
	}

	process_initialization_result(
		initialization_result,
		session, &sessions.admin_sessions)
}

fn process_initialization_result<S: ClusterSession, SC: ClusterSessionCreator<S, D>, D>(result: Result<(), Error>, session: Arc<S>, sessions: &ClusterSessionsContainer<S, SC, D>) -> Result<Arc<S>, Error> {
	match result {
		Ok(()) if session.is_finished() => {
			sessions.remove(&session.id());
			Ok(session)
		},
		Ok(()) => Ok(session),
		Err(error) => {
			sessions.remove(&session.id());
			Err(error)
		},
	}
}

#[cfg(test)]
pub mod tests {
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::collections::{HashMap, BTreeSet, VecDeque};
	use parking_lot::{Mutex, RwLock};
	use ethereum_types::{Address, H256};
	use ethkey::{Random, Generator, Public, Signature, sign};
	use key_server_cluster::{NodeId, SessionId, Requester, Error, DummyAclStorage, DummyKeyStorage,
		MapKeyServerSet, PlainNodeKeyPair};
	use key_server_cluster::message::Message;
	use key_server_cluster::cluster::{new_test, Cluster, ClusterCore, ClusterConfiguration, ClusterClient};
	use key_server_cluster::cluster_connections::ConnectionManager;
	use key_server_cluster::cluster_connections::tests::{MessagesQueue, TestConnections};
	use key_server_cluster::cluster_sessions::{ClusterSession, AdminSession, ClusterSessionsListener};
	use key_server_cluster::generation_session::{SessionImpl as GenerationSession, SessionState as GenerationSessionState};
	use key_server_cluster::decryption_session::{SessionImpl as DecryptionSession};
	use key_server_cluster::encryption_session::{SessionImpl as EncryptionSession};
	use key_server_cluster::signing_session_ecdsa::{SessionImpl as EcdsaSigningSession};
	use key_server_cluster::signing_session_schnorr::{SessionImpl as SchnorrSigningSession};
	use key_server_cluster::key_version_negotiation_session::{SessionImpl as KeyVersionNegotiationSession,
		IsolatedSessionTransport as KeyVersionNegotiationSessionTransport};

	#[derive(Default)]
	pub struct DummyClusterClient {
		pub generation_requests_count: AtomicUsize,
	}

	#[derive(Debug)]
	pub struct DummyCluster {
		id: NodeId,
		data: RwLock<DummyClusterData>,
	}

	#[derive(Debug, Default)]
	struct DummyClusterData {
		nodes: BTreeSet<NodeId>,
		messages: VecDeque<(NodeId, Message)>,
	}

	impl ClusterClient for DummyClusterClient {
		fn new_generation_session(&self, _session_id: SessionId, _origin: Option<Address>, _author: Address, _threshold: usize) -> Result<Arc<GenerationSession>, Error> {
			self.generation_requests_count.fetch_add(1, Ordering::Relaxed);
			Err(Error::Internal("test-error".into()))
		}
		fn new_encryption_session(&self, _session_id: SessionId, _requester: Requester, _common_point: Public, _encrypted_point: Public) -> Result<Arc<EncryptionSession>, Error> { unimplemented!("test-only") }
		fn new_decryption_session(&self, _session_id: SessionId, _origin: Option<Address>, _requester: Requester, _version: Option<H256>, _is_shadow_decryption: bool, _is_broadcast_session: bool) -> Result<Arc<DecryptionSession>, Error> { unimplemented!("test-only") }
		fn new_schnorr_signing_session(&self, _session_id: SessionId, _requester: Requester, _version: Option<H256>, _message_hash: H256) -> Result<Arc<SchnorrSigningSession>, Error> { unimplemented!("test-only") }
		fn new_ecdsa_signing_session(&self, _session_id: SessionId, _requester: Requester, _version: Option<H256>, _message_hash: H256) -> Result<Arc<EcdsaSigningSession>, Error> { unimplemented!("test-only") }

		fn new_key_version_negotiation_session(&self, _session_id: SessionId) -> Result<Arc<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>, Error> { unimplemented!("test-only") }
		fn new_servers_set_change_session(&self, _session_id: Option<SessionId>, _migration_id: Option<H256>, _new_nodes_set: BTreeSet<NodeId>, _old_set_signature: Signature, _new_set_signature: Signature) -> Result<Arc<AdminSession>, Error> { unimplemented!("test-only") }

		fn add_generation_listener(&self, _listener: Arc<ClusterSessionsListener<GenerationSession>>) {}
		fn add_decryption_listener(&self, _listener: Arc<ClusterSessionsListener<DecryptionSession>>) {}
		fn add_key_version_negotiation_listener(&self, _listener: Arc<ClusterSessionsListener<KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>>>) {}

		fn make_faulty_generation_sessions(&self) { unimplemented!("test-only") }
		fn generation_session(&self, _session_id: &SessionId) -> Option<Arc<GenerationSession>> { unimplemented!("test-only") }
		fn is_fully_connected(&self) -> bool { true }
		fn connect(&self) {}
	}

	impl DummyCluster {
		pub fn new(id: NodeId) -> Self {
			DummyCluster {
				id: id,
				data: RwLock::new(DummyClusterData::default())
			}
		}

		pub fn node(&self) -> NodeId {
			self.id.clone()
		}

		pub fn add_node(&self, node: NodeId) {
			self.data.write().nodes.insert(node);
		}

		pub fn add_nodes<I: Iterator<Item=NodeId>>(&self, nodes: I) {
			self.data.write().nodes.extend(nodes)
		}

		pub fn remove_node(&self, node: &NodeId) {
			self.data.write().nodes.remove(node);
		}

		pub fn take_message(&self) -> Option<(NodeId, Message)> {
			self.data.write().messages.pop_front()
		}
	}

	impl Cluster for DummyCluster {
		fn broadcast(&self, message: Message) -> Result<(), Error> {
			let mut data = self.data.write();
			let all_nodes: Vec<_> = data.nodes.iter().cloned().filter(|n| n != &self.id).collect();
			for node in all_nodes {
				data.messages.push_back((node, message.clone()));
			}
			Ok(())
		}

		fn send(&self, to: &NodeId, message: Message) -> Result<(), Error> {
			debug_assert!(&self.id != to);
			self.data.write().messages.push_back((to.clone(), message));
			Ok(())
		}

		fn is_connected(&self, node: &NodeId) -> bool {
			let data = self.data.read();
			&self.id == node || data.nodes.contains(node)
		}

		fn nodes(&self) -> BTreeSet<NodeId> {
			self.data.read().nodes.iter().cloned().collect()
		}

		fn configured_nodes_count(&self) -> usize {
			self.data.read().nodes.len()
		}

		fn connected_nodes_count(&self) -> usize {
			self.data.read().nodes.len()
		}
	}

	/// Loops until `predicate` returns `true` or `timeout` has elapsed.
	pub fn loop_until<F>(messages: MessagesQueue, clusters: &[Arc<ClusterCore<Arc<TestConnections>>>], predicate: F)
		where F: Fn() -> bool
	{
		let clusters: HashMap<_, _> = clusters.iter().cloned().map(|c| (c.data.self_key_pair.public().clone(), c)).collect();
		while !predicate() {
			let (from, to, message) = match messages.lock().pop_front() {
				Some(message) => message,
				None => panic!("no result"),
			};

			let cluster_data = &clusters[&to].data;
			let connection = cluster_data.connections.provider().connection(&from).unwrap();
			cluster_data.message_processor.process_connection_message(connection, message);
		}
	}

	pub fn make_clusters(num_nodes: usize) -> (MessagesQueue, Vec<Arc<ClusterCore<Arc<TestConnections>>>>) {
		let ports_begin = 0;
		let messages = Arc::new(Mutex::new(VecDeque::new()));
		let key_pairs: Vec<_> = (0..num_nodes).map(|_| Random.generate().unwrap()).collect();
		let cluster_params: Vec<_> = (0..num_nodes).map(|i| ClusterConfiguration {
			threads: 1,
			self_key_pair: Arc::new(PlainNodeKeyPair::new(key_pairs[i].clone())),
			listen_address: ("127.0.0.1".to_owned(), ports_begin + i as u16),
			key_server_set: Arc::new(MapKeyServerSet::new(false, key_pairs.iter().enumerate()
				.map(|(j, kp)| (kp.public().clone(), format!("127.0.0.1:{}", ports_begin + j as u16).parse().unwrap()))
				.collect())),
			allow_connecting_to_higher_nodes: false,
			key_storage: Arc::new(DummyKeyStorage::default()),
			acl_storage: Arc::new(DummyAclStorage::default()),
			admin_public: None,
			auto_migrate_enabled: false,
		}).collect();
		let clusters = cluster_params.into_iter()
			.map(|params| new_test(messages.clone(), params).unwrap())
			.collect();

		(messages, clusters)
	}

	#[test]
	fn cluster_wont_start_generation_session_if_not_fully_connected() {
		let (_, clusters) = make_clusters(3);
		clusters[0].data.connections.disconnect(clusters[0].data.self_key_pair.public().clone());
		match clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 1) {
			Err(Error::NodeDisconnected) => (),
			Err(e) => panic!("unexpected error {:?}", e),
			_ => panic!("unexpected success"),
		}
	}

	#[test]
	fn error_in_generation_session_broadcasted_to_all_other_nodes() {
		//::logger::init_log();
		let (messages, clusters) = make_clusters(3);

		// ask one of nodes to produce faulty generation sessions
		clusters[1].client().make_faulty_generation_sessions();

		// start && wait for generation session to fail
		let session = clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 1).unwrap();
		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || session_clone.joint_public_and_secret().is_some()
			&& clusters_clone[0].client().generation_session(&SessionId::default()).is_none());
		assert!(session.joint_public_and_secret().unwrap().is_err());

		// check that faulty session is either removed from all nodes, or nonexistent (already removed)
		for i in 1..3 {
			if let Some(session) = clusters[i].client().generation_session(&SessionId::default()) {
				let session_clone = session.clone();
				let clusters_clone = clusters.clone();
				// wait for both session completion && session removal (session completion event is fired
				// before session is removed from its own container by cluster)
				loop_until(messages.clone(), &clusters, move || session_clone.joint_public_and_secret().is_some()
					&& clusters_clone[i].client().generation_session(&SessionId::default()).is_none());
				assert!(session.joint_public_and_secret().unwrap().is_err());
			}
		}
	}

	#[test]
	fn generation_session_completion_signalled_if_failed_on_master() {
		//::logger::init_log();
		let (messages, clusters) = make_clusters(3);

		// ask one of nodes to produce faulty generation sessions
		clusters[0].client().make_faulty_generation_sessions();

		// start && wait for generation session to fail
		let session = clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 1).unwrap();
		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || session_clone.joint_public_and_secret().is_some()
			&& clusters_clone[0].client().generation_session(&SessionId::default()).is_none());
		assert!(session.joint_public_and_secret().unwrap().is_err());

		// check that faulty session is either removed from all nodes, or nonexistent (already removed)
		for i in 1..3 {
			if let Some(session) = clusters[i].client().generation_session(&SessionId::default()) {
				let session_clone = session.clone();
				let clusters_clone = clusters.clone();
				// wait for both session completion && session removal (session completion event is fired
				// before session is removed from its own container by cluster)
				loop_until(messages.clone(), &clusters, move || session_clone.joint_public_and_secret().is_some()
					&& clusters_clone[i].client().generation_session(&SessionId::default()).is_none());
				assert!(session.joint_public_and_secret().unwrap().is_err());
			}
		}
	}

	#[test]
	fn generation_session_is_removed_when_succeeded() {
		//::logger::init_log();
		let (messages, clusters) = make_clusters(3);

		// start && wait for generation session to complete
		let session = clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 1).unwrap();
		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || (session_clone.state() == GenerationSessionState::Finished
			|| session_clone.state() == GenerationSessionState::Failed)
			&& clusters_clone[0].client().generation_session(&SessionId::default()).is_none());
		assert!(session.joint_public_and_secret().unwrap().is_ok());

		// check that on non-master nodes session is either:
		// already removed
		// or it is removed right after completion
		for i in 1..3 {
			if let Some(session) = clusters[i].client().generation_session(&SessionId::default()) {
				// run to completion if completion message is still on the way
				// AND check that it is actually removed from cluster sessions
				let session_clone = session.clone();
				let clusters_clone = clusters.clone();
				loop_until(messages.clone(), &clusters, move || (session_clone.state() == GenerationSessionState::Finished
					|| session_clone.state() == GenerationSessionState::Failed)
					&& clusters_clone[i].client().generation_session(&SessionId::default()).is_none());
			}
		}
	}

	#[test]
	fn sessions_are_removed_when_initialization_fails() {
		let (_, clusters) = make_clusters(3);

		// generation session
		{
			// try to start generation session => fail in initialization
			assert_eq!(clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 100).map(|_| ()),
				Err(Error::NotEnoughNodesForThreshold));

			// try to start generation session => fails in initialization
			assert_eq!(clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 100).map(|_| ()),
				Err(Error::NotEnoughNodesForThreshold));

			assert!(clusters[0].data.sessions.generation_sessions.is_empty());
		}

		// decryption session
		{
			// try to start decryption session => fails in initialization
			assert_eq!(clusters[0].client().new_decryption_session(Default::default(), Default::default(), Default::default(), Some(Default::default()), false, false).map(|_| ()),
				Err(Error::InvalidMessage));

			// try to start generation session => fails in initialization
			assert_eq!(clusters[0].client().new_decryption_session(Default::default(), Default::default(), Default::default(), Some(Default::default()), false, false).map(|_| ()),
				Err(Error::InvalidMessage));

			assert!(clusters[0].data.sessions.decryption_sessions.is_empty());
			assert!(clusters[0].data.sessions.negotiation_sessions.is_empty());
		}
	}

	#[test]
	fn schnorr_signing_session_completes_if_node_does_not_have_a_share() {
		//::logger::init_log();
		let (messages, clusters) = make_clusters(3);

		// start && wait for generation session to complete
		let session = clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 1).unwrap();
		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || (session_clone.state() == GenerationSessionState::Finished
			|| session_clone.state() == GenerationSessionState::Failed)
			&& clusters_clone[0].client().generation_session(&SessionId::default()).is_none());
		assert!(session.joint_public_and_secret().unwrap().is_ok());

		// now remove share from node2
		assert!((0..3).all(|i| clusters[i].data.sessions.generation_sessions.is_empty()));
		clusters[2].data.config.key_storage.remove(&Default::default()).unwrap();

		// and try to sign message with generated key
		let signature = sign(Random.generate().unwrap().secret(), &Default::default()).unwrap();
		let session0 = clusters[0].client().new_schnorr_signing_session(Default::default(), signature.into(), None, Default::default()).unwrap();
		let session = clusters[0].data.sessions.schnorr_signing_sessions.first().unwrap();

		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || session_clone.is_finished() && (0..3).all(|i|
			clusters_clone[i].data.sessions.schnorr_signing_sessions.is_empty()));
		session0.wait().unwrap();

		// and try to sign message with generated key using node that has no key share
		let signature = sign(Random.generate().unwrap().secret(), &Default::default()).unwrap();
		let session2 = clusters[2].client().new_schnorr_signing_session(Default::default(), signature.into(), None, Default::default()).unwrap();
		let session = clusters[2].data.sessions.schnorr_signing_sessions.first().unwrap();

		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || session_clone.is_finished()  && (0..3).all(|i|
			clusters_clone[i].data.sessions.schnorr_signing_sessions.is_empty()));
		session2.wait().unwrap();

		// now remove share from node1
		clusters[1].data.config.key_storage.remove(&Default::default()).unwrap();

		// and try to sign message with generated key
		let signature = sign(Random.generate().unwrap().secret(), &Default::default()).unwrap();
		let session1 = clusters[0].client().new_schnorr_signing_session(Default::default(), signature.into(), None, Default::default()).unwrap();
		let session = clusters[0].data.sessions.schnorr_signing_sessions.first().unwrap();

		let session = session.clone();
		loop_until(messages, &clusters, move || session.is_finished());
		session1.wait().unwrap_err();
	}

	#[test]
	fn ecdsa_signing_session_completes_if_node_does_not_have_a_share() {
		//::logger::init_log();
		let (messages, clusters) = make_clusters(4);

		// start && wait for generation session to complete
		let session = clusters[0].client().new_generation_session(SessionId::default(), Default::default(), Default::default(), 1).unwrap();
		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || (session_clone.state() == GenerationSessionState::Finished
			|| session_clone.state() == GenerationSessionState::Failed)
			&& clusters_clone[0].client().generation_session(&SessionId::default()).is_none());
		assert!(session.joint_public_and_secret().unwrap().is_ok());

		// now remove share from node2
		assert!((0..3).all(|i| clusters[i].data.sessions.generation_sessions.is_empty()));
		clusters[2].data.config.key_storage.remove(&Default::default()).unwrap();

		// and try to sign message with generated key
		let signature = sign(Random.generate().unwrap().secret(), &Default::default()).unwrap();
		let session0 = clusters[0].client().new_ecdsa_signing_session(Default::default(), signature.into(), None, H256::random()).unwrap();
		let session = clusters[0].data.sessions.ecdsa_signing_sessions.first().unwrap();

		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || session_clone.is_finished() && (0..3).all(|i|
			clusters_clone[i].data.sessions.ecdsa_signing_sessions.is_empty()));
		session0.wait().unwrap();

		// and try to sign message with generated key using node that has no key share
		let signature = sign(Random.generate().unwrap().secret(), &Default::default()).unwrap();
		let session2 = clusters[2].client().new_ecdsa_signing_session(Default::default(), signature.into(), None, H256::random()).unwrap();
		let session = clusters[2].data.sessions.ecdsa_signing_sessions.first().unwrap();
		let session_clone = session.clone();
		let clusters_clone = clusters.clone();
		loop_until(messages.clone(), &clusters, move || session_clone.is_finished()  && (0..3).all(|i|
			clusters_clone[i].data.sessions.ecdsa_signing_sessions.is_empty()));
		session2.wait().unwrap();

		// now remove share from node1
		clusters[1].data.config.key_storage.remove(&Default::default()).unwrap();

		// and try to sign message with generated key
		let signature = sign(Random.generate().unwrap().secret(), &Default::default()).unwrap();
		let session1 = clusters[0].client().new_ecdsa_signing_session(Default::default(), signature.into(), None, H256::random()).unwrap();
		let session = clusters[0].data.sessions.ecdsa_signing_sessions.first().unwrap();
		loop_until(messages.clone(), &clusters, move || session.is_finished());
		session1.wait().unwrap_err();
	}
}
