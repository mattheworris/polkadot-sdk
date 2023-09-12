(function() {var implementors = {
"cumulus_client_consensus_common":[["impl&lt;Block: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>&gt; <a class=\"trait\" href=\"sc_consensus/import_queue/trait.Verifier.html\" title=\"trait sc_consensus::import_queue::Verifier\">Verifier</a>&lt;Block&gt; for <a class=\"struct\" href=\"cumulus_client_consensus_common/import_queue/struct.VerifyNothing.html\" title=\"struct cumulus_client_consensus_common::import_queue::VerifyNothing\">VerifyNothing</a>"]],
"cumulus_client_consensus_relay_chain":[["impl&lt;Client, Block, CIDP&gt; <a class=\"trait\" href=\"sc_consensus/import_queue/trait.Verifier.html\" title=\"trait sc_consensus::import_queue::Verifier\">Verifier</a>&lt;Block&gt; for <a class=\"struct\" href=\"cumulus_client_consensus_relay_chain/struct.Verifier.html\" title=\"struct cumulus_client_consensus_relay_chain::Verifier\">Verifier</a>&lt;Client, Block, CIDP&gt;<span class=\"where fmt-newline\">where\n    Block: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>,\n    Client: <a class=\"trait\" href=\"sp_api/trait.ProvideRuntimeApi.html\" title=\"trait sp_api::ProvideRuntimeApi\">ProvideRuntimeApi</a>&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    &lt;Client as <a class=\"trait\" href=\"sp_api/trait.ProvideRuntimeApi.html\" title=\"trait sp_api::ProvideRuntimeApi\">ProvideRuntimeApi</a>&lt;Block&gt;&gt;::<a class=\"associatedtype\" href=\"sp_api/trait.ProvideRuntimeApi.html#associatedtype.Api\" title=\"type sp_api::ProvideRuntimeApi::Api\">Api</a>: <a class=\"trait\" href=\"sp_block_builder/trait.BlockBuilder.html\" title=\"trait sp_block_builder::BlockBuilder\">BlockBuilderApi</a>&lt;Block&gt;,\n    CIDP: <a class=\"trait\" href=\"sp_inherents/client_side/trait.CreateInherentDataProviders.html\" title=\"trait sp_inherents::client_side::CreateInherentDataProviders\">CreateInherentDataProviders</a>&lt;Block, <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/std/primitive.unit.html\">()</a>&gt;,</span>"]],
"polkadot_parachain":[["impl&lt;Client, AuraId&gt; <a class=\"trait\" href=\"sc_consensus/import_queue/trait.Verifier.html\" title=\"trait sc_consensus::import_queue::Verifier\">Verifier</a>&lt;<a class=\"struct\" href=\"sp_runtime/generic/block/struct.Block.html\" title=\"struct sp_runtime::generic::block::Block\">Block</a>&lt;<a class=\"struct\" href=\"sp_runtime/generic/header/struct.Header.html\" title=\"struct sp_runtime::generic::header::Header\">Header</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/std/primitive.u32.html\">u32</a>, <a class=\"struct\" href=\"sp_runtime/traits/struct.BlakeTwo256.html\" title=\"struct sp_runtime::traits::BlakeTwo256\">BlakeTwo256</a>&gt;, <a class=\"struct\" href=\"sp_runtime/struct.OpaqueExtrinsic.html\" title=\"struct sp_runtime::OpaqueExtrinsic\">OpaqueExtrinsic</a>&gt;&gt; for <a class=\"struct\" href=\"polkadot_parachain/service/struct.Verifier.html\" title=\"struct polkadot_parachain::service::Verifier\">Verifier</a>&lt;Client, AuraId&gt;<span class=\"where fmt-newline\">where\n    Client: <a class=\"trait\" href=\"sp_api/trait.ProvideRuntimeApi.html\" title=\"trait sp_api::ProvideRuntimeApi\">ProvideRuntimeApi</a>&lt;<a class=\"type\" href=\"polkadot_parachain/service/type.Block.html\" title=\"type polkadot_parachain::service::Block\">Block</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    Client::<a class=\"associatedtype\" href=\"sp_api/trait.ProvideRuntimeApi.html#associatedtype.Api\" title=\"type sp_api::ProvideRuntimeApi::Api\">Api</a>: <a class=\"trait\" href=\"sp_consensus_aura/trait.AuraApi.html\" title=\"trait sp_consensus_aura::AuraApi\">AuraApi</a>&lt;<a class=\"type\" href=\"polkadot_parachain/service/type.Block.html\" title=\"type polkadot_parachain::service::Block\">Block</a>, AuraId&gt;,\n    AuraId: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + Codec,</span>"]],
"sc_consensus_aura":[["impl&lt;B: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>, C, P, CIDP&gt; Verifier&lt;B&gt; for <a class=\"struct\" href=\"sc_consensus_aura/struct.AuraVerifier.html\" title=\"struct sc_consensus_aura::AuraVerifier\">AuraVerifier</a>&lt;C, P, CIDP, <a class=\"type\" href=\"sp_runtime/traits/type.NumberFor.html\" title=\"type sp_runtime::traits::NumberFor\">NumberFor</a>&lt;B&gt;&gt;<span class=\"where fmt-newline\">where\n    C: ProvideRuntimeApi&lt;B&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + AuxStore,\n    C::Api: BlockBuilderApi&lt;B&gt; + <a class=\"trait\" href=\"sc_consensus_aura/trait.AuraApi.html\" title=\"trait sc_consensus_aura::AuraApi\">AuraApi</a>&lt;B, &lt;P as <a class=\"trait\" href=\"sp_core/crypto/trait.Pair.html\" title=\"trait sp_core::crypto::Pair\">Pair</a>&gt;::<a class=\"associatedtype\" href=\"sp_core/crypto/trait.Pair.html#associatedtype.Public\" title=\"type sp_core::crypto::Pair::Public\">Public</a>&gt; + ApiExt&lt;B&gt;,\n    P: <a class=\"trait\" href=\"sp_core/crypto/trait.Pair.html\" title=\"trait sp_core::crypto::Pair\">Pair</a>,\n    P::<a class=\"associatedtype\" href=\"sp_core/crypto/trait.Pair.html#associatedtype.Public\" title=\"type sp_core::crypto::Pair::Public\">Public</a>: Codec + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,\n    P::<a class=\"associatedtype\" href=\"sp_core/crypto/trait.Pair.html#associatedtype.Signature\" title=\"type sp_core::crypto::Pair::Signature\">Signature</a>: Codec,\n    CIDP: CreateInherentDataProviders&lt;B, <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/std/primitive.unit.html\">()</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    CIDP::InherentDataProviders: InherentDataProviderExt + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,</span>"]],
"sc_consensus_babe":[["impl&lt;Block, Client, SelectChain, CIDP&gt; Verifier&lt;Block&gt; for <a class=\"struct\" href=\"sc_consensus_babe/struct.BabeVerifier.html\" title=\"struct sc_consensus_babe::BabeVerifier\">BabeVerifier</a>&lt;Block, Client, SelectChain, CIDP&gt;<span class=\"where fmt-newline\">where\n    Block: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>,\n    Client: HeaderMetadata&lt;Block, Error = Error&gt; + HeaderBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + AuxStore,\n    Client::Api: BlockBuilderApi&lt;Block&gt; + <a class=\"trait\" href=\"sc_consensus_babe/trait.BabeApi.html\" title=\"trait sc_consensus_babe::BabeApi\">BabeApi</a>&lt;Block&gt;,\n    SelectChain: SelectChain&lt;Block&gt;,\n    CIDP: CreateInherentDataProviders&lt;Block, <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/std/primitive.unit.html\">()</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    CIDP::InherentDataProviders: InherentDataProviderExt + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,</span>"]],
"sc_consensus_manual_seal":[["impl&lt;B, C&gt; Verifier&lt;B&gt; for <a class=\"struct\" href=\"sc_consensus_manual_seal/consensus/babe/struct.BabeVerifier.html\" title=\"struct sc_consensus_manual_seal::consensus::babe::BabeVerifier\">BabeVerifier</a>&lt;B, C&gt;<span class=\"where fmt-newline\">where\n    B: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>,\n    C: HeaderBackend&lt;B&gt; + HeaderMetadata&lt;B, Error = Error&gt;,</span>"]],
"sc_consensus_pow":[["impl&lt;B: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>, Algorithm&gt; Verifier&lt;B&gt; for <a class=\"struct\" href=\"sc_consensus_pow/struct.PowVerifier.html\" title=\"struct sc_consensus_pow::PowVerifier\">PowVerifier</a>&lt;B, Algorithm&gt;<span class=\"where fmt-newline\">where\n    Algorithm: <a class=\"trait\" href=\"sc_consensus_pow/trait.PowAlgorithm.html\" title=\"trait sc_consensus_pow::PowAlgorithm\">PowAlgorithm</a>&lt;B&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,\n    Algorithm::<a class=\"associatedtype\" href=\"sc_consensus_pow/trait.PowAlgorithm.html#associatedtype.Difficulty\" title=\"type sc_consensus_pow::PowAlgorithm::Difficulty\">Difficulty</a>: 'static + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,</span>"]],
"sc_network_test":[["impl&lt;B: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>&gt; <a class=\"trait\" href=\"sc_consensus/import_queue/trait.Verifier.html\" title=\"trait sc_consensus::import_queue::Verifier\">Verifier</a>&lt;B&gt; for <a class=\"struct\" href=\"sc_network_test/struct.PassThroughVerifier.html\" title=\"struct sc_network_test::PassThroughVerifier\">PassThroughVerifier</a>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()