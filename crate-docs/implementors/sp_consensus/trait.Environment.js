(function() {var implementors = {
"cumulus_test_client":[],
"polkadot_test_client":[],
"sc_basic_authorship":[["impl&lt;A, B, Block, C, PR&gt; Environment&lt;Block&gt; for <a class=\"struct\" href=\"sc_basic_authorship/struct.ProposerFactory.html\" title=\"struct sc_basic_authorship::ProposerFactory\">ProposerFactory</a>&lt;A, B, C, PR&gt;<span class=\"where fmt-newline\">where\n    A: TransactionPool&lt;Block = Block&gt; + 'static,\n    B: Backend&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + 'static,\n    Block: <a class=\"trait\" href=\"sp_runtime/traits/trait.Block.html\" title=\"trait sp_runtime::traits::Block\">BlockT</a>,\n    C: BlockBuilderProvider&lt;B, Block, C&gt; + HeaderBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + 'static,\n    C::Api: ApiExt&lt;Block&gt; + BlockBuilderApi&lt;Block&gt;,\n    PR: ProofRecording,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()