(function() {var implementors = {
"polkadot_service":[],
"sp_runtime":[],
"staging_xcm_builder":[["impl&lt;RuntimeOrigin: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, EnsureBodyOrigin: <a class=\"trait\" href=\"frame_support/traits/dispatch/trait.EnsureOrigin.html\" title=\"trait frame_support::traits::dispatch::EnsureOrigin\">EnsureOrigin</a>&lt;RuntimeOrigin&gt;, Body: Get&lt;<a class=\"enum\" href=\"staging_xcm_builder/test_utils/enum.BodyId.html\" title=\"enum staging_xcm_builder::test_utils::BodyId\">BodyId</a>&gt;&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.TryConvert.html\" title=\"trait sp_runtime::traits::TryConvert\">TryConvert</a>&lt;RuntimeOrigin, <a class=\"struct\" href=\"staging_xcm_builder/test_utils/struct.MultiLocation.html\" title=\"struct staging_xcm_builder::test_utils::MultiLocation\">MultiLocation</a>&gt; for <a class=\"struct\" href=\"staging_xcm_builder/struct.OriginToPluralityVoice.html\" title=\"struct staging_xcm_builder::OriginToPluralityVoice\">OriginToPluralityVoice</a>&lt;RuntimeOrigin, EnsureBodyOrigin, Body&gt;"],["impl&lt;RuntimeOrigin: <a class=\"trait\" href=\"frame_support/traits/dispatch/trait.OriginTrait.html\" title=\"trait frame_support::traits::dispatch::OriginTrait\">OriginTrait</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, AccountId: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/std/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/std/primitive.array.html\">32</a>]&gt;, Network: Get&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.70.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"enum\" href=\"staging_xcm_builder/test_utils/enum.NetworkId.html\" title=\"enum staging_xcm_builder::test_utils::NetworkId\">NetworkId</a>&gt;&gt;&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.TryConvert.html\" title=\"trait sp_runtime::traits::TryConvert\">TryConvert</a>&lt;RuntimeOrigin, <a class=\"struct\" href=\"staging_xcm_builder/test_utils/struct.MultiLocation.html\" title=\"struct staging_xcm_builder::test_utils::MultiLocation\">MultiLocation</a>&gt; for <a class=\"struct\" href=\"staging_xcm_builder/struct.SignedToAccountId32.html\" title=\"struct staging_xcm_builder::SignedToAccountId32\">SignedToAccountId32</a>&lt;RuntimeOrigin, AccountId, Network&gt;<span class=\"where fmt-newline\">where\n    RuntimeOrigin::<a class=\"associatedtype\" href=\"frame_support/traits/dispatch/trait.OriginTrait.html#associatedtype.PalletsOrigin\" title=\"type frame_support::traits::dispatch::OriginTrait::PalletsOrigin\">PalletsOrigin</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"frame_support/dispatch/enum.RawOrigin.html\" title=\"enum frame_support::dispatch::RawOrigin\">SystemRawOrigin</a>&lt;AccountId&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/convert/trait.TryInto.html\" title=\"trait core::convert::TryInto\">TryInto</a>&lt;<a class=\"enum\" href=\"frame_support/dispatch/enum.RawOrigin.html\" title=\"enum frame_support::dispatch::RawOrigin\">SystemRawOrigin</a>&lt;AccountId&gt;, Error = RuntimeOrigin::<a class=\"associatedtype\" href=\"frame_support/traits/dispatch/trait.OriginTrait.html#associatedtype.PalletsOrigin\" title=\"type frame_support::traits::dispatch::OriginTrait::PalletsOrigin\">PalletsOrigin</a>&gt;,</span>"],["impl&lt;RuntimeOrigin: <a class=\"trait\" href=\"frame_support/traits/dispatch/trait.OriginTrait.html\" title=\"trait frame_support::traits::dispatch::OriginTrait\">OriginTrait</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, COrigin: <a class=\"trait\" href=\"frame_support/traits/misc/trait.GetBacking.html\" title=\"trait frame_support::traits::misc::GetBacking\">GetBacking</a>, Body: Get&lt;<a class=\"enum\" href=\"staging_xcm_builder/test_utils/enum.BodyId.html\" title=\"enum staging_xcm_builder::test_utils::BodyId\">BodyId</a>&gt;&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.TryConvert.html\" title=\"trait sp_runtime::traits::TryConvert\">TryConvert</a>&lt;RuntimeOrigin, <a class=\"struct\" href=\"staging_xcm_builder/test_utils/struct.MultiLocation.html\" title=\"struct staging_xcm_builder::test_utils::MultiLocation\">MultiLocation</a>&gt; for <a class=\"struct\" href=\"staging_xcm_builder/struct.BackingToPlurality.html\" title=\"struct staging_xcm_builder::BackingToPlurality\">BackingToPlurality</a>&lt;RuntimeOrigin, COrigin, Body&gt;<span class=\"where fmt-newline\">where\n    RuntimeOrigin::<a class=\"associatedtype\" href=\"frame_support/traits/dispatch/trait.OriginTrait.html#associatedtype.PalletsOrigin\" title=\"type frame_support::traits::dispatch::OriginTrait::PalletsOrigin\">PalletsOrigin</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;COrigin&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.70.0/core/convert/trait.TryInto.html\" title=\"trait core::convert::TryInto\">TryInto</a>&lt;COrigin, Error = RuntimeOrigin::<a class=\"associatedtype\" href=\"frame_support/traits/dispatch/trait.OriginTrait.html#associatedtype.PalletsOrigin\" title=\"type frame_support::traits::dispatch::OriginTrait::PalletsOrigin\">PalletsOrigin</a>&gt;,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()