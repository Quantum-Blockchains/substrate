(function() {var implementors = {};
implementors["node_runtime"] = [{"text":"impl Benchmark&lt;<a class=\"struct\" href=\"sp_runtime/generic/block/struct.Block.html\" title=\"struct sp_runtime::generic::block::Block\">Block</a>&lt;<a class=\"struct\" href=\"sp_runtime/generic/header/struct.Header.html\" title=\"struct sp_runtime::generic::header::Header\">Header</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, <a class=\"struct\" href=\"sp_runtime/traits/struct.BlakeTwo256.html\" title=\"struct sp_runtime::traits::BlakeTwo256\">BlakeTwo256</a>&gt;, <a class=\"struct\" href=\"sp_runtime/generic/unchecked_extrinsic/struct.UncheckedExtrinsic.html\" title=\"struct sp_runtime::generic::unchecked_extrinsic::UncheckedExtrinsic\">UncheckedExtrinsic</a>&lt;<a class=\"enum\" href=\"sp_runtime/multiaddress/enum.MultiAddress.html\" title=\"enum sp_runtime::multiaddress::MultiAddress\">MultiAddress</a>&lt;&lt;&lt;<a class=\"enum\" href=\"sp_runtime/enum.MultiSignature.html\" title=\"enum sp_runtime::MultiSignature\">MultiSignature</a> as <a class=\"trait\" href=\"sp_runtime/traits/trait.Verify.html\" title=\"trait sp_runtime::traits::Verify\">Verify</a>&gt;::<a class=\"associatedtype\" href=\"sp_runtime/traits/trait.Verify.html#associatedtype.Signer\" title=\"type sp_runtime::traits::Verify::Signer\">Signer</a> as <a class=\"trait\" href=\"sp_runtime/traits/trait.IdentifyAccount.html\" title=\"trait sp_runtime::traits::IdentifyAccount\">IdentifyAccount</a>&gt;::<a class=\"associatedtype\" href=\"sp_runtime/traits/trait.IdentifyAccount.html#associatedtype.AccountId\" title=\"type sp_runtime::traits::IdentifyAccount::AccountId\">AccountId</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>&gt;, <a class=\"enum\" href=\"node_runtime/enum.Call.html\" title=\"enum node_runtime::Call\">Call</a>, <a class=\"enum\" href=\"sp_runtime/enum.MultiSignature.html\" title=\"enum sp_runtime::MultiSignature\">MultiSignature</a>, (<a class=\"struct\" href=\"frame_system/extensions/check_non_zero_sender/struct.CheckNonZeroSender.html\" title=\"struct frame_system::extensions::check_non_zero_sender::CheckNonZeroSender\">CheckNonZeroSender</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_spec_version/struct.CheckSpecVersion.html\" title=\"struct frame_system::extensions::check_spec_version::CheckSpecVersion\">CheckSpecVersion</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_tx_version/struct.CheckTxVersion.html\" title=\"struct frame_system::extensions::check_tx_version::CheckTxVersion\">CheckTxVersion</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_genesis/struct.CheckGenesis.html\" title=\"struct frame_system::extensions::check_genesis::CheckGenesis\">CheckGenesis</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_mortality/struct.CheckMortality.html\" title=\"struct frame_system::extensions::check_mortality::CheckMortality\">CheckMortality</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_nonce/struct.CheckNonce.html\" title=\"struct frame_system::extensions::check_nonce::CheckNonce\">CheckNonce</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_weight/struct.CheckWeight.html\" title=\"struct frame_system::extensions::check_weight::CheckWeight\">CheckWeight</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"pallet_asset_tx_payment/struct.ChargeAssetTxPayment.html\" title=\"struct pallet_asset_tx_payment::ChargeAssetTxPayment\">ChargeAssetTxPayment</a>&lt;<a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>&gt;)&gt;&gt;&gt; for <a class=\"struct\" href=\"node_runtime/struct.Runtime.html\" title=\"struct node_runtime::Runtime\">Runtime</a>","synthetic":false,"types":["node_runtime::Runtime"]}];
implementors["node_template_runtime"] = [{"text":"impl Benchmark&lt;<a class=\"struct\" href=\"sp_runtime/generic/block/struct.Block.html\" title=\"struct sp_runtime::generic::block::Block\">Block</a>&lt;<a class=\"struct\" href=\"sp_runtime/generic/header/struct.Header.html\" title=\"struct sp_runtime::generic::header::Header\">Header</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, <a class=\"struct\" href=\"sp_runtime/traits/struct.BlakeTwo256.html\" title=\"struct sp_runtime::traits::BlakeTwo256\">BlakeTwo256</a>&gt;, <a class=\"struct\" href=\"sp_runtime/generic/unchecked_extrinsic/struct.UncheckedExtrinsic.html\" title=\"struct sp_runtime::generic::unchecked_extrinsic::UncheckedExtrinsic\">UncheckedExtrinsic</a>&lt;<a class=\"enum\" href=\"sp_runtime/multiaddress/enum.MultiAddress.html\" title=\"enum sp_runtime::multiaddress::MultiAddress\">MultiAddress</a>&lt;&lt;&lt;<a class=\"enum\" href=\"sp_runtime/enum.MultiSignature.html\" title=\"enum sp_runtime::MultiSignature\">MultiSignature</a> as <a class=\"trait\" href=\"sp_runtime/traits/trait.Verify.html\" title=\"trait sp_runtime::traits::Verify\">Verify</a>&gt;::<a class=\"associatedtype\" href=\"sp_runtime/traits/trait.Verify.html#associatedtype.Signer\" title=\"type sp_runtime::traits::Verify::Signer\">Signer</a> as <a class=\"trait\" href=\"sp_runtime/traits/trait.IdentifyAccount.html\" title=\"trait sp_runtime::traits::IdentifyAccount\">IdentifyAccount</a>&gt;::<a class=\"associatedtype\" href=\"sp_runtime/traits/trait.IdentifyAccount.html#associatedtype.AccountId\" title=\"type sp_runtime::traits::IdentifyAccount::AccountId\">AccountId</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>&gt;, <a class=\"enum\" href=\"node_template_runtime/enum.Call.html\" title=\"enum node_template_runtime::Call\">Call</a>, <a class=\"enum\" href=\"sp_runtime/enum.MultiSignature.html\" title=\"enum sp_runtime::MultiSignature\">MultiSignature</a>, (<a class=\"struct\" href=\"frame_system/extensions/check_non_zero_sender/struct.CheckNonZeroSender.html\" title=\"struct frame_system::extensions::check_non_zero_sender::CheckNonZeroSender\">CheckNonZeroSender</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_spec_version/struct.CheckSpecVersion.html\" title=\"struct frame_system::extensions::check_spec_version::CheckSpecVersion\">CheckSpecVersion</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_tx_version/struct.CheckTxVersion.html\" title=\"struct frame_system::extensions::check_tx_version::CheckTxVersion\">CheckTxVersion</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_genesis/struct.CheckGenesis.html\" title=\"struct frame_system::extensions::check_genesis::CheckGenesis\">CheckGenesis</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_mortality/struct.CheckMortality.html\" title=\"struct frame_system::extensions::check_mortality::CheckMortality\">CheckMortality</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_nonce/struct.CheckNonce.html\" title=\"struct frame_system::extensions::check_nonce::CheckNonce\">CheckNonce</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"frame_system/extensions/check_weight/struct.CheckWeight.html\" title=\"struct frame_system::extensions::check_weight::CheckWeight\">CheckWeight</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;, <a class=\"struct\" href=\"pallet_transaction_payment/struct.ChargeTransactionPayment.html\" title=\"struct pallet_transaction_payment::ChargeTransactionPayment\">ChargeTransactionPayment</a>&lt;<a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>&gt;)&gt;&gt;&gt; for <a class=\"struct\" href=\"node_template_runtime/struct.Runtime.html\" title=\"struct node_template_runtime::Runtime\">Runtime</a>","synthetic":false,"types":["node_template_runtime::Runtime"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()