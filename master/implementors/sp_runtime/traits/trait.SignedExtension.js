(function() {var implementors = {};
implementors["frame_system"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckGenesis.html\" title=\"struct frame_system::CheckGenesis\">CheckGenesis</a>&lt;T&gt;","synthetic":false,"types":["frame_system::extensions::check_genesis::CheckGenesis"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckMortality.html\" title=\"struct frame_system::CheckMortality\">CheckMortality</a>&lt;T&gt;","synthetic":false,"types":["frame_system::extensions::check_mortality::CheckMortality"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckNonZeroSender.html\" title=\"struct frame_system::CheckNonZeroSender\">CheckNonZeroSender</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.Call\" title=\"type frame_system::pallet::Config::Call\">Call</a>: <a class=\"trait\" href=\"sp_runtime/traits/trait.Dispatchable.html\" title=\"trait sp_runtime::traits::Dispatchable\">Dispatchable</a>&lt;Info = DispatchInfo&gt;,&nbsp;</span>","synthetic":false,"types":["frame_system::extensions::check_non_zero_sender::CheckNonZeroSender"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckNonce.html\" title=\"struct frame_system::CheckNonce\">CheckNonce</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.Call\" title=\"type frame_system::pallet::Config::Call\">Call</a>: <a class=\"trait\" href=\"sp_runtime/traits/trait.Dispatchable.html\" title=\"trait sp_runtime::traits::Dispatchable\">Dispatchable</a>&lt;Info = DispatchInfo&gt;,&nbsp;</span>","synthetic":false,"types":["frame_system::extensions::check_nonce::CheckNonce"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckSpecVersion.html\" title=\"struct frame_system::CheckSpecVersion\">CheckSpecVersion</a>&lt;T&gt;","synthetic":false,"types":["frame_system::extensions::check_spec_version::CheckSpecVersion"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckTxVersion.html\" title=\"struct frame_system::CheckTxVersion\">CheckTxVersion</a>&lt;T&gt;","synthetic":false,"types":["frame_system::extensions::check_tx_version::CheckTxVersion"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"frame_system/struct.CheckWeight.html\" title=\"struct frame_system::CheckWeight\">CheckWeight</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.Call\" title=\"type frame_system::pallet::Config::Call\">Call</a>: <a class=\"trait\" href=\"sp_runtime/traits/trait.Dispatchable.html\" title=\"trait sp_runtime::traits::Dispatchable\">Dispatchable</a>&lt;Info = DispatchInfo, PostInfo = PostDispatchInfo&gt;,&nbsp;</span>","synthetic":false,"types":["frame_system::extensions::check_weight::CheckWeight"]}];
implementors["pallet_asset_tx_payment"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html\" title=\"trait pallet_asset_tx_payment::pallet::Config\">Config</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"pallet_asset_tx_payment/struct.ChargeAssetTxPayment.html\" title=\"struct pallet_asset_tx_payment::ChargeAssetTxPayment\">ChargeAssetTxPayment</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.Call\" title=\"type frame_system::pallet::Config::Call\">Call</a>: <a class=\"trait\" href=\"sp_runtime/traits/trait.Dispatchable.html\" title=\"trait sp_runtime::traits::Dispatchable\">Dispatchable</a>&lt;Info = DispatchInfo, PostInfo = PostDispatchInfo&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;T as <a class=\"trait\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html\" title=\"trait pallet_asset_tx_payment::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html#associatedtype.Fungibles\" title=\"type pallet_asset_tx_payment::pallet::Config::Fungibles\">Fungibles</a> as Inspect&lt;&lt;T as <a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.AccountId\" title=\"type frame_system::pallet::Config::AccountId\">AccountId</a>&gt;&gt;::Balance: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"sp_arithmetic/fixed_point/trait.FixedPointOperand.html\" title=\"trait sp_arithmetic::fixed_point::FixedPointOperand\">FixedPointOperand</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;T as <a class=\"trait\" href=\"pallet_transaction_payment/pallet/trait.Config.html\" title=\"trait pallet_transaction_payment::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"pallet_transaction_payment/pallet/trait.Config.html#associatedtype.OnChargeTransaction\" title=\"type pallet_transaction_payment::pallet::Config::OnChargeTransaction\">OnChargeTransaction</a> as <a class=\"trait\" href=\"pallet_transaction_payment/payment/trait.OnChargeTransaction.html\" title=\"trait pallet_transaction_payment::payment::OnChargeTransaction\">OnChargeTransaction</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"pallet_transaction_payment/payment/trait.OnChargeTransaction.html#associatedtype.Balance\" title=\"type pallet_transaction_payment::payment::OnChargeTransaction::Balance\">Balance</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>&gt; + <a class=\"trait\" href=\"sp_arithmetic/fixed_point/trait.FixedPointOperand.html\" title=\"trait sp_arithmetic::fixed_point::FixedPointOperand\">FixedPointOperand</a> + IsType&lt;&lt;&lt;T as <a class=\"trait\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html\" title=\"trait pallet_asset_tx_payment::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html#associatedtype.OnChargeAssetTransaction\" title=\"type pallet_asset_tx_payment::pallet::Config::OnChargeAssetTransaction\">OnChargeAssetTransaction</a> as <a class=\"trait\" href=\"pallet_asset_tx_payment/trait.OnChargeAssetTransaction.html\" title=\"trait pallet_asset_tx_payment::OnChargeAssetTransaction\">OnChargeAssetTransaction</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/trait.OnChargeAssetTransaction.html#associatedtype.Balance\" title=\"type pallet_asset_tx_payment::OnChargeAssetTransaction::Balance\">Balance</a>&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;T as <a class=\"trait\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html\" title=\"trait pallet_asset_tx_payment::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html#associatedtype.OnChargeAssetTransaction\" title=\"type pallet_asset_tx_payment::pallet::Config::OnChargeAssetTransaction\">OnChargeAssetTransaction</a> as <a class=\"trait\" href=\"pallet_asset_tx_payment/trait.OnChargeAssetTransaction.html\" title=\"trait pallet_asset_tx_payment::OnChargeAssetTransaction\">OnChargeAssetTransaction</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/trait.OnChargeAssetTransaction.html#associatedtype.AssetId\" title=\"type pallet_asset_tx_payment::OnChargeAssetTransaction::AssetId\">AssetId</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;CreditOf&lt;T::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.AccountId\" title=\"type frame_system::pallet::Config::AccountId\">AccountId</a>, T::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html#associatedtype.Fungibles\" title=\"type pallet_asset_tx_payment::pallet::Config::Fungibles\">Fungibles</a>&gt;: IsType&lt;&lt;&lt;T as <a class=\"trait\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html\" title=\"trait pallet_asset_tx_payment::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/pallet/trait.Config.html#associatedtype.OnChargeAssetTransaction\" title=\"type pallet_asset_tx_payment::pallet::Config::OnChargeAssetTransaction\">OnChargeAssetTransaction</a> as <a class=\"trait\" href=\"pallet_asset_tx_payment/trait.OnChargeAssetTransaction.html\" title=\"trait pallet_asset_tx_payment::OnChargeAssetTransaction\">OnChargeAssetTransaction</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"pallet_asset_tx_payment/trait.OnChargeAssetTransaction.html#associatedtype.LiquidityInfo\" title=\"type pallet_asset_tx_payment::OnChargeAssetTransaction::LiquidityInfo\">LiquidityInfo</a>&gt;,&nbsp;</span>","synthetic":false,"types":["pallet_asset_tx_payment::ChargeAssetTxPayment"]}];
implementors["pallet_example_basic"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"pallet_example_basic/pallet/trait.Config.html\" title=\"trait pallet_example_basic::pallet::Config\">Config</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"pallet_example_basic/struct.WatchDummy.html\" title=\"struct pallet_example_basic::WatchDummy\">WatchDummy</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;T as <a class=\"trait\" href=\"frame_system/pallet/trait.Config.html\" title=\"trait frame_system::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.Call\" title=\"type frame_system::pallet::Config::Call\">Call</a>: <a class=\"trait\" href=\"frame_support/traits/misc/trait.IsSubType.html\" title=\"trait frame_support::traits::misc::IsSubType\">IsSubType</a>&lt;<a class=\"enum\" href=\"pallet_example_basic/pallet/enum.Call.html\" title=\"enum pallet_example_basic::pallet::Call\">Call</a>&lt;T&gt;&gt;,&nbsp;</span>","synthetic":false,"types":["pallet_example_basic::WatchDummy"]}];
implementors["pallet_transaction_payment"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"pallet_transaction_payment/pallet/trait.Config.html\" title=\"trait pallet_transaction_payment::pallet::Config\">Config</a>&gt; <a class=\"trait\" href=\"sp_runtime/traits/trait.SignedExtension.html\" title=\"trait sp_runtime::traits::SignedExtension\">SignedExtension</a> for <a class=\"struct\" href=\"pallet_transaction_payment/struct.ChargeTransactionPayment.html\" title=\"struct pallet_transaction_payment::ChargeTransactionPayment\">ChargeTransactionPayment</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;T as <a class=\"trait\" href=\"pallet_transaction_payment/pallet/trait.Config.html\" title=\"trait pallet_transaction_payment::pallet::Config\">Config</a>&gt;::<a class=\"associatedtype\" href=\"pallet_transaction_payment/pallet/trait.Config.html#associatedtype.OnChargeTransaction\" title=\"type pallet_transaction_payment::pallet::Config::OnChargeTransaction\">OnChargeTransaction</a> as <a class=\"trait\" href=\"pallet_transaction_payment/trait.OnChargeTransaction.html\" title=\"trait pallet_transaction_payment::OnChargeTransaction\">OnChargeTransaction</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"pallet_transaction_payment/trait.OnChargeTransaction.html#associatedtype.Balance\" title=\"type pallet_transaction_payment::OnChargeTransaction::Balance\">Balance</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>&gt; + <a class=\"trait\" href=\"sp_arithmetic/fixed_point/trait.FixedPointOperand.html\" title=\"trait sp_arithmetic::fixed_point::FixedPointOperand\">FixedPointOperand</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;T::<a class=\"associatedtype\" href=\"frame_system/pallet/trait.Config.html#associatedtype.Call\" title=\"type frame_system::pallet::Config::Call\">Call</a>: <a class=\"trait\" href=\"sp_runtime/traits/trait.Dispatchable.html\" title=\"trait sp_runtime::traits::Dispatchable\">Dispatchable</a>&lt;Info = DispatchInfo, PostInfo = PostDispatchInfo&gt;,&nbsp;</span>","synthetic":false,"types":["pallet_transaction_payment::ChargeTransactionPayment"]}];
implementors["sp_runtime"] = [];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()