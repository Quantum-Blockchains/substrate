window.SIDEBAR_ITEMS = {"derive":[["Decode","Derive `parity_scale_codec::Decode` and for struct and enum."],["Encode","Derive `parity_scale_codec::Encode` and `parity_scale_codec::EncodeLike` for struct and enum."],["MaxEncodedLen","Derive `parity_scale_codec::MaxEncodedLen` for struct and enum."],["RuntimeDebug",""],["TypeInfo",""]],"enum":[["DispatchError","Reason why a dispatch call failed."],["RawOrigin","Origin for the System pallet."]],"macro":[["Clone","Derive macro generating an impl of the trait `Clone`."],["Eq","Derive macro generating an impl of the trait `Eq`."],["PartialEq","Derive macro generating an impl of the trait `PartialEq`."]],"mod":[["fmt","Utilities for formatting and printing `String`s."],["marker","Primitive traits and types representing basic properties of types."],["result","Error handling with the `Result` type."]],"struct":[["CallMetadata","The function and pallet name of the Call."],["Vec","A contiguous growable array type, written as `Vec<T>`, short for ‘vector’."],["Weight",""]],"trait":[["Callable","Serializable version of pallet dispatchable."],["Clone","A common trait for the ability to explicitly duplicate an object."],["Codec","Trait that allows zero-copy read/write of value-references to/from slices in LE format."],["Decode","Trait that allows zero-copy read of value-references from slices in LE format."],["Dispatchable","A lazy call (module function and argument values) that can be executed via its `dispatch` method."],["Encode","Trait that allows zero-copy write of value-references to slices in LE format."],["EncodeAsRef","Something that can be encoded as a reference."],["EncodeLike","A marker trait that tells the compiler that a type encode to the same representation as another type."],["Eq","Trait for equality comparisons which are equivalence relations."],["GetCallMetadata","Gets the metadata for the Call - function name and pallet name."],["GetCallName","Gets the function name of the Call."],["GetStorageVersion","Provides information about the storage version of a pallet."],["HasCompact","Trait that tells you if a given type can be encoded/decoded in a compact way."],["Input","Trait that allows reading of data into a slice."],["MaxEncodedLen","Items implementing `MaxEncodedLen` have a statically known maximum encoded size."],["Output","Trait that allows writing of data."],["Parameter","A type that can be used as a parameter in a dispatchable function."],["PartialEq","Trait for equality comparisons which are partial equivalence relations."],["TypeInfo","Implementors return their meta type information."],["UnfilteredDispatchable","Type that can be dispatched with an origin but without checking the origin filter."]],"type":[["CallableCallFor",""],["DispatchErrorWithPostInfo","The error type contained in a `DispatchResultWithPostInfo`."],["DispatchResult","Unaugmented version of `DispatchResultWithPostInfo` that can be returned from dispatchable functions and is automatically converted to the augmented type. Should be used whenever the `PostDispatchInfo` does not need to be overwritten. As this should be the common case it is the implicit return type when none is specified."],["DispatchResultWithPostInfo","The return type of a `Dispatchable` in frame. When returned explicitly from a dispatchable function it allows overriding the default `PostDispatchInfo` returned from a dispatch."],["TransactionPriority","Priority for a transaction. Additive. Higher is better."]]};