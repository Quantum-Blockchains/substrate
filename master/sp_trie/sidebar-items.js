window.SIDEBAR_ITEMS = {"enum":[["CompactProofError","Error for trie node decoding."],["Error","Error for trie node decoding."],["NodePlan","Various re-exports from the `trie-db` crate. A `NodePlan` is a blueprint for decoding a node from a byte slice. The `NodePlan` is created by parsing an encoded node and can be reused multiple times. This is useful as a `Node` borrows from a byte slice and this struct does not."],["ValuePlan","Various re-exports from the `trie-db` crate. Plan for value representation in `NodePlan`."],["VerifyError","Errors that may occur during proof verification. Most of the errors types simply indicate that the proof is invalid with respect to the statement being verified, and the exact error type can be used for debugging."]],"fn":[["child_delta_trie_root","Determine a child trie root given a hash DB and delta values. H is the default hasher, but a generic implementation may ignore this type parameter and use other hashers."],["child_trie_root","Determine a child trie root given its ordered contents, closed form. H is the default hasher, but a generic implementation may ignore this type parameter and use other hashers."],["decode_compact","Decode a compact proof."],["delta_trie_root","Determine a trie root given a hash DB and delta values."],["empty_child_trie_root","Determine the empty child trie root."],["empty_trie_root","Determine the empty trie root."],["encode_compact","Encode a compact proof."],["generate_trie_proof","Create a proof for a subset of keys in a trie."],["prefixed_key","Various re-exports from the `memory-db` crate. Derive a database key from hash value of the node (key) and  the node prefix."],["read_child_trie_value","Read a value from the child trie."],["read_child_trie_value_with","Read a value from the child trie with given query."],["read_trie_value","Read a value from the trie."],["read_trie_value_with","Read a value from the trie with given Query."],["record_all_keys","Record all keys for a given root."],["verify_trie_proof","Verify a set of key-value pairs against a trie root and a proof."]],"mod":[["nibble_ops","Various re-exports from the `trie-db` crate. Utility methods to work on radix 16 nibble."],["trie_types","This module is for non generic definition of trie type. Only the `Hasher` trait is generic in this case."]],"static":[["EMPTY_PREFIX","Various re-exports from the `hash-db` crate. An empty prefix constant. Can be use when the prefix is not use internally or for root nodes."]],"struct":[["CompactProof","Storage proof in compact form."],["HashKey","Various re-exports from the `memory-db` crate. Key function that only uses the hash"],["KeySpacedDB","`HashDB` implementation that append a encoded prefix (unique id bytes) in addition to the prefix of every key value."],["KeySpacedDBMut","`HashDBMut` implementation that append a encoded prefix (unique id bytes) in addition to the prefix of every key value."],["LayoutV0","substrate trie layout"],["LayoutV1","substrate trie layout, with external value nodes."],["NodeCodec","Concrete implementation of a [`NodeCodecT`] with SCALE encoding."],["PrefixedKey","Various re-exports from the `memory-db` crate. Key function that concatenates prefix and hash."],["Recorder","Various re-exports from the `trie-db` crate. Records trie nodes as they pass it."],["StorageProof","A proof that some set of key-value pairs are included in the storage trie. The proof contains the storage values so that the partial storage backend can be reconstructed by a verifier that does not already have access to the key-value pairs."],["TrieDBIterator","Various re-exports from the `trie-db` crate. Iterator for going through all values in the trie in pre-order traversal order."],["TrieDBKeyIterator","Various re-exports from the `trie-db` crate. Iterator for going through all of key with values in the trie in pre-order traversal order."],["TrieStream","Codec-flavored TrieStream."]],"trait":[["AsHashDB","Reexport from `hash_db`, with genericity set for `Hasher` trait."],["HashDBT","Various re-exports from the `hash-db` crate. Trait modelling datastore keyed by a hash defined by the `Hasher`."],["KeyFunction","Various re-exports from the `memory-db` crate."],["Query","Various re-exports from the `trie-db` crate. Description of what kind of query will be made to the trie."],["Trie","Various re-exports from the `trie-db` crate. A key-value datastore implemented as a database-backed modified Merkle tree."],["TrieConfiguration","Various re-exports from the `trie-db` crate. This trait associates a trie definition with preferred methods. It also contains own default implementations and can be used to allow switching implementation."],["TrieLayout","Various re-exports from the `trie-db` crate. Trait with definition of trie layout. Contains all associated trait needed for a trie definition or implementation."],["TrieMut","Various re-exports from the `trie-db` crate. A key-value datastore implemented as a database-backed modified Merkle tree."]],"type":[["CError","Various re-exports from the `trie-db` crate. Alias accessor to `NodeCodec` associated `Error` type from a `TrieLayout`."],["DBValue","Various re-exports from the `trie-db` crate. Database value"],["GenericMemoryDB","Reexport from `hash_db`, with genericity set for `Hasher` trait."],["HashDB","Reexport from `hash_db`, with genericity set for `Hasher` trait."],["Lookup","Querying interface, as in `trie_db` but less generic."],["MemoryDB","Reexport from `hash_db`, with genericity set for `Hasher` trait. This uses a noops `KeyFunction` (key addressing must be hashed or using an encoding scheme that avoid key conflict)."],["PrefixedMemoryDB","Reexport from `hash_db`, with genericity set for `Hasher` trait. This uses a `KeyFunction` for prefixing keys internally (avoiding key conflict for non random keys)."],["TrieDB","Persistent trie database read-access interface for the a given hasher."],["TrieDBMut","Persistent trie database write-access interface for the a given hasher."],["TrieError","TrieDB error over `TrieConfiguration` trait."],["TrieHash","Hash type for a trie layout."]]};