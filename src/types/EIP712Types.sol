// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Message signed by the sponsor that specifies the conditions under which their
// tokens can be claimed; the specified arbiter verifies that those conditions
// have been met and specifies a set of beneficiaries that will receive up to the
// specified amount of tokens.
struct Compact {
    address arbiter; // The account tasked with verifying and submitting the claim.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes12 lockTag; // A tag representing the allocator, reset period, and scope.
    address token; // The locked token, or address(0) for native tokens.
    uint256 amount; // The amount of ERC6909 tokens to allocate.
        // Optional witness may follow.
}

// keccak256(bytes("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount)"))
bytes32 constant COMPACT_TYPEHASH = 0x73b631296de001508966ddfc334593ad8f850ccd3be4d2c58a9ed469844eebc7;

// abi.decode(bytes("Compact(address arbiter,address "), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_ONE = 0x436f6d70616374286164647265737320617262697465722c6164647265737320;

// abi.decode(bytes("sponsor,uint256 nonce,uint256 ex"), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_TWO = 0x73706f6e736f722c75696e74323536206e6f6e63652c75696e74323536206578;

// abi.decode(bytes("pires,bytes12 lockTag,address to"), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_THREE = 0x70697265732c62797465733132206c6f636b5461672c6164647265737320746f;

// abi.decode(bytes("ken,uint256 amount,Mandate manda"), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_FOUR = 0x6b656e2c75696e7432353620616d6f756e742c4d616e64617465206d616e6461;

// uint88(abi.decode(bytes("te)Mandate("), (bytes11)))
uint88 constant COMPACT_TYPESTRING_FRAGMENT_FIVE = 0x7465294d616e6461746528;

// A batch or multichain compact can contain commitments from multiple resource locks.
struct Commitment {
    bytes12 lockTag; // A tag representing the allocator, reset period, and scope.
    address token; // The locked token, or address(0) for native tokens.
    uint256 amount; // The maximum committed amount of tokens.
}

// Message signed by the sponsor that specifies the conditions under which a set of
// tokens, each sharing an allocator, can be claimed; the specified arbiter verifies
// that those conditions have been met and specifies a set of beneficiaries that will
// receive up to the specified amounts of each token.
struct BatchCompact {
    address arbiter; // The account tasked with verifying and submitting the claim.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    Commitment[] commitments; // The committed token IDs and amounts.
        // Optional witness may follow.
}

// keccak256(bytes("BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Commitment[] commitments)Commitment(bytes12 lockTag,address token,uint256 amount)"))
bytes32 constant BATCH_COMPACT_TYPEHASH = 0x25ad323dd014759caf54f2c599f416828ddd05a76fe67e7b8980e0d6298ef164;

// abi.decode(bytes("BatchCompact(address arbiter,add"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4261746368436f6d70616374286164647265737320617262697465722c616464;

// abi.decode(bytes("ress sponsor,uint256 nonce,uint2"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x726573732073706f6e736f722c75696e74323536206e6f6e63652c75696e7432;

// abi.decode(bytes("56 expires,Commitment[] commitme"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x353620657870697265732c436f6d6d69746d656e745b5d20636f6d6d69746d65;

// abi.decode(bytes("nt,Mandate mandate)Commitment(by"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x6e742c4d616e64617465206d616e6461746529436f6d6d69746d656e74286279;

// abi.decode(bytes("tes12 lockTag,address token,uint"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE =
    0x7465733132206c6f636b5461672c6164647265737320746f6b656e2c75696e74;

// uint152(abi.decode(bytes("256 amount)Mandate("), (bytes19)))
uint152 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX = 0x32353620616d6f756e74294d616e6461746528;

// A multichain compact can declare tokens and amounts to allocate from multiple chains,
// each designated by their chainId. Any allocated tokens on an exogenous domain (e.g. all
// but the first element) must designate the Multichain scope. Each element may designate
// a unique arbiter for the chain in question. Note that the witness data is distinct for
// each element, but all elements must share the same EIP-712 "Mandate" witness typestring.
struct Element {
    address arbiter; // The account tasked with verifying and submitting the claim.
    uint256 chainId; // The chainId where the tokens are located.
    Commitment[] commitments; // The committed token IDs and amounts.
        // Mandate (witness) must follow.
}

// Message signed by the sponsor that specifies the conditions under which a set of
// tokens across a number of different chains can be claimed; the specified arbiter on
// each chain verifies that those conditions have been met and specifies a set of
// beneficiaries that will receive up to the specified amounts of each token.
struct MultichainCompact {
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    Element[] elements; // Arbiter, chainId, ids & amounts, and mandate for each chain.
}

// keccak256(bytes("MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Commitment(bytes12 lockTag,address token,uint256 amount)Element(address arbiter,uint256 chainId,Commitment[] commitments)"))
bytes32 constant MULTICHAIN_COMPACT_TYPEHASH = 0x94a98b41cfcabeda13557d529a7d99f5f2b5843fe05f479758bcb30b4e57f1a4;

// abi.decode(bytes("MultichainCompact(address sponso"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4d756c7469636861696e436f6d7061637428616464726573732073706f6e736f;

// abi.decode(bytes("r,uint256 nonce,uint256 expires,"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x722c75696e74323536206e6f6e63652c75696e7432353620657870697265732c;

// abi.decode(bytes("Element[] elements)Commitment(by"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x456c656d656e745b5d20656c656d656e747329436f6d6d69746d656e74286279;

// abi.decode(bytes("tes12 lockTag,address token,uint"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x7465733132206c6f636b5461672c6164647265737320746f6b656e2c75696e74;

// abi.decode(bytes("256 amount)Element(address arbit"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE =
    0x32353620616d6f756e7429456c656d656e742861646472657373206172626974;

// abi.decode(bytes("er,uint256 chainId,Commitment[] "), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX =
    0x65722c75696e7432353620636861696e49642c436f6d6d69746d656e745b5d20;

// abi.decode(bytes("commitments, Mandate mandate)Man"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SEVEN =
    0x636f6d6d69746d656e74732c204d616e64617465206d616e64617465294d616e;

// uint40(abi.decode(bytes("date("), (bytes5))
uint40 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_EIGHT = 0x6461746528;

// keccak256(bytes("Element(address arbiter,uint256 chainId,Commitment[] commitments)Commitment(bytes12 lockTag,address token,uint256 amount)"))
bytes32 constant ELEMENT_TYPEHASH = 0xf2584684f674489e33f0de69fc34d03a4ceb80b27b1de97e0e7778ec779deca5;

/// @dev `keccak256(bytes("CompactDeposit(bytes12 lockTag,address recipient)"))`.
bytes32 constant PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH =
    0xaced9f7c53bfda31d043cbef88f9ee23b8171ec904889af3d5d0b9b81914a404;

/// @dev `keccak256(bytes("Activation(address activator,uint256 id,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount)"))`.
bytes32 constant COMPACT_ACTIVATION_TYPEHASH = 0x8b05b54b25c4a22095273abeb15e89077542cdca8be672282102c3473780942c;

/// @dev `keccak256(bytes("Activation(address activator,uint256 id,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Commitment[] commitments)Commitment(bytes12 lockTag,address token,uint256 amount)"))`.
bytes32 constant BATCH_COMPACT_ACTIVATION_TYPEHASH = 0x0b71f281a653d954c8906b89356c95627918ae1ae093bfeabd30dcabeb465bac;

/// @dev `keccak256(bytes("BatchActivation(address activator,uint256[] ids,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount)"))`.
bytes32 constant COMPACT_BATCH_ACTIVATION_TYPEHASH = 0x25686dcdaf36339365d8aad4b420a3460867a181238971ffae587b16c6d9660f;

/// @dev `keccak256(bytes("BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Commitment[] commitments)Commitment(bytes12 lockTag,address token,uint256 amount)"))`.
bytes32 constant BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH =
    0xccd1083bf76e8cc4025444a9a97d4a6eeab40d6d806c020d80dd5b20b554833c;

// abi.decode(bytes("Activation witness)Activation(ad"), (bytes32))
bytes32 constant PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE =
    0x41637469766174696f6e207769746e6573732941637469766174696f6e286164;

// uint216(abi.decode(bytes("dress activator,uint256 id,"), (bytes27)))
uint216 constant PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO =
    0x647265737320616374697661746f722c75696e743235362069642c;

// abi.decode(bytes("BatchActivation witness)BatchAct"), (bytes32))
bytes32 constant PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE =
    0x426174636841637469766174696f6e207769746e657373294261746368416374;

// abi.decode(bytes("ivation(address activator,uint25"), (bytes32))
bytes32 constant PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO =
    0x69766174696f6e286164647265737320616374697661746f722c75696e743235;

// uint64(abi.decode(bytes("6[] ids,"), (bytes8)))
uint64 constant PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_THREE = 0x365b5d206964732c;

// abi.decode(bytes("Compact compact)Compact(address "), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x436f6d7061637420636f6d7061637429436f6d70616374286164647265737320;

// abi.decode(bytes("arbiter,address sponsor,uint256 "), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x617262697465722c616464726573732073706f6e736f722c75696e7432353620;

// abi.decode(bytes("nonce,uint256 expires,bytes12 lo"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x6e6f6e63652c75696e7432353620657870697265732c62797465733132206c6f;

// abi.decode(bytes("ckTag, address token,uint256 amo"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x636b5461672c206164647265737320746f6b656e2c75696e7432353620616d6f;

// uint224(abi.decode(bytes("unt,Mandate mandate)Mandate("), (bytes28)))
uint224 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FIVE =
    0x756e742c4d616e64617465206d616e64617465294d616e6461746528;

// abi.decode(bytes("BatchCompact compact)BatchCompac"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4261746368436f6d7061637420636f6d70616374294261746368436f6d706163;

// abi.decode(bytes("t(address arbiter,address sponso"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x74286164647265737320617262697465722c616464726573732073706f6e736f;

// abi.decode(bytes("r,uint256 nonce,uint256 expires,"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x722c75696e74323536206e6f6e63652c75696e7432353620657870697265732c;

// abi.decode(bytes("Commitment[] commitments,Mandate"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x436f6d6d69746d656e745b5d20636f6d6d69746d656e74732c4d616e64617465;

// abi.decode(bytes(" mandate)Commitment(bytes12 lock"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE =
    0x206d616e6461746529436f6d6d69746d656e742862797465733132206c6f636b;

// abi.decode(bytes("Tag,address token,uint256 amount"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX =
    0x5461672c6164647265737320746f6b656e2c75696e7432353620616d6f756e74;

// uint72(abi.decode(bytes(")Mandate("), (bytes9)))
uint72 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_SEVEN = 0x294d616e6461746528;

// abi.decode(bytes(")TokenPermissions(address token,"), (bytes32))
bytes32 constant TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE =
    0x29546f6b656e5065726d697373696f6e73286164647265737320746f6b656e2c;

// uint120(abi.decode(bytes("uint256 amount)"), (bytes15)))
uint120 constant TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO = 0x75696e7432353620616d6f756e7429;

// abi.decode(bytes("CompactDeposit witness)CompactDe"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE =
    0x436f6d706163744465706f736974207769746e65737329436f6d706163744465;

// abi.decode(bytes("posit(bytes12 lockTag,address re"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO =
    0x706f7369742862797465733132206c6f636b5461672c61646472657373207265;

// abi.decode(bytes("cipient)TokenPermissions(address"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE =
    0x63697069656e7429546f6b656e5065726d697373696f6e732861646472657373;

// uint176(abi.decode(bytes(" token,uint256 amount)"), (bytes22)))
uint176 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR = 0x20746f6b656e2c75696e7432353620616d6f756e7429;
