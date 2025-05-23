import hre from "hardhat";
import {
  keccak256,
  encodePacked,
  encodeAbiParameters,
  Address,
  toBytes,
  Hex,
  toHex,
  concatHex,
  Hash,
} from "viem";

type CompactData = {
  arbiter: Address;
  sponsor: Address;
  nonce: bigint;
  expires: bigint;
  id: bigint;
  amount: bigint;
  mandate?: {
    witnessArgument: bigint;
  };
};

function getLockTag(allocatorId: bigint, scope: bigint, resetPeriod: bigint) {
  return (scope << 95n) | (resetPeriod << 92n) | allocatorId;
}

function getAllocatorId(allocator: Address | bigint) {
  // Calculate compact flag
  // First, count leading zero nibbles in the address
  let leadingZeros = 0;
  let mask = 0xf000000000000000000000000000000000000000n;

  for (let i = 0; i < 40; i++) {
    if ((BigInt(allocator) & mask) !== 0n) {
      break;
    }
    leadingZeros++;
    mask = mask >> 4n;
  }

  // Calculate the compact flag for the address:
  // - 0-3 leading zero nibbles: 0
  // - 4-17 leading zero nibbles: number of leading zeros minus 3
  // - 18+ leading zero nibbles: 15
  let compactFlag = 0n;
  if (leadingZeros >= 18) {
    compactFlag = 15n;
  } else if (leadingZeros >= 4) {
    compactFlag = BigInt(leadingZeros - 3);
  }

  // Extract the last 88 bits of the address
  const last88Bits = BigInt(allocator) & 0xffffffffffffffffffffffn;

  // Combine the compact flag (4 bits) with the last 88 bits
  return (compactFlag << 88n) | last88Bits;
}

function getTokenId(lockTag: bigint, tokenAddress: bigint) {
  return (lockTag << 160n) | tokenAddress;
}

function getClaimant(lockTag: bigint, receiver: bigint | Address) {
  return (lockTag << 96n) | BigInt(receiver);
}

function getSimpleWitnessHash(witnessArgument: bigint) {
  // keccak256("Mandate(uint256 witnessArgument)")
  const typeHash = "0x9e52cfc72580d3ec00c7361bbb625c7b47e58df37ef770a2b832d0c916115242";

  const encodedData = encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }],
    [typeHash, witnessArgument]
  );

  return keccak256(encodedData);
}

async function getSignedCompact(
  theCompact: Address,
  sponsor: Address,
  message: CompactData
) {
  const client = await hre.viem.getWalletClient(sponsor);
  return client.signTypedData({
    domain: {
      name: "The Compact",
      version: "1",
      chainId: BigInt(hre.network.config.chainId!),
      verifyingContract: theCompact,
    },
    types: getTypes(message),
    primaryType: "Compact",
    message,
  });
}

function getClaimHash(message: CompactData) {
  return keccak256(
    message.mandate ?
      encodeAbiParameters(
        [
          { type: 'bytes32' }, // COMPACT_TYPEHASH
          { type: 'address' }, // arbiter
          { type: 'address' }, // sponsor
          { type: 'uint256' }, // nonce
          { type: 'uint256' }, // expires
          { type: 'uint256' }, // id
          { type: 'uint256' }, // amount
          { type: 'bytes32' }, // mandateHash
        ],
        [
          keccak256(toBytes('Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 witnessArgument)')),
          message.arbiter as `0x${string}`,
          message.sponsor as `0x${string}`,
          BigInt(message.nonce),
          BigInt(message.expires),
          BigInt(message.id),
          BigInt(message.amount),
          keccak256(encodeAbiParameters(
            [
              { type: 'bytes32' },
              { type: 'uint256' },
            ],
            [
              keccak256(toBytes('Mandate(uint256 witnessArgument)')),
              BigInt(message.mandate.witnessArgument),
            ]
          )),
        ]
      ) :
      encodeAbiParameters(
        [
          { type: 'bytes32' }, // COMPACT_TYPEHASH
          { type: 'address' }, // arbiter
          { type: 'address' }, // sponsor
          { type: 'uint256' }, // nonce
          { type: 'uint256' }, // expires
          { type: 'uint256' }, // id
          { type: 'uint256' }, // amount
        ],
        [
          keccak256(toBytes('Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)')),
          message.arbiter as `0x${string}`,
          message.sponsor as `0x${string}`,
          BigInt(message.nonce),
          BigInt(message.expires),
          BigInt(message.id),
          BigInt(message.amount),
        ]
    )
  );
}

function getTypes(message: CompactData) {
  if (message.mandate) {
    return {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Compact: [
        { name: 'arbiter', type: 'address' },
        { name: 'sponsor', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'expires', type: 'uint256' },
        { name: 'id', type: 'uint256' },
        { name: 'amount', type: 'uint256' },
        { name: 'mandate', type: 'Mandate' },
      ],
      Mandate: [
        { name: 'witnessArgument', type: 'uint256' },
      ],
    };
  }

  return {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' },
      { name: 'verifyingContract', type: 'address' },
    ],
    Compact: [
      { name: 'arbiter', type: 'address' },
      { name: 'sponsor', type: 'address' },
      { name: 'nonce', type: 'uint256' },
      { name: 'expires', type: 'uint256' },
      { name: 'id', type: 'uint256' },
      { name: 'amount', type: 'uint256' },
    ],
  };
}

function getClaimPayload(
  message: CompactData,
  sponsorSignature: Hex,
  claimants: { lockTag: bigint; claimant: Address; amount: bigint }[]
) {
  return {
    allocatorData: "0x" as Hex,
    sponsorSignature,
    sponsor: message.sponsor,
    nonce: message.nonce,
    expires: message.expires,
    witness: getSimpleWitnessHash(message.mandate?.witnessArgument ?? 0n),
    witnessTypestring: "uint256 witnessArgument",
    id: message.id,
    allocatedAmount: message.amount,
    claimants: claimants.map(({ lockTag, claimant, amount }) => ({
      claimant: getClaimant(lockTag, claimant),
      amount: amount,
    })),
  };
}

function getRegistrationSlot(
  sponsor: Address,
  claimHash: Hash,
  typehash: Hash
): Hash {
  // _ACTIVE_REGISTRATIONS_SCOPE = 0x68a30dd0 -> 4 bytes.
  return keccak256(concatHex(["0x68a30dd0", sponsor, claimHash, typehash]));
}

export {
  getLockTag,
  getAllocatorId,
  getTokenId,
  getSimpleWitnessHash,
  getSignedCompact,
  getClaimHash,
  getClaimant,
  getClaimPayload,
  getRegistrationSlot,
};
