// SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.0 <0.9.0;

import "../utils/ZgsSpec.sol";
import "../utils/Blake2b.sol";
import "./RecallRange.sol";

library MineLib {
    struct PoraAnswer {
        bytes32 contextDigest;
        bytes32 nonce;
        bytes32 minerId;
        RecallRange range;
        uint recallPosition;
        uint sealOffset;
        bytes32 sealedContextDigest;
        bytes32[UNITS_PER_SEAL] sealedData;
        bytes32[] merkleProof;
    }

    function computeScratchPadAndMix(
        bytes32[UNITS_PER_SEAL] memory sealedData,
        uint skipSeals,
        bytes32[2] memory padDigest
    ) internal view returns (bytes32[2] memory recallSeed, bytes32[UNITS_PER_SEAL] memory mixedData) {
        // Compute the scratch pad and mix data for the mining process
        for (uint i = 0; i < skipSeals; i++) {
            for (uint j = 0; j < BHASHES_PER_SEAL; j++) {
                padDigest = Blake2b.blake2b(padDigest);
            }
        }

        for (uint i = 0; i < UNITS_PER_SEAL; i += 2) {
            padDigest = Blake2b.blake2b(padDigest);
            mixedData[i] = padDigest[0] ^ sealedData[i];
            mixedData[i + 1] = padDigest[1] ^ sealedData[i + 1];
        }

        for (uint i = skipSeals + 1; i < SEALS_PER_PAD; i++) {
            for (uint j = 0; j < BHASHES_PER_SEAL; j++) {
                padDigest = Blake2b.blake2b(padDigest);
            }
        }

        recallSeed = padDigest;
    }

    function computePoraHash(
        uint sealOffset,
        bytes32[2] memory padSeed,
        bytes32[UNITS_PER_SEAL] memory mixedData
    ) internal view returns (bytes32) {
        // Compute the PoRA (Proof of Random Access) hash for sealing
        bytes32[2] memory h = [
            Blake2b.BLAKE2B_INIT_STATE0,
            Blake2b.BLAKE2B_INIT_STATE1
        ];

        h = Blake2b.blake2bF(h, bytes32(sealOffset), padSeed[0], padSeed[1], bytes32(0), 128, false);
        for (uint i = 0; i < UNITS_PER_SEAL - 4; i += 4) {
            uint length = 128 + 32 * (i + 4);
            h = Blake2b.blake2bF(h, mixedData[i], mixedData[i + 1], mixedData[i + 2], mixedData[i + 3], length, false);
        }
        h = Blake2b.blake2bF(
            h,
            mixedData[UNITS_PER_SEAL - 4],
            mixedData[UNITS_PER_SEAL - 3],
            mixedData[UNITS_PER_SEAL - 2],
            mixedData[UNITS_PER_SEAL - 1],
            128 + UNITS_PER_SEAL * 32,
            true
        );
        return h[0];
    }

    function unseal(PoraAnswer memory answer) internal pure returns (bytes32[UNITS_PER_SEAL] memory unsealedData) {
        // Unseal the sealed data using the miner's ID and sealed context digest
        unsealedData[0] = answer.sealedData[0] ^
            keccak256(abi.encode(answer.minerId, answer.sealedContextDigest, answer.recallPosition));
        for (uint i = 1; i < UNITS_PER_SEAL; i++) {
            unsealedData[i] = answer.sealedData[i] ^ keccak256(abi.encode(answer.sealedData[i - 1]));
        }
    }

    function recoverMerkleRoot(
        PoraAnswer memory answer,
        bytes32[UNITS_PER_SEAL] memory unsealedData
    ) internal pure returns (bytes32) {
        // Recover the Merkle root from the unsealed data and the provided Merkle proof
        for (uint i = 0; i < UNITS_PER_SEAL; i += UNITS_PER_SECTOR) {
            unsealedData[i] = keccak256(abi.encodePacked(unsealedData, i * 32));
        }

        for (uint i = UNITS_PER_SECTOR; i < UNITS_PER_SEAL; i <<= 1) {
            for (uint j = 0; j < UNITS_PER_SEAL; j += i << 1) {
                unsealedData[j] = keccak256(abi.encodePacked(unsealedData[j], unsealedData[j + i]));
            }
        }

        bytes32 currentHash = unsealedData[0];
        delete unsealedData;

        uint unsealedIndex = answer.recallPosition / SECTORS_PER_SEAL;
        for (uint i = 0; i < answer.merkleProof.length; i++) {
            currentHash = unsealedIndex % 2 == 0
                ? keccak256(abi.encodePacked(currentHash, answer.merkleProof[i]))
                : keccak256(abi.encodePacked(answer.merkleProof[i], currentHash));
            unsealedIndex /= 2;
        }
        return currentHash;
    }
}
