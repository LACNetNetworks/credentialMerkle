// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

import "./lib/MerkleProof.sol";

contract Verifier {

    function isValid(
        bytes32[] memory _proof,
        bytes32 _root,
        bytes32 _leaf
    ) external returns (bool){
        return MerkleProof.verify(_proof,_root,_leaf);
    }
}