// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;



import "./Verifier.sol";



contract ZKShieldedPool {

    Groth16Verifier public immutable verifier;



    mapping(bytes32 => bool) public commitments;

    mapping(bytes32 => bool) public nullifiers;



    event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 timestamp);

    event Withdrawal(address recipient, bytes32 indexed nullifier);



    constructor(address _verifierAddress) {

        verifier = Groth16Verifier(_verifierAddress);

    }



    function deposit(bytes32 commitment) external payable {

        require(msg.value > 0, "Deposit amount must be greater than zero");

        require(!commitments[commitment], "Commitment already exists");



        commitments[commitment] = true;

        emit Deposit(commitment, block.number, block.timestamp);

    }

    function withdraw(

        address payable recipient,

        bytes32 nullifier,

        uint[2] calldata a,

        uint[2][2] calldata b,

        uint[2] calldata c,

        uint[6] calldata input

    ) external {

        require(!nullifiers[nullifier], "Nullifier already spent - double spend detected");



        bool proofValid = verifier.verifyProof(a, b, c, input);

        require(proofValid, "Invalid Zero-Knowledge proof");



        nullifiers[nullifier] = true;



        (bool success, ) = recipient.call{value: 1 ether}("");

        require(success, "Transfer failed");



        emit Withdrawal(recipient, nullifier);

    }

} 

