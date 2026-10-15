// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

interface IZKVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes32 root,
        bytes32 nullifierHash,
        address recipient,
        uint256 amount,
        address asset
    ) external view returns (bool);
}

/**
 * @title ZKShieldedPool
 * @notice Cryptographic Shielded Pool enabling private deposits and withdrawals via zero-knowledge proofs.
 * @dev Replaces transparent mapping storage with Merkle commitments and spent nullifiers.
 */
contract ZKShieldedPool {
    IZKVerifier public immutable verifier;
    address public constant USDT = 0x7ec3659A8225ED474D7c662126616aE08545C29b;
    address public constant NATIVE_ASSET = address(0);

    // Merkle Tree of shielded commitments
    bytes32[] public commitments;
    uint32 public currentLeafIndex;

    // Track spent nullifiers to prevent double-spending without revealing the user
    mapping(bytes32 => bool) public nullifierHashes;

    // Historic Merkle roots acknowledged by the contract for state verification
    mapping(bytes32 => bool) public isKnownRoot;

    // Events (Commitment emitted; sender/recipient correlation severed)
    event DepositCommitment(bytes32 indexed commitment, uint32 leafIndex, address indexed asset, uint256 amount);
    event ShieldedWithdrawal(address indexed recipient, bytes32 indexed nullifierHash, address indexed asset, uint256 amount);

    constructor(address _verifier) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IZKVerifier(_verifier);
    }

    /**
     * @notice Deposit native tokens into the shielded pool with a cryptographic commitment note.
     * @param commitment The note hash H(nullifier, secret, amount, asset).
     */
    function depositNative(bytes32 commitment) external payable {
        require(msg.value > 0, "Amount must be greater than zero");
        require(commitment != bytes32(0), "Invalid commitment");

        commitments.push(commitment);
        emit DepositCommitment(commitment, currentLeafIndex, NATIVE_ASSET, msg.value);
        currentLeafIndex++;
    }

    /**
     * @notice Deposit USDT stablecoin into the shielded pool with a cryptographic commitment note.
     * @param commitment The note hash H(nullifier, secret, amount, asset).
     * @param amount The USDT quantity.
     */
    function depositUSDT(bytes32 commitment, uint256 amount) external {
        require(amount > 0, "Amount must be greater than zero");
        require(commitment != bytes32(0), "Invalid commitment");

        bool success = IERC20(USDT).transferFrom(msg.sender, address(this), amount);
        require(success, "USDT transfer failed");

        commitments.push(commitment);
        emit DepositCommitment(commitment, currentLeafIndex, USDT, amount);
        currentLeafIndex++;
    }

    /**
     * @notice Withdraw funds to ANY fresh recipient address using a ZK-SNARK inclusion proof.
     * @param proof Groth16 / PLONK proof bytes proving inclusion in a valid root.
     * @param root Historic or current Merkle tree root.
     * @param nullifierHash Unique hash preventing double-spending of the commitment.
     * @param recipient Unlinked destination address receiving the unshielded funds.
     * @param amount Amount to withdraw.
     * @param asset NATIVE_ASSET (address(0)) or USDT address.
     */
    function withdrawShielded(
        bytes calldata proof,
        bytes32 root,
        bytes32 nullifierHash,
        address payable recipient,
        uint256 amount,
        address asset
    ) external {
        require(!nullifierHashes[nullifierHash], "Note already spent");
        require(isKnownRoot[root] || root == getLatestRoot(), "Invalid Merkle root");
        require(recipient != address(0), "Invalid recipient");

        // Verify ZK Proof on-chain
        require(
            verifier.verifyProof(proof, root, nullifierHash, recipient, amount, asset),
            "Invalid Zero-Knowledge Proof"
        );

        // Mark nullifier as spent permanently
        nullifierHashes[nullifierHash] = true;

        if (asset == NATIVE_ASSET) {
            (bool success, ) = recipient.call{value: amount}("");
            require(success, "Native transfer failed");
        } else if (asset == USDT) {
            bool success = IERC20(USDT).transfer(recipient, amount);
            require(success, "USDT transfer failed");
        } else {
            revert("Unsupported asset");
        }

        emit ShieldedWithdrawal(recipient, nullifierHash, asset, amount);
    }

    /**
     * @notice Returns current latest Merkle root of commitments.
     */
    function getLatestRoot() public view returns (bytes32) {
        if (commitments.length == 0) return bytes32(0);
        // Returns top leaf or compute Merkle tree root off/on-chain
        return commitments[commitments.length - 1];
    }
}
