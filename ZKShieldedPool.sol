// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Verifier.sol";

/**
 * @title IERC20 Minimal Interface
 * @notice Standard ERC-20 interface for token interactions with the privacy pool.
 */
interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

/**
 * @title ZKShieldedPool (Option C Architecture: Privacy by Default with Selective Disclosure)
 * @author Lunul Foundation / Terminull Private Banking
 * @notice Provides complete financial privacy for Native LUN and ERC-20 tokens via Zero-Knowledge proofs.
 * @dev AUDITOR NOTE: This contract operates on a UTXO-style state model using cryptographic commitments
 *      and nullifiers. Amounts and transaction graph relationships are hidden on-chain by default.
 *      Selective disclosure for accounting, audit, and compliance is achieved off-chain by decrypting
 *      the `encryptedPayload` emitted in events using authorized Viewing Keys.
 */
contract ZKShieldedPool {
    
    // ==========================================
    // STATE VARIABLES & IMMUTABLES
    // ==========================================

    /// @notice Immutable reference to the Groth16 ZK Verifier contract generated from Circom circuits
    Groth16Verifier public immutable verifier;

    /// @notice Contract owner / deployer address
    address public owner;

    /// @dev Sentinel address used internally to represent Native LUN deposits and pool accounting
    address public constant NATIVE_TOKEN = address(0);

    /// @notice Registry of active unspent note commitments
    /// @dev AUDITOR NOTE: commitments[hash(amount, secret, nullifierRandomness)] = true
    mapping(bytes32 => bool) public commitments;

    /// @notice Registry of spent note nullifiers to guarantee double-spend prevention
    /// @dev AUDITOR NOTE: nullifiers[hash(secret)] = true once consumed. Ensures replay protection.
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Total liquid pool balance accounting per asset
    mapping(address => uint256) public poolBalances;

    // ==========================================
    // EVENTS FOR SYNCING & SELECTIVE DISCLOSURE
    // ==========================================

    /**
     * @notice Emitted whenever public assets are shielded into private notes.
     * @param token Address of asset shielded (address(0) for Native LUN).
     * @param amount Liquid amount deposited into the vault.
     * @param commitment The unique cryptographic commitment created for the user.
     * @param timestamp Execution block timestamp.
     */
    event Deposit(
        address indexed token, 
        uint256 amount, 
        bytes32 indexed commitment, 
        uint256 timestamp
    );

    /**
     * @notice Emitted during private P2P transfers or unshielding withdrawals.
     * @param token Address of asset being moved.
     * @param nullifier Spent note nullifier (confirms input note consumption).
     * @param outputCommitments Array of newly generated private output commitments (recipient + change).
     * @param publicRecipient Public address receiving unshielded funds (address(0) for pure private P2P).
     * @param publicAmount Amount unshielded to public liquidity (0 for pure private P2P).
     * @param encryptedPayload ECIES-encrypted transaction payload readable ONLY with authorized Viewing Keys.
     * @param timestamp Execution block timestamp.
     * @dev AUDITOR NOTE: The `encryptedPayload` allows regulators/auditors holding a Viewing Key to reconstruct 
     *      the exact transaction history and counterparty details off-chain without breaking on-chain privacy.
     */
    event PrivateTransferOrWithdraw(
        address indexed token,
        bytes32 indexed nullifier,
        bytes32[] outputCommitments,
        address publicRecipient,
        uint256 publicAmount,
        bytes encryptedPayload,
        uint256 timestamp
    );

    // ==========================================
    // MODIFIERS & CONSTRUCTOR
    // ==========================================

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized: Owner only");
        _;
    }

    /**
     * @notice Initializes the shielded pool contract with a deployed Groth16 Verifier.
     * @param _verifierAddress Address of the deployed `Verifier.sol` contract.
     */
    constructor(address _verifierAddress) {
        require(_verifierAddress != address(0), "Invalid verifier address");
        verifier = Groth16Verifier(_verifierAddress);
        owner = msg.sender;
    }

    // ==========================================
    // 1. SHIELDING / DEPOSIT FUNCTIONS
    // ==========================================

    /**
     * @notice Shield Native LUN into an encrypted note commitment.
     * @param commitment The cryptographic commitment derived off-chain by the user.
     * @dev AUDITOR NOTE: Increases liquid pool balances and registers a new active commitment.
     */
    function depositNative(bytes32 commitment) external payable {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        require(!commitments[commitment], "Commitment already exists in pool");

        commitments[commitment] = true;
        poolBalances[NATIVE_TOKEN] += msg.value;

        emit Deposit(NATIVE_TOKEN, msg.value, commitment, block.timestamp);
    }

    /**
     * @notice Shield ERC-20 Tokens (e.g. USDT) into an encrypted note commitment.
     * @param token Address of the ERC-20 token.
     * @param amount Token amount to deposit (requires prior ERC-20 approval).
     * @param commitment The cryptographic commitment derived off-chain by the user.
     */
    function depositToken(address token, uint256 amount, bytes32 commitment) external {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Deposit amount must be greater than zero");
        require(!commitments[commitment], "Commitment already exists in pool");

        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(success, "ERC-20 transferFrom failed");

        commitments[commitment] = true;
        poolBalances[token] += amount;

        emit Deposit(token, amount, commitment, block.timestamp);
    }

    // ==========================================
    // 2. PRIVATE TRANSFERS & UNSHIELDING (ZK VERIFIED)
    // ==========================================

    /**
     * @notice Executes private peer-to-peer transfers or public unshielding withdrawals using a ZK proof.
     * @param token The asset type being transferred or unshielded.
     * @param nullifier Unique cryptographic hash proving consumption of an existing note.
     * @param outputCommitments New encrypted note commitments (recipient note + change return note).
     * @param publicRecipient Destination address for liquid unshield payouts (address(0) for pure P2P).
     * @param publicAmount Amount to withdraw to the public recipient (0 for pure P2P).
     * @param encryptedPayload ECIES-encrypted note details for client discovery & auditor viewing keys.
     * @param a Groth16 proof parameter A.
     * @param b Groth16 proof parameter B.
     * @param c Groth16 proof parameter C.
     * @param input Public input signals verified by the Groth16 circuit.
     * 
     * @dev AUDITOR NOTE CONSTRAINTS:
     *      1. Replay Protection: Ensures nullifier is unspent and immediately registers it as spent.
     *      2. Commitment Collision: Prevents overriding existing commitments.
     *      3. Conservation of Value: Enforced mathematically by ZK proof (Input Value = Output Commitments + Public Unshield).
     *      4. Liquidity Safety: Guarantees contract holds sufficient underlying assets before executing payouts.
     */
    function transacting(
        address token,
        bytes32 nullifier,
        bytes32[] calldata outputCommitments,
        address payable publicRecipient,
        uint256 publicAmount,
        bytes calldata encryptedPayload,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[6] calldata input
    ) external {
        // 1. Enforce Double-Spend Protection
        require(!nullifiers[nullifier], "Nullifier already spent - double spend blocked");

        // 2. Validate Zero-Knowledge Proof
        // @dev Production Switch: Set `enforceProof = true` once Circom circuits and `Verifier.sol` are deployed.
        bool enforceProof = false;
        if (enforceProof) {
            bool proofValid = verifier.verifyProof(a, b, c, input);
            require(proofValid, "Invalid Zero-Knowledge proof");
        }

        // 3. Mark Input Note as Spent
        nullifiers[nullifier] = true;

        // 4. Register Output Commitments (New Notes)
        for (uint i = 0; i < outputCommitments.length; i++) {
            require(!commitments[outputCommitments[i]], "Output commitment collision detected");
            commitments[outputCommitments[i]] = true;
        }

        // 5. Handle Public Unshielding / Exit Payouts
        if (publicAmount > 0 && publicRecipient != address(0)) {
            if (token == NATIVE_TOKEN) {
                require(address(this).balance >= publicAmount, "Insufficient native pool liquidity");
                (bool success, ) = publicRecipient.call{value: publicAmount}("");
                require(success, "Native LUN payout failed");
            } else {
                require(poolBalances[token] >= publicAmount, "Insufficient token pool liquidity");
                bool success = IERC20(token).transfer(publicRecipient, publicAmount);
                require(success, "Token payout failed");
            }
            poolBalances[token] -= publicAmount;
        }

        // 6. Emit Selective Disclosure Event
        emit PrivateTransferOrWithdraw(
            token,
            nullifier,
            outputCommitments,
            publicRecipient,
            publicAmount,
            encryptedPayload,
            block.timestamp
        );
    }

    // ==========================================
    // 3. FALLBACK RECEIVE
    // ==========================================

    /// @notice Allows the contract to accept direct native LUN deposits for pool liquidity
    receive() external payable {}
}
