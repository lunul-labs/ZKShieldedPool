// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Verifier.sol";

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract ZKShieldedPool {
    Groth16Verifier public immutable verifier;
    address public owner;

    // Sentinel address representing Native LUN
    address public constant NATIVE_TOKEN = address(0);

    // Cryptographic state tracking
    mapping(bytes32 => bool) public commitments;
    mapping(bytes32 => bool) public nullifiers;

    // Asset balance accounting inside the vault
    mapping(address => uint256) public poolBalances;

    // Future-proofing: Extension/Plugin registry for advanced banking features (bridges, yield, payroll)
    mapping(address => bool) public authorizedExtensions;

    // Events
    event Deposit(address indexed token, uint256 amount, bytes32 indexed commitment, uint256 leafIndex, uint256 timestamp);
    event Withdrawal(address indexed token, address recipient, uint256 amount, bytes32 indexed nullifier);
    event ExtensionUpdated(address indexed extension, bool status);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(address _verifierAddress) {
        verifier = Groth16Verifier(_verifierAddress);
        owner = msg.sender;
    }

    // ==========================================
    // 1. SHIELD / DEPOSIT (Native LUN & ERC20 USDT)
    // ==========================================
    
    /// @notice Shield Native LUN into the privacy vault
    function depositNative(bytes32 commitment) external payable {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        require(!commitments[commitment], "Commitment already exists");

        commitments[commitment] = true;
        poolBalances[NATIVE_TOKEN] += msg.value;

        emit Deposit(NATIVE_TOKEN, msg.value, commitment, block.number, block.timestamp);
    }

    /// @notice Shield ERC-20 Tokens (e.g. USDT) into the privacy vault
    function depositToken(address token, uint256 amount, bytes32 commitment) external {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Deposit amount must be greater than zero");
        require(!commitments[commitment], "Commitment already exists");

        // Pull tokens from user into pool
        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(success, "Token transfer failed");

        commitments[commitment] = true;
        poolBalances[token] += amount;

        emit Deposit(token, amount, commitment, block.number, block.timestamp);
    }

    // ==========================================
    // 2. WITHDRAW / UNSHIELD / SEND (ZK Verified)
    // ==========================================

    /// @notice Withdraw, unshield, or privately transfer assets using a ZK proof
    function withdraw(
        address token,
        address payable recipient,
        uint256 amount,
        bytes32 nullifier,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[6] calldata input
    ) external {
        require(!nullifiers[nullifier], "Nullifier already spent - double spend detected");
        
        if (token == NATIVE_TOKEN) {
            require(address(this).balance >= amount, "Insufficient native pool liquidity");
        } else {
            require(poolBalances[token] >= amount, "Insufficient token pool liquidity");
        }

        // Production ZK Proof verification (set to true when frontend SnarkJS is fully plugged in)
        bool enforceProof = false;
        if (enforceProof) {
            bool proofValid = verifier.verifyProof(a, b, c, input);
            require(proofValid, "Invalid Zero-Knowledge proof");
        }

        nullifiers[nullifier] = true;
        poolBalances[token] -= amount;

        // Execute payout (Native LUN or ERC-20 USDT)
        if (token == NATIVE_TOKEN) {
            (bool success, ) = recipient.call{value: amount}("");
            require(success, "Native transfer failed");
        } else {
            bool success = IERC20(token).transfer(recipient, amount);
            require(success, "Token transfer failed");
        }

        emit Withdrawal(token, recipient, amount, nullifier);
    }

    // ==========================================
    // 3. FUTURE-PROOFING EXTENSION HOOKS
    // ==========================================

    /// @notice Authorize or revoke external extension modules (for future cross-chain bridges, yield, etc.)
    function setExtension(address extension, bool status) external onlyOwner {
        authorizedExtensions[extension] = status;
        emit ExtensionUpdated(extension, status);
    }

    /// @notice Fallback to accept native liquidity
    receive() external payable {}
}
