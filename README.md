# Terminull | Private Banking & Shielded Treasury Terminal

Terminull is an institutional-grade, zero-knowledge privacy terminal and treasury management suite deployed on **NullNet Mainnet** (Chain ID `448000`). It provides corporate entities, DAOs, and treasuries with encrypted transaction environments, masked transfer amounts, darkpool settlements, and local SQLite audit trail persistence.

---

## 🏛️ Core Architecture & Endpoints

- **Hosting & Server:** Hosted at `bridge.lunul.org` via PM2 on port `4008`.
- **Network:** NullNet Mainnet (RPC: `https://rpc.lunul.org`).
- **Smart Contracts:**
  - `ZKShieldedPool`: `0xC82681a28Bf26f6beb6b48442Ba9887a2872743B`
  - `Groth16Verifier`: `0x39e1451944d2F71F586850f81c12E9A8DA5A73b0`
  - `USDT (ERC-20)`: `0x7ec3659A8225ED474D7c662126616aE08545C29b` (**18 Decimals**)

---

## ⚡ Smart Contract Interaction Functions

### 1. `handleShield()` (Deposit & Shield)
Converts public naked assets (Native LUN or ERC-20 USDT) into encrypted zero-knowledge commitments.
- **Native LUN:** Calls `poolContract.depositNative(commitment, { value: parsedAmt })`.
- **ERC-20 USDT:** Executes an `approve()` transaction on the USDT contract, followed by `poolContract.depositToken(tokenAddr, parsedAmt, commitment)`.
- **Decimals Handling:** Automatically scales via `ethers.utils.parseUnits(val, 18)` to match the 18-decimal deployment of the custom stablecoin.

### 2. `handleWithdraw()` (Unshield Withdrawal)
Converts shielded notes back into public naked balances in the user's wallet.
- **Function Call:** Invokes `poolContract.transacting(...)` with a unique random `nullifier`, empty output commitments, and a public recipient address.
- **State Update:** Filters local storage notes to deduct the withdrawn amount and syncs live on-chain balances.

### 3. `handleUniversalSend()` (Flexible Privacy Transfers)
Supports three distinct institutional transfer modes:
- **Mode 1 (Normal Public Transfer):** Standard direct transfer on NullNet L1 (`signer.sendTransaction` for LUN, `erc20.transfer` for USDT). Fully visible on-chain.
- **Mode 2 (Private P2P - Masked Amount):** Routes through the shielded pool via `transacting()` where the recipient address is public but the transaction amount is masked.
- **Mode 3 (Full Darkpool):** Maximum privacy where both the recipient address and amount are hidden. Generates a secure encrypted payload and registers the note in the backend SQLite database inbox via `POST /api/notes/save`.

### 4. `handleClaim()` (Receive & DB Sync)
- **API Call:** Issues a `GET /api/notes/scan/${address}` request to the Express backend (`server.js`) to scan pending database records and synchronize incoming darkpool/private notes into the user's local storage inbox (`terminull_notes_*`).

---

## 📊 Balance Tracking & Formatting
- Maintained via dedicated UI display windows for **LUN Vault (Native)** and **USDT Vault (ERC-20)**.
- Automatically queries native balances (`provider.getBalance`) and ERC-20 balances (`usdtContract.balanceOf`) formatted precisely with `18 decimals` (`ethers.utils.formatUnits(rawUsdt, 18)`).
- Validates active shielded note commitments directly against on-chain state (`poolContract.commitments(note.commitment)`).

---

## 🚀 Local Setup & Deployment

1. **Clone Repository:**
   ```bash
   git clone [https://github.com/lunul-labs/zkbridge.git](https://github.com/lunul-labs/zkbridge.git)
   cd zkbridge
