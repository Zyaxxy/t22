use anchor_lang::prelude::*;

pub mod constants;
pub mod error;
pub mod instructions;

pub use constants::*;
pub use error::*;
pub use instructions::*;

declare_id!("CLc5wT5gfXcER5UDoWFHiqRuWAUthdrU7pLXW92wssNB");

#[program]
pub mod t22 {
    use super::*;

    /// Task 1: Create a remittance stablecoin mint stacking:
    /// - TransferFeeConfig (protocol-level fee on every transfer for issuer revenue)
    /// - MetadataPointer (pointed at the mint itself so wallets don't trust an off-chain registry)
    /// - DefaultAccountState (AccountState::Frozen, forcing new accounts frozen until KYC clears)
    /// - MintCloseAuthority (allows closing the mint if decommissioned)
    ///
    /// Sized correctly via ExtensionType::try_calculate_account_len::<MintState>,
    /// with every extension-init instruction ordered BEFORE InitializeMint2.
    pub fn create_remittance_mint(
        ctx: Context<CreateRemittanceMint>,
        decimals: u8,
        fee_basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        instructions::remittance::handler_create_remittance_mint(
            ctx,
            decimals,
            fee_basis_points,
            maximum_fee,
        )
    }

    /// Task 2 & 3: Transfer function that:
    /// - Uses transfer_checked_with_fee CPI
    /// - Dynamically calculates the expected fee via calculate_epoch_fee(current_epoch, amount)
    /// - Strictly reads mint and account state via StateWithExtensions, never raw unpack
    pub fn transfer_with_fee(ctx: Context<TransferWithFee>, amount: u64) -> Result<()> {
        instructions::remittance::handler_transfer_with_fee(ctx, amount)
    }

    /// Task 4: Unfreeze path:
    /// Freeze authority thaws an individual account after KYC clearance,
    /// separate from any mint-level default-state change.
    pub fn thaw_account(ctx: Context<ThawAccount>) -> Result<()> {
        instructions::remittance::handler_thaw_account(ctx)
    }

    /// Task 5: Re-issue the mint carrying forward the same extension set:
    /// - TransferFeeConfig
    /// - MetadataPointer (pointed at mint itself)
    /// - DefaultAccountState (Frozen)
    /// - MintCloseAuthority
    /// PLUS:
    /// - PermanentDelegate (seizure authority)
    /// - ConfidentialTransferMint (confidential transfers enabled with approve_policy = manual, i.e. auto_approve_new_accounts = false)
    /// - ConfidentialTransferFeeConfig (required by Token-2022 when TransferFeeConfig + ConfidentialTransferMint coexist)
    ///
    /// Sized via ExtensionType::try_calculate_account_len and all extension inits ordered before InitializeMint2.
    pub fn create_reissued_confidential_mint(
        ctx: Context<CreateReissuedConfidentialMint>,
        decimals: u8,
        fee_basis_points: u16,
        maximum_fee: u64,
        withdraw_withheld_authority_elgamal_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::confidential::handler_create_reissued_confidential_mint(
            ctx,
            decimals,
            fee_basis_points,
            maximum_fee,
            withdraw_withheld_authority_elgamal_pubkey,
        )
    }

    /// Task 6: Pure confidential mint creation with configurable auto_approve_new_accounts
    pub fn create_confidential_mint(
        ctx: Context<CreateConfidentialMint>,
        decimals: u8,
        auto_approve_new_accounts: bool,
    ) -> Result<()> {
        instructions::confidential::handler_create_confidential_mint(
            ctx,
            decimals,
            auto_approve_new_accounts,
        )
    }

    /// Task 5: Permanent delegate seizure on plaintext token balance.
    /// Seizes tokens from a sanctioned wallet without the owner's signature.
    pub fn permanent_delegate_seize(
        ctx: Context<PermanentDelegateSeize>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        instructions::confidential::handler_permanent_delegate_seize(ctx, amount, decimals)
    }

    /// Task 6: Deposit plaintext tokens into confidential pending balance.
    pub fn deposit_confidential(
        ctx: Context<DepositConfidential>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        instructions::confidential::handler_deposit_confidential(ctx, amount, decimals)
    }

    /// Task 6: Apply pending confidential balance into available confidential balance.
    pub fn apply_pending_balance(
        ctx: Context<ApplyPendingBalance>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    ) -> Result<()> {
        instructions::confidential::handler_apply_pending_balance(
            ctx,
            expected_pending_balance_credit_counter,
            new_decryptable_available_balance,
        )
    }
}
