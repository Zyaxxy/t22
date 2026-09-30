use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_interface::{
    default_account_state_initialize, initialize_mint2, metadata_pointer_initialize,
    mint_close_authority_initialize, permanent_delegate_initialize, transfer_checked,
    transfer_fee_initialize, DefaultAccountStateInitialize, InitializeMint2,
    MetadataPointerInitialize, MintCloseAuthorityInitialize, PermanentDelegateInitialize,
    TokenInterface, TransferChecked, TransferFeeInitialize, spl_token_2022,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{instruction as confidential_instruction, DecryptableBalance},
        confidential_transfer_fee::instruction as confidential_fee_instruction,
        ExtensionType,
    },
    state::{AccountState, Mint as MintState},
};

use crate::constants::AE_CIPHERTEXT_LEN;

#[derive(Accounts)]
pub struct CreateReissuedConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Created and initialized in handler
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Permanent delegate authority for seizures
    pub permanent_delegate: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Created and initialized in handler
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PermanentDelegateSeize<'info> {
    /// CHECK: Validated by Token-2022
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Source account from which tokens are seized
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,

    /// CHECK: Seizure destination account
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,

    /// Permanent delegate is signer (holder does not sign!)
    pub permanent_delegate: Signer<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// CHECK: Validated by Token-2022
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: Validated by Token-2022
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ApplyPendingBalance<'info> {
    /// CHECK: Validated by Token-2022
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
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
pub fn handler_create_reissued_confidential_mint(
    ctx: Context<CreateReissuedConfidentialMint>,
    decimals: u8,
    fee_basis_points: u16,
    maximum_fee: u64,
    withdraw_withheld_authority_elgamal_pubkey: [u8; 32],
) -> Result<()> {
    let extensions = [
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ];

    let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
    let lamports = Rent::get()?.minimum_balance(space);

    // Phase 1: Allocate mint account
    anchor_lang::system_program::create_account(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            anchor_lang::system_program::CreateAccount {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.mint.to_account_info(),
            },
        ),
        lamports,
        space as u64,
        &ctx.accounts.token_program.key(),
    )?;

    let token_program_info = ctx.accounts.token_program.to_account_info();
    let mint_info = ctx.accounts.mint.to_account_info();
    let token_prog_key = ctx.accounts.token_program.key();

    // Phase 2: Initialize ALL 7 extensions BEFORE InitializeMint2

    // 1. TransferFeeConfig
    transfer_fee_initialize(
        CpiContext::new(
            token_prog_key,
            TransferFeeInitialize {
                token_program_id: token_program_info.clone(),
                mint: mint_info.clone(),
            },
        ),
        Some(&ctx.accounts.payer.key()),
        Some(&ctx.accounts.payer.key()),
        fee_basis_points,
        maximum_fee,
    )?;

    // 2. MetadataPointer pointed at mint itself
    metadata_pointer_initialize(
        CpiContext::new(
            token_prog_key,
            MetadataPointerInitialize {
                token_program_id: token_program_info.clone(),
                mint: mint_info.clone(),
            },
        ),
        Some(ctx.accounts.payer.key()),
        Some(ctx.accounts.mint.key()),
    )?;

    // 3. DefaultAccountState (Frozen)
    default_account_state_initialize(
        CpiContext::new(
            token_prog_key,
            DefaultAccountStateInitialize {
                token_program_id: token_program_info.clone(),
                mint: mint_info.clone(),
            },
        ),
        &AccountState::Frozen,
    )?;

    // 4. MintCloseAuthority
    mint_close_authority_initialize(
        CpiContext::new(
            token_prog_key,
            MintCloseAuthorityInitialize {
                token_program_id: token_program_info.clone(),
                mint: mint_info.clone(),
            },
        ),
        Some(&ctx.accounts.payer.key()),
    )?;

    // 5. PermanentDelegate (seizure authority)
    permanent_delegate_initialize(
        CpiContext::new(
            token_prog_key,
            PermanentDelegateInitialize {
                token_program_id: token_program_info.clone(),
                mint: mint_info.clone(),
            },
        ),
        &ctx.accounts.permanent_delegate.key(),
    )?;

    // 6. ConfidentialTransferMint with approve_policy = manual (auto_approve_new_accounts = false)
    let ct_init_ix = confidential_instruction::initialize_mint(
        &ctx.accounts.token_program.key(),
        &ctx.accounts.mint.key(),
        Some(ctx.accounts.payer.key()), // confidential transfer mint authority
        false,                          // approve_policy = manual (auto_approve_new_accounts = false)
        None,                           // optional auditor ElGamal pubkey
    )?;
    invoke(
        &ct_init_ix,
        &[mint_info.clone(), token_program_info.clone()],
    )?;

    // 7. ConfidentialTransferFeeConfig (required by Token-2022 when TransferFeeConfig + ConfidentialTransferMint coexist)
    let ct_fee_ix = confidential_fee_instruction::initialize_confidential_transfer_fee_config(
        &ctx.accounts.token_program.key(),
        &ctx.accounts.mint.key(),
        Some(ctx.accounts.payer.key()),
        &withdraw_withheld_authority_elgamal_pubkey.into(),
    )?;
    invoke(
        &ct_fee_ix,
        &[mint_info.clone(), token_program_info.clone()],
    )?;

    // Phase 3: InitializeMint2
    initialize_mint2(
        CpiContext::new(
            token_prog_key,
            InitializeMint2 { mint: mint_info },
        ),
        decimals,
        &ctx.accounts.payer.key(),
        Some(&ctx.accounts.payer.key()),
    )?;

    msg!(
        "Re-issued mint {} with PermanentDelegate ({}) and ConfidentialTransfers (manual approval) created ({} bytes)",
        ctx.accounts.mint.key(),
        ctx.accounts.permanent_delegate.key(),
        space
    );
    Ok(())
}

/// Task 6: Pure confidential mint creation with configurable auto_approve_new_accounts
pub fn handler_create_confidential_mint(
    ctx: Context<CreateConfidentialMint>,
    decimals: u8,
    auto_approve_new_accounts: bool,
) -> Result<()> {
    let space = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let lamports = Rent::get()?.minimum_balance(space);

    anchor_lang::system_program::create_account(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            anchor_lang::system_program::CreateAccount {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.mint.to_account_info(),
            },
        ),
        lamports,
        space as u64,
        &ctx.accounts.token_program.key(),
    )?;

    let ix = confidential_instruction::initialize_mint(
        &ctx.accounts.token_program.key(),
        &ctx.accounts.mint.key(),
        Some(ctx.accounts.payer.key()),
        auto_approve_new_accounts,
        None,
    )?;
    invoke(
        &ix,
        &[
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;

    initialize_mint2(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            InitializeMint2 {
                mint: ctx.accounts.mint.to_account_info(),
            },
        ),
        decimals,
        &ctx.accounts.payer.key(),
        Some(&ctx.accounts.payer.key()),
    )?;

    msg!(
        "Confidential mint {} created ({} bytes, auto_approve: {})",
        ctx.accounts.mint.key(),
        space,
        auto_approve_new_accounts
    );
    Ok(())
}

/// Task 5: Permanent delegate seizure on plaintext token balance.
/// Seizes tokens from a sanctioned wallet without the owner's signature.
pub fn handler_permanent_delegate_seize(
    ctx: Context<PermanentDelegateSeize>,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.source.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.permanent_delegate.to_account_info(),
            },
        ),
        amount,
        decimals,
    )?;

    msg!(
        "Permanent delegate {} seized {} plaintext tokens from {} to {}",
        ctx.accounts.permanent_delegate.key(),
        amount,
        ctx.accounts.source.key(),
        ctx.accounts.destination.key()
    );
    Ok(())
}

/// Task 6: Deposit plaintext tokens into confidential pending balance.
pub fn handler_deposit_confidential(
    ctx: Context<DepositConfidential>,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    let ix = confidential_instruction::deposit(
        &ctx.accounts.token_program.key(),
        &ctx.accounts.token_account.key(),
        &ctx.accounts.mint.key(),
        amount,
        decimals,
        &ctx.accounts.authority.key(),
        &[],
    )?;
    invoke(
        &ix,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.authority.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;
    Ok(())
}

/// Task 6: Apply pending confidential balance into available confidential balance.
pub fn handler_apply_pending_balance(
    ctx: Context<ApplyPendingBalance>,
    expected_pending_balance_credit_counter: u64,
    new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
) -> Result<()> {
    let balance = DecryptableBalance::from(new_decryptable_available_balance);
    let ix = confidential_instruction::apply_pending_balance(
        &ctx.accounts.token_program.key(),
        &ctx.accounts.token_account.key(),
        expected_pending_balance_credit_counter,
        &balance,
        &ctx.accounts.authority.key(),
        &[],
    )?;
    invoke(
        &ix,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.authority.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;
    Ok(())
}
