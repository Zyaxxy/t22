use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    default_account_state_initialize, initialize_mint2, metadata_pointer_initialize,
    mint_close_authority_initialize, spl_token_2022, thaw_account as cpi_thaw_account,
    transfer_checked_with_fee, transfer_fee_initialize, DefaultAccountStateInitialize,
    InitializeMint2, MetadataPointerInitialize, MintCloseAuthorityInitialize,
    ThawAccount as CpiThawAccount, TokenInterface, TransferCheckedWithFee, TransferFeeInitialize,
};
use spl_token_2022::{
    extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensions, ExtensionType,
        StateWithExtensions,
    },
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};

use crate::error::RemittanceError;

#[derive(Accounts)]
pub struct CreateRemittanceMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Created and initialized in instruction handler
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferWithFee<'info> {
    /// CHECK: Mint account validated through StateWithExtensions
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Source account validated through StateWithExtensions
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,

    /// CHECK: Destination account validated by Token-2022 program
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ThawAccount<'info> {
    /// CHECK: Mint account validated through StateWithExtensions
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Token account to thaw, validated through StateWithExtensions
    #[account(mut, owner = token_program.key())]
    pub account_to_thaw: UncheckedAccount<'info>,

    pub freeze_authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Task 1: Create a remittance stablecoin mint stacking:
/// - TransferFeeConfig (protocol-level fee on every transfer for issuer revenue)
/// - MetadataPointer (pointed at the mint itself so wallets don't trust an off-chain registry)
/// - DefaultAccountState (AccountState::Frozen, forcing new accounts frozen until KYC clears)
/// - MintCloseAuthority (allows closing the mint if decommissioned)
///
/// Sized correctly via ExtensionType::try_calculate_account_len::<MintState>,
/// with every extension-init instruction ordered BEFORE InitializeMint2.
pub fn handler_create_remittance_mint(
    ctx: Context<CreateRemittanceMint>,
    decimals: u8,
    fee_basis_points: u16,
    maximum_fee: u64,
) -> Result<()> {
    let extensions = [
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ];

    // 1. Exact sizing via ExtensionType::try_calculate_account_len
    let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
    let lamports = Rent::get()?.minimum_balance(space);

    // Phase 1: Allocate account owned by Token-2022
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

    // Phase 2: Initialize EVERY extension BEFORE InitializeMint2

    // Extension 1: TransferFeeConfig
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

    // Extension 2: MetadataPointer pointed AT THE MINT ITSELF
    metadata_pointer_initialize(
        CpiContext::new(
            token_prog_key,
            MetadataPointerInitialize {
                token_program_id: token_program_info.clone(),
                mint: mint_info.clone(),
            },
        ),
        Some(ctx.accounts.payer.key()),
        Some(ctx.accounts.mint.key()), // Pointed at the mint itself
    )?;

    // Extension 3: DefaultAccountState initialized to Frozen
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

    // Extension 4: MintCloseAuthority
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

    // Phase 3: Seal mint with InitializeMint2 (freeze authority set to payer)
    initialize_mint2(
        CpiContext::new(
            token_prog_key,
            InitializeMint2 { mint: mint_info },
        ),
        decimals,
        &ctx.accounts.payer.key(),
        Some(&ctx.accounts.payer.key()), // freeze authority for KYC thawing
    )?;

    msg!(
        "Remittance mint {} created (len: {} bytes) with TransferFeeConfig, MetadataPointer, DefaultAccountState(Frozen), MintCloseAuthority",
        ctx.accounts.mint.key(),
        space
    );
    Ok(())
}

/// Task 2 & 3: Transfer function that:
/// - Uses transfer_checked_with_fee CPI
/// - Dynamically calculates the expected fee via calculate_epoch_fee(current_epoch, amount)
/// - Strictly reads mint and account state via StateWithExtensions, never raw unpack
pub fn handler_transfer_with_fee(
    ctx: Context<TransferWithFee>,
    amount: u64,
) -> Result<()> {
    // Read mint state exclusively through StateWithExtensions
    let (expected_fee, decimals) = {
        let mint_info = ctx.accounts.mint.to_account_info();
        let mint_data = mint_info.try_borrow_data()?;
        let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data)
            .map_err(|_| anchor_lang::error::ErrorCode::AccountDidNotDeserialize)?;

        // Extract TransferFeeConfig extension
        let fee_config = mint_state
            .get_extension::<TransferFeeConfig>()
            .map_err(|_| RemittanceError::MissingTransferFeeConfig)?;

        // Dynamic fee calculation based on current epoch
        let clock = Clock::get()?;
        let fee = fee_config
            .calculate_epoch_fee(clock.epoch, amount)
            .ok_or(RemittanceError::FeeCalculationError)?;
        (fee, mint_state.base.decimals)
    };

    // Read source account state exclusively through StateWithExtensions
    {
        let source_info = ctx.accounts.source.to_account_info();
        let source_data = source_info.try_borrow_data()?;
        let source_state = StateWithExtensions::<TokenAccountState>::unpack(&source_data)
            .map_err(|_| anchor_lang::error::ErrorCode::AccountDidNotDeserialize)?;

        require!(
            source_state.base.state != AccountState::Frozen,
            RemittanceError::AccountFrozen
        );
    }

    // Execute transfer_checked_with_fee CPI
    transfer_checked_with_fee(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferCheckedWithFee {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                source: ctx.accounts.source.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                destination: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ),
        amount,
        decimals,
        expected_fee,
    )?;

    msg!(
        "Transferred {} tokens with dynamic epoch fee {}",
        amount,
        expected_fee
    );
    Ok(())
}

/// Task 4: Unfreeze path:
/// Freeze authority thaws an individual account after KYC clearance,
/// separate from any mint-level default-state change.
pub fn handler_thaw_account(ctx: Context<ThawAccount>) -> Result<()> {
    // Verify freeze authority via StateWithExtensions
    {
        let mint_info = ctx.accounts.mint.to_account_info();
        let mint_data = mint_info.try_borrow_data()?;
        let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data)
            .map_err(|_| anchor_lang::error::ErrorCode::AccountDidNotDeserialize)?;

        let freeze_auth: Option<Pubkey> = mint_state.base.freeze_authority.into();
        require!(
            freeze_auth == Some(ctx.accounts.freeze_authority.key()),
            RemittanceError::InvalidFreezeAuthority
        );
    }

    // Read token account through StateWithExtensions
    {
        let acct_info = ctx.accounts.account_to_thaw.to_account_info();
        let acct_data = acct_info.try_borrow_data()?;
        let acct_state = StateWithExtensions::<TokenAccountState>::unpack(&acct_data)
            .map_err(|_| anchor_lang::error::ErrorCode::AccountDidNotDeserialize)?;
        require!(
            acct_state.base.state == AccountState::Frozen,
            RemittanceError::AccountAlreadyThawed
        );
    }

    // Execute thaw_account CPI
    cpi_thaw_account(CpiContext::new(
        ctx.accounts.token_program.key(),
        CpiThawAccount {
            account: ctx.accounts.account_to_thaw.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            authority: ctx.accounts.freeze_authority.to_account_info(),
        },
    ))?;

    msg!(
        "Account {} thawed after KYC verification by freeze authority {}. Mint default state remains Frozen.",
        ctx.accounts.account_to_thaw.key(),
        ctx.accounts.freeze_authority.key()
    );
    Ok(())
}
