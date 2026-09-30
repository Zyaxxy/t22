use anchor_lang::prelude::*;

#[error_code]
pub enum RemittanceError {
    #[msg("Missing expected TransferFeeConfig extension on mint")]
    MissingTransferFeeConfig,
    #[msg("Calculation of transfer fee for current epoch failed")]
    FeeCalculationError,
    #[msg("Account is frozen and cannot transfer tokens")]
    AccountFrozen,
    #[msg("Signer is not the valid freeze authority")]
    InvalidFreezeAuthority,
    #[msg("Account is already thawed / initialized")]
    AccountAlreadyThawed,
}
