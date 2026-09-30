use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        default_account_state::DefaultAccountState,
        metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority,
        transfer_fee::{TransferFeeAmount, TransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
const FEE_BASIS_POINTS: u16 = 250; // 2.5%
const MAXIMUM_FEE: u64 = 5_000;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    if path.exists() {
        svm.add_program_from_file(ID, &path).unwrap();
    }
    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    if let Err(e) = svm.send_transaction(tx) {
        panic!("tx failed: {:#?}, err: {:?}", e.meta.logs, e.err);
    }
    svm.expire_blockhash();
}

fn send_expecting_failure(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: &[Instruction],
    extra: &[&Keypair],
) -> String {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    let res = match svm.send_transaction(tx) {
        Ok(_) => panic!("expected failure, got success"),
        Err(e) => e.meta.logs.join("\n"),
    };
    svm.expire_blockhash();
    res
}

/// Helper: Creates a plain Token-2022 account for a user under a given mint.
fn create_token_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
    extensions: &[ExtensionType],
) -> Pubkey {
    let ta = Keypair::new();
    let space =
        ExtensionType::try_calculate_account_len::<TokenAccountState>(extensions).unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);

    send(
        svm,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), mint, owner).unwrap(),
        ],
        &[&ta],
    );
    ta.pubkey()
}

// ===========================================================================
// TASK 1 & TASK 3: Mint Creation, Extension Stacking, Sizing & State Inspection
// ===========================================================================

#[test]
fn test_task1_and_task3_remittance_mint_creation_and_state_with_extensions() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // Compute expected size with try_calculate_account_len
    let expected_extensions = [
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ];
    let expected_len =
        ExtensionType::try_calculate_account_len::<MintState>(&expected_extensions).unwrap();

    // Call Anchor instruction create_remittance_mint
    let ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateRemittanceMint {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateRemittanceMint {
            decimals: DECIMALS,
            fee_basis_points: FEE_BASIS_POINTS,
            maximum_fee: MAXIMUM_FEE,
        }
        .data(),
    };

    send(&mut svm, &payer, &[ix], &[&mint]);

    // Inspect mint account data
    let mint_acc = svm.get_account(&mint.pubkey()).unwrap();
    assert_eq!(
        mint_acc.data.len(),
        expected_len,
        "Mint account length must match ExtensionType::try_calculate_account_len"
    );

    // TASK 3: Read mint state EXCLUSIVELY through StateWithExtensions
    let state = StateWithExtensions::<MintState>::unpack(&mint_acc.data).unwrap();
    assert_eq!(state.base.decimals, DECIMALS);
    let mint_auth: Option<Pubkey> = state.base.mint_authority.into();
    let freeze_auth: Option<Pubkey> = state.base.freeze_authority.into();
    assert_eq!(mint_auth, Some(payer.pubkey()));
    assert_eq!(freeze_auth, Some(payer.pubkey()));

    // Verify Extension 1: TransferFeeConfig
    let fee_config = state.get_extension::<TransferFeeConfig>().unwrap();
    assert_eq!(
        u16::from(fee_config.newer_transfer_fee.transfer_fee_basis_points),
        FEE_BASIS_POINTS
    );
    assert_eq!(
        u64::from(fee_config.newer_transfer_fee.maximum_fee),
        MAXIMUM_FEE
    );

    // Verify Extension 2: MetadataPointer pointed AT THE MINT ITSELF
    let meta_ptr = state.get_extension::<MetadataPointer>().unwrap();
    let meta_addr: Option<Pubkey> = meta_ptr.metadata_address.into();
    let meta_auth: Option<Pubkey> = meta_ptr.authority.into();
    assert_eq!(
        meta_addr,
        Some(mint.pubkey()),
        "MetadataPointer MUST point at the mint itself"
    );
    assert_eq!(meta_auth, Some(payer.pubkey()));

    // Verify Extension 3: DefaultAccountState is Frozen
    let default_state = state.get_extension::<DefaultAccountState>().unwrap();
    assert_eq!(
        AccountState::try_from(default_state.state).unwrap(),
        AccountState::Frozen,
        "DefaultAccountState must be initialized to Frozen"
    );

    // Verify Extension 4: MintCloseAuthority
    let close_auth = state.get_extension::<MintCloseAuthority>().unwrap();
    let close_addr: Option<Pubkey> = close_auth.close_authority.into();
    assert_eq!(
        close_addr,
        Some(payer.pubkey()),
        "MintCloseAuthority must be set to payer"
    );

    println!("Task 1 & Task 3 PASSED: Mint created with all 4 extensions stacked, correctly sized at {expected_len} bytes, and verified exclusively via StateWithExtensions.");
}

// ===========================================================================
// TASK 1: Extension-Init Ordering Discipline
// ===========================================================================

#[test]
fn test_task1_extension_init_after_initialize_mint_must_fail() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    let extensions = [
        ExtensionType::TransferFeeConfig,
        ExtensionType::DefaultAccountState,
    ];
    let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions).unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);

    // If an extension initializer is ordered AFTER InitializeMint2, Token-2022 rejects it!
    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &mint.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            // Prematurely initialize mint before extensions
            t22new::instruction::initialize_mint2(
                &TOKEN_2022_PROGRAM_ID,
                &mint.pubkey(),
                &payer.pubkey(),
                Some(&payer.pubkey()),
                DECIMALS,
            )
            .unwrap(),
            // Extension init placed AFTER InitializeMint2 -> MUST FAIL
            t22new::extension::default_account_state::instruction::initialize_default_account_state(
                &TOKEN_2022_PROGRAM_ID,
                &mint.pubkey(),
                &AccountState::Frozen,
            )
            .unwrap(),
        ],
        &[&mint],
    );

    println!("Extension init after InitializeMint failure logs:\n{logs}");
    assert!(
        logs.contains("failed") || logs.contains("Error") || logs.contains("custom program error"),
        "Initializing extension after InitializeMint2 must be rejected by Token-2022"
    );
    println!("Task 1 Ordering Discipline PASSED: Token-2022 enforces all extension-init instructions occur BEFORE InitializeMint2.");
}

// ===========================================================================
// TASK 4: KYC Unfreeze Path (Thawing individual accounts)
// ===========================================================================

#[test]
fn test_task4_kyc_unfreeze_path() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // 1. Create remittance mint
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateRemittanceMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateRemittanceMint {
                decimals: DECIMALS,
                fee_basis_points: FEE_BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
            }
            .data(),
        }],
        &[&mint],
    );

    let alice = Keypair::new();
    let bob = Keypair::new();
    svm.airdrop(&alice.pubkey(), 10_000_000_000).unwrap();

    // 2. User creates an account under this mint.
    // Because DefaultAccountState is Frozen, the account MUST start frozen!
    let alice_account = create_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &alice.pubkey(),
        &[ExtensionType::TransferFeeAmount],
    );

    // Verify Alice's account starts frozen via StateWithExtensions
    let alice_data = svm.get_account(&alice_account).unwrap().data;
    let alice_state = StateWithExtensions::<TokenAccountState>::unpack(&alice_data).unwrap();
    assert_eq!(
        alice_state.base.state,
        AccountState::Frozen,
        "New account MUST start in Frozen state due to DefaultAccountState"
    );

    // 3. Attempting to mint to Alice while frozen MUST FAIL because account is frozen!
    let mint_fail_logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice_account,
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );
    assert!(
        mint_fail_logs.contains("Account is frozen") || mint_fail_logs.contains("frozen"),
        "Minting into frozen account must be blocked"
    );

    // 4. KYC Cleared: Freeze authority calls thaw_account on Alice's account
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ThawAccount {
                mint: mint.pubkey(),
                account_to_thaw: alice_account,
                freeze_authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ThawAccount {}.data(),
        }],
        &[],
    );

    // 5. Verify Alice's account is now Initialized (thawed)
    let alice_data = svm.get_account(&alice_account).unwrap().data;
    let alice_state = StateWithExtensions::<TokenAccountState>::unpack(&alice_data).unwrap();
    assert_eq!(
        alice_state.base.state,
        AccountState::Initialized,
        "Account must be thawed after KYC unfreeze"
    );

    // Now minting to Alice succeeds!
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice_account,
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );

    // 6. Crucial requirement: Verify mint-level default state REMAINS FROZEN
    let mint_data = svm.get_account(&mint.pubkey()).unwrap().data;
    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data).unwrap();
    let default_ext = mint_state.get_extension::<DefaultAccountState>().unwrap();
    assert_eq!(
        AccountState::try_from(default_ext.state).unwrap(),
        AccountState::Frozen,
        "Mint's default account state must remain Frozen even after individual thaw"
    );

    // 7. Verify subsequent new account (Bob) still defaults to Frozen
    let bob_account = create_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &bob.pubkey(),
        &[ExtensionType::TransferFeeAmount],
    );
    let bob_data = svm.get_account(&bob_account).unwrap().data;
    let bob_state = StateWithExtensions::<TokenAccountState>::unpack(&bob_data).unwrap();
    assert_eq!(
        bob_state.base.state,
        AccountState::Frozen,
        "Future accounts must still be created Frozen"
    );

    // Alice tries to transfer to Bob while Bob is frozen -> MUST FAIL!
    let transfer_fail_logs = send_expecting_failure(
        &mut svm,
        &alice,
        &[Instruction {
            program_id: ID,
            accounts: accounts::TransferWithFee {
                mint: mint.pubkey(),
                source: alice_account,
                destination: bob_account,
                authority: alice.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::TransferWithFee { amount: 1_000 }.data(),
        }],
        &[],
    );
    assert!(
        transfer_fail_logs.contains("frozen") || transfer_fail_logs.contains("AccountFrozen") || transfer_fail_logs.contains("custom program error"),
        "Transfer to frozen account must fail"
    );

    // 8. Bob clears KYC: freeze authority thaws Bob
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ThawAccount {
                mint: mint.pubkey(),
                account_to_thaw: bob_account,
                freeze_authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ThawAccount {}.data(),
        }],
        &[],
    );

    // Now Alice can transfer to Bob!
    send(
        &mut svm,
        &alice,
        &[Instruction {
            program_id: ID,
            accounts: accounts::TransferWithFee {
                mint: mint.pubkey(),
                source: alice_account,
                destination: bob_account,
                authority: alice.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::TransferWithFee { amount: 2_000 }.data(),
        }],
        &[],
    );

    println!("Task 4 KYC Unfreeze Path PASSED: Account thawed individually while mint default state remains frozen.");
}

// ===========================================================================
// TASK 2: Transfer Checked With Dynamic Epoch Fee
// ===========================================================================

#[test]
fn test_task2_transfer_with_dynamic_epoch_fee() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // 1. Create remittance mint with 250 bps fee (2.5%) and max fee 5000
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateRemittanceMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateRemittanceMint {
                decimals: DECIMALS,
                fee_basis_points: FEE_BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
            }
            .data(),
        }],
        &[&mint],
    );

    let alice = Keypair::new();
    let bob = Keypair::new();
    svm.airdrop(&alice.pubkey(), 10_000_000_000).unwrap();

    let alice_account = create_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &alice.pubkey(),
        &[ExtensionType::TransferFeeAmount],
    );
    let bob_account = create_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &bob.pubkey(),
        &[ExtensionType::TransferFeeAmount],
    );

    // KYC thaw for both
    send(
        &mut svm,
        &payer,
        &[
            Instruction {
                program_id: ID,
                accounts: accounts::ThawAccount {
                    mint: mint.pubkey(),
                    account_to_thaw: alice_account,
                    freeze_authority: payer.pubkey(),
                    token_program: TOKEN_2022_PROGRAM_ID,
                }
                .to_account_metas(None),
                data: instruction::ThawAccount {}.data(),
            },
            Instruction {
                program_id: ID,
                accounts: accounts::ThawAccount {
                    mint: mint.pubkey(),
                    account_to_thaw: bob_account,
                    freeze_authority: payer.pubkey(),
                    token_program: TOKEN_2022_PROGRAM_ID,
                }
                .to_account_metas(None),
                data: instruction::ThawAccount {}.data(),
            },
        ],
        &[],
    );

    // Mint 10_000 tokens to Alice
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice_account,
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );

    // Transfer 4_000 tokens from Alice to Bob using transfer_with_fee instruction
    // 250 bps = 2.5%: 4000 * 250 / 10000 = 100 tokens fee
    let transfer_amount = 4_000u64;
    let expected_fee = 100u64;

    send(
        &mut svm,
        &alice,
        &[Instruction {
            program_id: ID,
            accounts: accounts::TransferWithFee {
                mint: mint.pubkey(),
                source: alice_account,
                destination: bob_account,
                authority: alice.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::TransferWithFee {
                amount: transfer_amount,
            }
            .data(),
        }],
        &[],
    );

    // Verify balances via StateWithExtensions
    let alice_data = svm.get_account(&alice_account).unwrap().data;
    let alice_state = StateWithExtensions::<TokenAccountState>::unpack(&alice_data).unwrap();
    assert_eq!(alice_state.base.amount, 6_000);

    let bob_data = svm.get_account(&bob_account).unwrap().data;
    let bob_state = StateWithExtensions::<TokenAccountState>::unpack(&bob_data).unwrap();
    // Bob receives amount minus fee = 4000 - 100 = 3900
    assert_eq!(bob_state.base.amount, transfer_amount - expected_fee);

    // Withheld fee on destination account
    let fee_ext = bob_state.get_extension::<TransferFeeAmount>().unwrap();
    assert_eq!(u64::from(fee_ext.withheld_amount), expected_fee);

    println!("Task 2 Dynamic Fee Transfer PASSED: Transfer executed with dynamic calculate_epoch_fee (amount: {transfer_amount}, fee: {expected_fee}).");
}
