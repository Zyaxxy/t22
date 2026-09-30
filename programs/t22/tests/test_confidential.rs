use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use proofext::instruction::ProofLocation;
use proofgen::{transfer::transfer_split_proof_data, withdraw::withdraw_proof_data};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::num::NonZeroI8;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        confidential_transfer::{
            instruction as ct_ix, ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        default_account_state::DefaultAccountState,
        metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority,
        permanent_delegate::PermanentDelegate,
        transfer_fee::{TransferFeeAmount, TransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use zk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        derivation::derive_confidential_keys,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use zkif::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::ZkProofData,
    state::ProofContextState,
};

const ZK_PROGRAM_ID: Pubkey = zkif::ID;
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

struct Holder {
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn read_ct(svm: &LiteSVM, account: &Pubkey) -> ConfidentialTransferAccount {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    *state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

fn available_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let ciphertext: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    elgamal.secret().decrypt_u32(&ciphertext).unwrap()
}

fn pending_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let lo: ElGamalCiphertext = ct.pending_balance_lo.try_into().unwrap();
    let hi: ElGamalCiphertext = ct.pending_balance_hi.try_into().unwrap();
    let lo = elgamal.secret().decrypt_u32(&lo).unwrap();
    let hi = elgamal.secret().decrypt_u32(&hi).unwrap();
    lo + (hi << 16)
}

fn apply_pending(svm: &mut LiteSVM, payer: &Keypair, holder: &Holder, owner: &Keypair) {
    let ct = read_ct(svm, &holder.account);
    let counter: u64 = ct.pending_balance_credit_counter.into();
    let new_available =
        available_balance(&ct, &holder.elgamal) + pending_balance(&ct, &holder.elgamal);
    let ciphertext: [u8; 36] = holder.aes.encrypt(new_available).to_bytes();

    let ix = Instruction {
        program_id: ID,
        accounts: accounts::ApplyPendingBalance {
            token_account: holder.account,
            authority: owner.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: ciphertext,
        }
        .data(),
    };
    send(svm, payer, &[ix], &[owner]);
}

fn stage_proof<T, U>(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instruction_kind: ProofInstruction,
    proof: &T,
) -> Pubkey
where
    T: bytemuck::Pod + ZkProofData<U>,
    U: bytemuck::Pod,
{
    let context_len = std::mem::size_of::<ProofContextState<U>>();
    let context = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(context_len);
    send(
        svm,
        payer,
        &[solana_system_interface::instruction::create_account(
            &payer.pubkey(),
            &context.pubkey(),
            lamports,
            context_len as u64,
            &ZK_PROGRAM_ID,
        )],
        &[&context],
    );
    let ix = instruction_kind.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &context.pubkey(),
            context_state_authority: &payer.pubkey(),
        }),
        proof,
    );
    send(
        svm,
        payer,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(400_000),
            ix,
        ],
        &[],
    );
    context.pubkey()
}

fn close_contexts(svm: &mut LiteSVM, payer: &Keypair, contexts: &[Pubkey]) -> u64 {
    let before = svm.get_balance(&payer.pubkey()).unwrap();
    let ixs: Vec<Instruction> = contexts
        .iter()
        .map(|c| {
            close_context_state(
                ContextStateInfo {
                    context_state_account: c,
                    context_state_authority: &payer.pubkey(),
                },
                &payer.pubkey(),
            )
        })
        .collect();
    send(svm, payer, &ixs, &[]);
    for c in contexts {
        assert!(svm
            .get_account(c)
            .map(|a| a.data.is_empty())
            .unwrap_or(true));
    }
    svm.get_balance(&payer.pubkey())
        .unwrap()
        .saturating_sub(before)
}

fn create_token_account_with_extensions(
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
// TASK 5: Mint Re-issuance, Seizure Authority & The Gap Analysis
// ===========================================================================

#[test]
fn test_task5_reissued_mint_creation_and_extensions() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let permanent_delegate = Keypair::new();

    // The fee is withheld as an ElGamal ciphertext, so the withdraw withheld
    // authority needs an ElGamal key pair.
    let (fee_authority_elgamal, _) = derive_confidential_keys(&payer, b"").unwrap();
    let fee_authority_pubkey: [u8; 32] = fee_authority_elgamal.pubkey().into();

    // 1. Re-issue mint stacking all extensions:
    // - TransferFeeConfig
    // - MetadataPointer
    // - DefaultAccountState (Frozen)
    // - MintCloseAuthority
    // - PermanentDelegate
    // - ConfidentialTransferMint (auto_approve_new_accounts = false)
    // - ConfidentialTransferFeeConfig (Token-2022 architectural requirement when transfer fee + confidential mint coexist)
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateReissuedConfidentialMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                permanent_delegate: permanent_delegate.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateReissuedConfidentialMint {
                decimals: DECIMALS,
                fee_basis_points: FEE_BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
                withdraw_withheld_authority_elgamal_pubkey: fee_authority_pubkey,
            }
            .data(),
        }],
        &[&mint],
    );

    // 2. Validate mint account length matches try_calculate_account_len exactly
    let mint_data = svm.get_account(&mint.pubkey()).unwrap().data;
    let expected_len = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ])
    .unwrap();
    assert_eq!(mint_data.len(), expected_len);
    assert_eq!(mint_data.len(), 625);

    // 3. Inspect mint exclusively through StateWithExtensions
    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data).unwrap();
    let extensions = mint_state.get_extension_types().unwrap();

    assert!(extensions.contains(&ExtensionType::TransferFeeConfig));
    assert!(extensions.contains(&ExtensionType::MetadataPointer));
    assert!(extensions.contains(&ExtensionType::DefaultAccountState));
    assert!(extensions.contains(&ExtensionType::MintCloseAuthority));
    assert!(extensions.contains(&ExtensionType::PermanentDelegate));
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferMint));
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferFeeConfig));

    // Verify TransferFeeConfig and MintCloseAuthority
    let tf_config = mint_state.get_extension::<TransferFeeConfig>().unwrap();
    assert_eq!(u16::from(tf_config.newer_transfer_fee.transfer_fee_basis_points), FEE_BASIS_POINTS);
    let close_auth = mint_state.get_extension::<MintCloseAuthority>().unwrap();
    let close_auth_pubkey: Option<Pubkey> = close_auth.close_authority.into();
    assert_eq!(close_auth_pubkey, Some(payer.pubkey()));

    // Verify PermanentDelegate
    let pd = mint_state.get_extension::<PermanentDelegate>().unwrap();
    let pd_pubkey: Option<Pubkey> = pd.delegate.into();
    assert_eq!(pd_pubkey, Some(permanent_delegate.pubkey()));

    // Verify ConfidentialTransferMint manual approval policy
    let ct_mint = mint_state
        .get_extension::<ConfidentialTransferMint>()
        .unwrap();
    assert_eq!(
        bool::from(ct_mint.auto_approve_new_accounts),
        false,
        "ConfidentialTransferMint must require manual approval"
    );

    // Verify MetadataPointer points to mint itself
    let meta_ptr = mint_state.get_extension::<MetadataPointer>().unwrap();
    let meta_addr: Option<Pubkey> = meta_ptr.metadata_address.into();
    assert_eq!(meta_addr, Some(mint.pubkey()));

    // Verify DefaultAccountState is Frozen
    let def_state = mint_state.get_extension::<DefaultAccountState>().unwrap();
    assert_eq!(
        AccountState::try_from(def_state.state).unwrap(),
        AccountState::Frozen
    );

    println!(
        "Task 5 Mint Re-issuance PASSED: Stacks all extensions (625 bytes), with PermanentDelegate, ConfidentialTransfers, and manual approval policy."
    );
}

#[test]
fn test_task5_permanent_delegate_seizure_and_the_gap() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let permanent_delegate = Keypair::new();
    let treasury = Keypair::new();
    let sanctioned_user = Keypair::new();

    let (fee_authority_elgamal, _) = derive_confidential_keys(&payer, b"").unwrap();
    let fee_authority_pubkey: [u8; 32] = fee_authority_elgamal.pubkey().into();

    // Re-issue mint
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateReissuedConfidentialMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                permanent_delegate: permanent_delegate.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateReissuedConfidentialMint {
                decimals: DECIMALS,
                fee_basis_points: FEE_BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
                withdraw_withheld_authority_elgamal_pubkey: fee_authority_pubkey,
            }
            .data(),
        }],
        &[&mint],
    );

    // Create sanctioned user's token account (sized for TransferFeeAmount + ConfidentialTransferAccount + ConfidentialTransferFeeAmount)
    let sanctioned_account = create_token_account_with_extensions(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &sanctioned_user.pubkey(),
        &[
            ExtensionType::TransferFeeAmount,
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    );
    // Create treasury account for receiving seized tokens
    let treasury_account = create_token_account_with_extensions(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &treasury.pubkey(),
        &[ExtensionType::TransferFeeAmount],
    );

    // KYC thaw both accounts
    send(
        &mut svm,
        &payer,
        &[
            Instruction {
                program_id: ID,
                accounts: accounts::ThawAccount {
                    mint: mint.pubkey(),
                    account_to_thaw: sanctioned_account,
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
                    account_to_thaw: treasury_account,
                    freeze_authority: payer.pubkey(),
                    token_program: TOKEN_2022_PROGRAM_ID,
                }
                .to_account_metas(None),
                data: instruction::ThawAccount {}.data(),
            },
        ],
        &[],
    );

    // Mint 10_000 plaintext tokens to sanctioned user
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &sanctioned_account,
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );

    // -----------------------------------------------------------------------
    // Demonstration 1: PermanentDelegate Seizure on PLAINTEXT tokens
    // -----------------------------------------------------------------------
    // The seizure authority executes permanent_delegate_seize WITHOUT sanctioned_user's signature!
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::PermanentDelegateSeize {
                mint: mint.pubkey(),
                source: sanctioned_account,
                destination: treasury_account,
                permanent_delegate: permanent_delegate.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::PermanentDelegateSeize {
                amount: 4_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[&permanent_delegate],
    );

    // Verify plaintext seizure results via StateWithExtensions
    let s_data = svm.get_account(&sanctioned_account).unwrap().data;
    let s_state = StateWithExtensions::<TokenAccountState>::unpack(&s_data).unwrap();
    assert_eq!(s_state.base.amount, 6_000);

    let t_data = svm.get_account(&treasury_account).unwrap().data;
    let t_state = StateWithExtensions::<TokenAccountState>::unpack(&t_data).unwrap();
    // 4,000 transferred minus 2.5% protocol fee (100) = 3,900 net in treasury
    assert_eq!(t_state.base.amount, 3_900);
    let fee_ext = t_state.get_extension::<TransferFeeAmount>().unwrap();
    assert_eq!(u64::from(fee_ext.withheld_amount), 100);

    println!("Task 5 Plaintext Seizure PASSED: PermanentDelegate successfully seized 4,000 tokens (3,900 net + 100 protocol fee withheld) without user signature.");

    // -----------------------------------------------------------------------
    // Demonstration 2: THE REGULATORY & ARCHITECTURAL GAP
    // -----------------------------------------------------------------------
    // Now sanctioned user moves their remaining 6,000 plaintext tokens into
    // confidential storage.
    // Configure user's confidential account:
    let (s_elgamal, s_aes) = derive_confidential_keys(&sanctioned_user, b"").unwrap();
    let s_proof = build_pubkey_validity_proof_data(&s_elgamal).unwrap();
    let config_ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &sanctioned_account,
        &mint.pubkey(),
        &s_aes.encrypt(0).into(),
        65536,
        &sanctioned_user.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &s_proof),
    )
    .unwrap();
    send(&mut svm, &payer, &config_ixs, &[&sanctioned_user]);

    // Approve the account (manual policy)
    let approve_ix = ct_ix::approve_account(
        &TOKEN_2022_PROGRAM_ID,
        &sanctioned_account,
        &mint.pubkey(),
        &payer.pubkey(),
        &[],
    )
    .unwrap();
    send(&mut svm, &payer, &[approve_ix], &[]);

    // Deposit remaining 6,000 tokens into confidential balance
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: sanctioned_account,
                mint: mint.pubkey(),
                authority: sanctioned_user.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: 6_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[&sanctioned_user],
    );

    // Apply pending to available
    let s_holder = Holder {
        account: sanctioned_account,
        elgamal: s_elgamal,
        aes: s_aes,
    };
    apply_pending(&mut svm, &payer, &s_holder, &sanctioned_user);

    // Verify plaintext balance is now 0, and confidential available balance is 6,000
    let s_data = svm.get_account(&sanctioned_account).unwrap().data;
    let s_state = StateWithExtensions::<TokenAccountState>::unpack(&s_data).unwrap();
    assert_eq!(s_state.base.amount, 0, "Plaintext balance must be 0 after confidential deposit");

    let s_ct = read_ct(&svm, &sanctioned_account);
    assert_eq!(available_balance(&s_ct, &s_holder.elgamal), 6_000);

    // NOW: Regulators order the PermanentDelegate to seize the 6,000 tokens from the sanctioned wallet!
    // Attempting to seize via PermanentDelegate FAILS because the plaintext balance is 0!
    let seize_failure_logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::PermanentDelegateSeize {
                mint: mint.pubkey(),
                source: sanctioned_account,
                destination: treasury_account,
                permanent_delegate: permanent_delegate.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::PermanentDelegateSeize {
                amount: 6_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[&permanent_delegate],
    );
    assert!(
        seize_failure_logs.contains("insufficient funds") || seize_failure_logs.contains("custom program error"),
        "Permanent delegate cannot seize confidential tokens"
    );

    // Even attempting to seize 1 token fails!
    let seize_1_failure = send_expecting_failure(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::PermanentDelegateSeize {
                mint: mint.pubkey(),
                source: sanctioned_account,
                destination: treasury_account,
                permanent_delegate: permanent_delegate.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::PermanentDelegateSeize {
                amount: 1,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[&permanent_delegate],
    );
    assert!(seize_1_failure.contains("insufficient funds") || seize_1_failure.contains("custom program error"));

    println!(
        "Task 5 THE GAP IDENTIFIED & CONFIRMED: Token-2022 PermanentDelegate can only move plaintext tokens (base.amount). \
        Once deposited into ElGamal ciphertexts (ConfidentialTransferAccount), tokens are mathematically immune to delegate seizure. \
        The issuer's only mitigations are preventative: manual approval policy (refusing approve_account) or freeze authority (locking the account without seizing)."
    );
}

// ===========================================================================
// TASK 6: Full Confidential Lifecycle End-to-End
// ===========================================================================

#[test]
fn test_task6_confidential_lifecycle_end_to_end() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // 1. Create pure confidential mint with approve_policy = manual (auto_approve_new_accounts = false)
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateConfidentialMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateConfidentialMint {
                decimals: DECIMALS,
                auto_approve_new_accounts: false, // approve_policy = manual
            }
            .data(),
        }],
        &[&mint],
    );

    // Verify mint configuration
    let mint_data = svm.get_account(&mint.pubkey()).unwrap().data;
    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data).unwrap();
    let ct_mint = mint_state
        .get_extension::<ConfidentialTransferMint>()
        .unwrap();
    assert_eq!(bool::from(ct_mint.auto_approve_new_accounts), false);

    // 2. ATA / Account Creation for Alice and Bob
    let alice = Keypair::new();
    let bob = Keypair::new();
    svm.airdrop(&alice.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&bob.pubkey(), 10_000_000_000).unwrap();

    let alice_account = create_token_account_with_extensions(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &alice.pubkey(),
        &[ExtensionType::ConfidentialTransferAccount],
    );
    let bob_account = create_token_account_with_extensions(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &bob.pubkey(),
        &[ExtensionType::ConfidentialTransferAccount],
    );

    // -----------------------------------------------------------------------
    // Step 1: ConfigureAccount (Owner-Only)
    // -----------------------------------------------------------------------
    let (alice_elgamal, alice_aes) = derive_confidential_keys(&alice, b"").unwrap();
    let alice_proof = build_pubkey_validity_proof_data(&alice_elgamal).unwrap();

    let eve = Keypair::new();
    svm.airdrop(&eve.pubkey(), 10_000_000_000).unwrap();

    // Negative test: An attacker (eve) attempts to configure Alice's account with Eve as authority -> MUST FAIL!
    let attacker_ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &alice_account,
        &mint.pubkey(),
        &alice_aes.encrypt(0).into(),
        65536,
        &eve.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &alice_proof),
    )
    .unwrap();
    let non_owner_fail_logs = send_expecting_failure(&mut svm, &payer, &attacker_ixs, &[&eve]);
    assert!(
        non_owner_fail_logs.contains("custom program error")
            || non_owner_fail_logs.contains("InstructionError")
            || non_owner_fail_logs.contains("owner"),
        "ConfigureAccount MUST be owner-only"
    );

    // Positive test: Owner (Alice) signs ConfigureAccount
    let alice_ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &alice_account,
        &mint.pubkey(),
        &alice_aes.encrypt(0).into(),
        65536,
        &alice.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &alice_proof),
    )
    .unwrap();
    send(&mut svm, &payer, &alice_ixs, &[&alice]);

    // Verify Alice's account is configured, but NOT yet approved (manual approve policy)
    let alice_ct = read_ct(&svm, &alice_account);
    assert_eq!(
        bool::from(alice_ct.approved),
        false,
        "Account must not be approved automatically under manual approve policy"
    );

    // Bob also configures his account
    let (bob_elgamal, bob_aes) = derive_confidential_keys(&bob, b"").unwrap();
    let bob_proof = build_pubkey_validity_proof_data(&bob_elgamal).unwrap();
    let bob_config_ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &bob_account,
        &mint.pubkey(),
        &bob_aes.encrypt(0).into(),
        65536,
        &bob.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &bob_proof),
    )
    .unwrap();
    send(&mut svm, &payer, &bob_config_ixs, &[&bob]);

    let bob_ct = read_ct(&svm, &bob_account);
    assert_eq!(bool::from(bob_ct.approved), false);

    println!("Task 6 Step 1 PASSED: ConfigureAccount is strictly owner-only and approved=false under manual policy.");

    // -----------------------------------------------------------------------
    // Step 2: Issuer Manual Approval Policy Enforcement
    // -----------------------------------------------------------------------
    // Mint tokens to Alice
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

    // Attempting DepositConfidentialTokens before issuer approval MUST FAIL!
    let unapproved_deposit_fail = send_expecting_failure(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: alice_account,
                mint: mint.pubkey(),
                authority: alice.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: 10_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[&alice],
    );
    assert!(
        unapproved_deposit_fail.contains("custom program error")
            || unapproved_deposit_fail.contains("not approved")
            || unapproved_deposit_fail.contains("InstructionError"),
        "Deposit into unapproved account must fail"
    );

    // Issuer (payer/authority) calls ct_ix::approve_account for both Alice and Bob
    send(
        &mut svm,
        &payer,
        &[
            ct_ix::approve_account(
                &TOKEN_2022_PROGRAM_ID,
                &alice_account,
                &mint.pubkey(),
                &payer.pubkey(),
                &[],
            )
            .unwrap(),
            ct_ix::approve_account(
                &TOKEN_2022_PROGRAM_ID,
                &bob_account,
                &mint.pubkey(),
                &payer.pubkey(),
                &[],
            )
            .unwrap(),
        ],
        &[],
    );

    // Verify both accounts now have approved = true
    assert_eq!(bool::from(read_ct(&svm, &alice_account).approved), true);
    assert_eq!(bool::from(read_ct(&svm, &bob_account).approved), true);

    println!("Task 6 Step 2 PASSED: Manual approve policy enforced: unapproved deposit rejected; approve_account succeeded.");

    // -----------------------------------------------------------------------
    // Step 3: DepositConfidentialTokens
    // -----------------------------------------------------------------------
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: alice_account,
                mint: mint.pubkey(),
                authority: alice.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: 10_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[&alice],
    );

    let alice_ct = read_ct(&svm, &alice_account);
    assert_eq!(pending_balance(&alice_ct, &alice_elgamal), 10_000);
    assert_eq!(available_balance(&alice_ct, &alice_elgamal), 0);

    // Verify plaintext balance decreased to 0
    let a_data = svm.get_account(&alice_account).unwrap().data;
    let a_state = StateWithExtensions::<TokenAccountState>::unpack(&a_data).unwrap();
    assert_eq!(a_state.base.amount, 0);

    println!("Task 6 Step 3 PASSED: DepositConfidentialTokens deposited 10,000 into pending_balance.");

    // -----------------------------------------------------------------------
    // Step 4: ApplyPendingBalance
    // -----------------------------------------------------------------------
    let alice_holder = Holder {
        account: alice_account,
        elgamal: alice_elgamal,
        aes: alice_aes,
    };
    apply_pending(&mut svm, &payer, &alice_holder, &alice);

    let alice_ct = read_ct(&svm, &alice_account);
    assert_eq!(pending_balance(&alice_ct, &alice_holder.elgamal), 0);
    let alice_avail = available_balance(&alice_ct, &alice_holder.elgamal);
    assert_eq!(alice_avail, 10_000);

    println!("Task 6 Step 4 PASSED: ApplyPendingBalance rolled pending into available_balance (10,000).");

    // -----------------------------------------------------------------------
    // Step 5: Confidential Transfer (Alice -> Bob)
    // -----------------------------------------------------------------------
    let transfer_amount = 3_500u64;
    let current_available: ElGamalCiphertext = alice_ct.available_balance.try_into().unwrap();
    let current_decryptable: AeCiphertext = alice_ct.decryptable_available_balance.try_into().unwrap();
    let bob_pubkey: ElGamalPubkey = read_ct(&svm, &bob_account).elgamal_pubkey.try_into().unwrap();

    let proofs = transfer_split_proof_data(
        &current_available,
        &current_decryptable,
        transfer_amount,
        &alice_holder.elgamal,
        &alice_holder.aes,
        &bob_pubkey,
        None,
    )
    .unwrap();

    // Stage all 3 ZK proofs into context accounts
    let eq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let val_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let range_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU128,
        &proofs.range_proof_data,
    );

    let new_alice_decryptable = alice_holder.aes.encrypt(alice_avail - transfer_amount);
    let transfer_ixs = ct_ix::transfer(
        &TOKEN_2022_PROGRAM_ID,
        &alice_account,
        &mint.pubkey(),
        &bob_account,
        &new_alice_decryptable.into(),
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &alice.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&val_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &transfer_ixs, &[&alice]);

    // Close proof contexts and recover rent
    let recovered_rent = close_contexts(&mut svm, &payer, &[eq_ctx, val_ctx, range_ctx]);
    assert!(recovered_rent > 0, "Proof context rent must be recovered");

    // Alice available balance is now 6,500
    let alice_ct = read_ct(&svm, &alice_account);
    assert_eq!(
        available_balance(&alice_ct, &alice_holder.elgamal),
        10_000 - transfer_amount
    );

    // Bob receives tokens in pending_balance
    let bob_holder = Holder {
        account: bob_account,
        elgamal: bob_elgamal,
        aes: bob_aes,
    };
    let bob_ct = read_ct(&svm, &bob_account);
    assert_eq!(pending_balance(&bob_ct, &bob_holder.elgamal), transfer_amount);
    assert_eq!(available_balance(&bob_ct, &bob_holder.elgamal), 0);

    println!("Task 6 Step 5 PASSED: Confidential Transfer executed; Bob received 3,500 in pending_balance.");

    // -----------------------------------------------------------------------
    // Step 6: Recipient ApplyPendingBalance BEFORE Withdrawal
    // (Explicit prompt requirement: "including applying pending balance before withdrawal")
    // -----------------------------------------------------------------------
    apply_pending(&mut svm, &payer, &bob_holder, &bob);

    let bob_ct = read_ct(&svm, &bob_account);
    assert_eq!(pending_balance(&bob_ct, &bob_holder.elgamal), 0);
    assert_eq!(available_balance(&bob_ct, &bob_holder.elgamal), transfer_amount);

    println!("Task 6 Step 6 PASSED: Recipient ApplyPendingBalance executed before withdrawal; Bob available = 3,500.");

    // -----------------------------------------------------------------------
    // Step 7: WithdrawConfidentialTokens Back to Plaintext
    // -----------------------------------------------------------------------
    let withdraw_amount = 1_500u64;
    let bob_available = available_balance(&bob_ct, &bob_holder.elgamal);
    let bob_curr_cipher: ElGamalCiphertext = bob_ct.available_balance.try_into().unwrap();

    let wproofs = withdraw_proof_data(
        &bob_curr_cipher,
        bob_available,
        withdraw_amount,
        &bob_holder.elgamal,
    )
    .unwrap();

    // Stage 2 ZK proofs for withdrawal
    let weq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &wproofs.equality_proof_data,
    );
    let wrange_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &wproofs.range_proof_data,
    );

    let new_bob_decryptable = bob_holder.aes.encrypt(bob_available - withdraw_amount);
    let withdraw_ixs = ct_ix::withdraw(
        &TOKEN_2022_PROGRAM_ID,
        &bob_account,
        &mint.pubkey(),
        withdraw_amount,
        DECIMALS,
        &new_bob_decryptable.into(),
        &bob.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&weq_ctx),
        ProofLocation::ContextStateAccount(&wrange_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &withdraw_ixs, &[&bob]);

    close_contexts(&mut svm, &payer, &[weq_ctx, wrange_ctx]);

    // Verify Bob's plaintext public balance increased by withdraw_amount
    let b_data = svm.get_account(&bob_account).unwrap().data;
    let b_state = StateWithExtensions::<TokenAccountState>::unpack(&b_data).unwrap();
    assert_eq!(
        b_state.base.amount, withdraw_amount,
        "Public plaintext balance must match withdrawn amount"
    );

    // Verify Bob's remaining confidential available balance
    let bob_ct = read_ct(&svm, &bob_account);
    assert_eq!(
        available_balance(&bob_ct, &bob_holder.elgamal),
        transfer_amount - withdraw_amount
    );

    println!(
        "Task 6 Step 7 PASSED: WithdrawConfidentialTokens successfully withdrew 1,500 back to public plaintext balance (remaining confidential: 2,000)."
    );
}

#[test]
fn test_tampered_zk_proof_rejected() {
    let (mut svm, payer) = setup();
    let (elgamal, _) = derive_confidential_keys(&payer, b"").unwrap();

    let valid_proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let mut tampered_proof = valid_proof;

    let bytes = bytemuck::bytes_of_mut(&mut tampered_proof);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01; // Corrupt single bit

    let valid_ix = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, &valid_proof);
    let tampered_ix =
        ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, &tampered_proof);

    // Valid proof succeeds
    send(&mut svm, &payer, &[valid_ix], &[]);

    // Tampered proof fails
    let fail_logs = send_expecting_failure(&mut svm, &payer, &[tampered_ix], &[]);
    assert!(
        fail_logs.contains("proof verification failed")
            || fail_logs.contains("custom program error")
            || fail_logs.contains("InstructionError"),
        "Tampered ZK proof must be rejected"
    );

    println!("Cryptographic Integrity PASSED: Single-bit tampered ZK proof rejected by proof program.");
}
