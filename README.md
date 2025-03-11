# solana-smart-contract-security-best-practices

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/slowmist_team.svg?style=social&label=Follow%20%40SlowMist_Team)](https://twitter.com/slowmist_team)

[[中文]](./README_CN.md)

  * [Common pitfalls of Solana smart contracts:](#common-pitfalls-of-solana-smart-contracts-)
    + [Integer overflow or underflow](#integer-overflow-or-underflow)
    + [Loss of precision](#loss-of-precision)
    + [Inaccurate calculation results](#inaccurate-calculation-results)
    + [Panic due to division by zero](#panic-due-to-division-by-zero)
    + [Error not handled](#error-not-handled)
    + [Missing check for the permission of caller](#missing-check-for-the-permission-of-caller)
    + [Account signer check](#account-signer-check)
    + [Account writable check](#account-writable-check)
    + [Account owner or program id check](#account-owner-or-program-id-check)
    + [Account initialized check](#account-initialized-check)
    + [PDA substitution check](#pda-substitution-check)
    + [Missing system account check](#missing-system-account-check)
    + [Missing check for lamports](#missing-check-for-lamports)
    + [Pyth oracle check](#pyth-oracle-check)
    + [Timely state reset](#timely-state-reset)
  * [Attacks using the Anchor framework](#attacks-using-the-anchor-framework)
    + [Signer authorization](#signer-authorization)
    + [Account data matching](#account-data-matching)
    + [Owner checks](#owner-checks)
    + [Type cosplay](#type-cosplay)
    + [Check initialize](#check-initialize)
    + [Arbitrary cpi](#arbitrary-cpi)
    + [Duplicate mutable accounts](#duplicate-mutable-accounts)
    + [Bump seed canonicalization](#bump-seed-canonicalization)
    + [Pda sharing](#pda-sharing)
    + [Closing accounts](#closing-accounts)
    + [Sysvar address checking](#sysvar-address-checking)
    + [Account Reloading](#account-reloading)
  * [Case Analysis](#case-analysis)


## Common pitfalls of Solana smart contracts:

### Integer overflow or underflow
- Severity: High
- Description:  
Caculate without checking for overflow/underflow.
- Exploit Scenario:
```rust
pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
  let user_balance = ctx.accounts.user.balance + amount;
}
```
- Recommendation:  
Use `checked_add/checked_sub/checked_div/checked_mul`, instead of `+-*/`

### Loss of precision
- Severity: High
- Description:  
The use of `try_round_u64()` for rounding up leads to problems with precision.
- Exploit Scenario:
```rust
pub fn collateral_to_liquidity(&self, collateral_amount: u64) -> Result<u64, ProgramError> {
    Decimal::from(collateral_amount)
        .try_div(self.0)?
        .try_round_u64()
}
```
- Recommendation:  
Use `try_floor_u64()` to prevent arbitrage attacks.

### Inaccurate calculation results
- Severity: High
- Description:  
The use of `saturating_add`, `saturating_mul`, and `saturating_sub` in Rust is generally intended to prevent integer overflow and underflow, ensuring that the result remains within the valid range for the data type. However, in certain cases, relying on these functions alone can lead to inaccurate or unexpected results. This occurs when the application logic assumes that saturation alone guarantees accurate results, but ignores the potential loss of precision or accuracy.
- Exploit Scenario:
```rust
let over_fee = paid_amount.saturating_sub(actual_amount);
```
- Recommendation:  
Use `checked_add/checked_sub/checked_div/checked_mul` instead.

### Panic due to division by zero 
- Severity: High
- Description:  
In Rust, attempting to divide a number by zero results in a panic, causing the program to terminate. This behavior may lead to unintended consequences or instability if not properly handled.
- Exploit Scenario:
```rust
let result = dividend / divisor;
```
- Recommendation:  
Check if divisor is zero.

### Error not handled
- Severity: High
- Description:  
Call function without check the return value.
- Exploit Scenario:
```rust
&spl_token::instruction::transfer(
    //...
    );
```
- Recommendation:  
This `Result` may be an `Err` variant, which should be handled, don't forget to add `?` at the end of the line.

### Missing check for the permission of caller
- Severity: Low
- Description:  
Without checking if signer is a legitimate administrator/creator when initialize a global account, hacker could create a fake account for attacking.
- Exploit Scenario:  
```rust
fn init_market(
    accounts: &[AccountInfo],
) -> ProgramResult {
    // Without checking if signer is a legitimate administrator/creator. Anyone can invoke this function.
    Ok(())
}
```
- Recommendation:  
Hardcode an administrator key in the program and set invoke signer key to the key.

### Account signer check
- Severity: High
- Description:  
Check if the expected signer account has actually signed.
The bellow shows unauthorized account can write/modify account data.
- Exploit Scenario:  
- Recommendation:  
```rust
let payer_account = next_account_info(accounts_iter)?;
if !payer_account.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

### Account writable check
- Severity: High
- Description:  
Check if the expected state account's have been checked as writable
- Exploit Scenario:  
- Recommendation:  
```rust
let hello_state_account = next_account_info(accounts_iter)?;
if !hello_state_account.is_writable {
    return Err(ProgramError::InvalidAccountData);
}
```

### Account owner or program id check
- Severity: High
- Description:  
Check if the expected state account's owner is the called program id.
For example:
Not check the account owner before reading, it may be created by evil program and filled with fake data.
- Exploit Scenario:  
```rust
let pyth_price_info = next_account_info(account_info_iter)?;
let market_price = get_pyth_price(pyth_price_info, clock)?;
```
- Recommendation:  
Check whether the `pyth_price_info.owner` is the correct program.
```rust
let program_id = Pubkey::from_str("Oracle Pubkey").unwrap();
if pyth_price_info.owner.ne(&program_id) {
    return Err(ProgramError::IllegalOwner);
}
```

### Account initialized check
- Severity: High
- Description:  
If initializing the state for the first time, check if the account's already been initialized or not.
- Exploit Scenario:  
- Recommendation:  
```rust
let hello_state_account = next_account_info(accounts_iter)?;
let mut hello_state = HelloState::try_from_slice(&hello_state_account.data.borrow())?;
if hello_state.is_initialized {
    return Err(ProgramError::AccountAlreadyInitialized);
}
hello_state.is_initialized = true;
hello_state.serialize(&mut &mut hello_state_account.data.borrow_mut()[..])?;
```

### PDA substitution check
- Severity: High
- Description:  
PDA is an account whose owner is a program, it can be created by an unofficial, take care to check the correct account.
- Exploit Scenario:
```rust
let config_pda_info = next_account_info(account_info_iter)?; //config_pda_info can be replaced by unofficial account.
let seeds = &[
    b"user_pda_desc".as_ref(),
    config_pda_info.key.as_ref(),
    &[bump],
];
let user_pda_pubkey =
    Pubkey::create_program_address(seeds, program_id)?;
//...
```
- Recommendation:  
We recommend creating a PDA based on a unique account, it is usually an initial configuration account.

### Missing system account check
- Severity: High
- Description:  
The sysvar account contains system data.  
Common accounts:  
```
Clock: SysvarC1ock11111111111111111111111111111111
EpochSchedule: SysvarEpochSchedu1e111111111111111111111111
Fees: SysvarFees111111111111111111111111111111111
Instructions: Sysvar1nstructions1111111111111111111111111
RecentBlockhashes: SysvarRecentB1ockHashes11111111111111111111
Rent: SysvarRent111111111111111111111111111111111
SlotHashes: SysvarS1otHashes111111111111111111111111111
SlotHistory: SysvarS1otHistory11111111111111111111111111
StakeHistory: SysvarStakeHistory1111111111111111111111111
SPL token program: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
```
- Exploit Scenario:  
```rust
let token_program_id = next_account_info(account_info_iter)?;
//invoke token program without checking if it is the SPL token program.
spl_token_transfer(TokenTransferParams {
    //...
    token_program: token_program_id.clone(),
})?;
```
- Recommendation:  
Hardcode sysvar key in the program and check when passing in.

### Missing check for lamports

- Severity: low
- Description: 
  When a Solana account is deleted (lamports set to zero), the data in the account can still be read before the transaction is completed, which could lead to an accident if the lamports value is not checked before the account data is read.

- Exploit Scenario:  
- Recommendation:
```rust
if **the_account_to_read.try_borrow_lamports()? > 0 {
    //logic here
}
```

### Pyth oracle check
- Severity: High
- Description:  
Pyth oracle price sometimes fails, we should take care to check its status.
- Exploit Scenario:  
```rust
if pyth_price.agg.status != PriceStatus::Trading {
    return Err(ErrorCode::InvalidPythConfig);
}
```
- Recommendation:  
Upgrade the Pyth sdk to the latest version.


### Timely state reset
- Severity: High
- Description:  
Reset authority while change owner.
- Exploit Scenario:  
```rust
if let COption::Some(authority) = new_authority {
    account.owner = authority;
} else {
    return Err(TokenError::InvalidInstruction.into());
}
```
- Recommendation:  
```rust
if let COption::Some(authority) = new_authority {
    account.owner = authority;
} else {
    return Err(TokenError::InvalidInstruction.into());
}

account.delegate = COption::None;
account.delegated_amount = 0;

if account.is_native() {
    account.close_authority = COption::None;
}
```

## Attacks using the Anchor framework

### Signer authorization
- Severity: High
- Description:  
Signer check is to ensure that the role initiating the execution call is authenticated.
- Exploit Scenario:  
The account is missing signer check.
```rust
#[program]
pub mod signer_authorization_insecure {
    use super::*;

    pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
        msg!("GM {}", ctx.accounts.authority.key().to_string());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct LogMessage<'info> {
    authority: AccountInfo<'info>,
}
```

- Recommendation:  
```rust
#[program]
pub mod signer_authorization_secure {
    use super::*;

    pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
        if !ctx.accounts.authority.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        msg!("GM {}", ctx.accounts.authority.key().to_string());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct LogMessage<'info> {
    authority: AccountInfo<'info>,
}
```


### Account data matching
- Severity: High
- Description:  
During an audit, it's crucial to focus on the data structures parsed from the meta in the Account. Pay particular attention to permission-related checks, such as Token ownership and Token mint authority.
- Exploit Scenario:  
```rust
#[program]
pub mod account_data_matching_insecure {
    use super::*;

    pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
        let token = SplTokenAccount::unpack(&ctx.accounts.token.data.borrow())?;
        msg!("Your account balance is: {}", token.amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct LogMessage<'info> {
    token: AccountInfo<'info>,
    authority: Signer<'info>,
}
```
- Recommendation:  
```rust
#[program]
pub mod account_data_matching_secure {
    use super::*;

    pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
        let token = SplTokenAccount::unpack(&ctx.accounts.token.data.borrow())?;
        if ctx.accounts.authority.key != &token.owner {
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("Your acocunt balance is: {}", token.amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct LogMessage<'info> {
    token: AccountInfo<'info>,
    authority: Signer<'info>,
}
```

### Owner checks
- Severity: High
- Description:  
Owner checks come in two forms:

1. The first type involves checking the Owner field in the meta-data of an Account, such as verifying the owner of tokens in SPL Token.

2. The second type is the Owner check on the Account itself. Typically, in the case of PDA (Program Derived Account), the Owner is the program ID used during derivation. However, it's important to note that the program can change the Owner to another program ID during derivation, and only the Account's Owner can operate on the Account's data.

During an audit, determining which Owner check to apply depends on the business logic of the program.
- Exploit Scenario:  
```rust
#[program]
pub mod owner_checks_insecure {
    use super::*;

    pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
        let token = SplTokenAccount::unpack(&ctx.accounts.token.data.borrow())?;
        if ctx.accounts.authority.key != &token.owner {
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("Your account balance is: {}", token.amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct LogMessage<'info> {
    token: AccountInfo<'info>,
    authority: Signer<'info>,
}
```
- Recommendation:  
```rust
#[program]
pub mod owner_checks_secure {
    use super::*;

    pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
        let token = SplTokenAccount::unpack(&ctx.accounts.token.data.borrow())?;
        if ctx.accounts.token.owner != &spl_token::ID {
            return Err(ProgramError::InvalidAccountData);
        }
        if ctx.accounts.authority.key != &token.owner {
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("Your account balance is: {}", token.amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct LogMessage<'info> {
    token: AccountInfo<'info>,
    authority: Signer<'info>,
}
```

### Type cosplay
- Severity: High
- Description:  
During the audit, identify Accounts within the program that share the same data structure. Attempt to deduce the risk of these different Accounts potentially impersonating each other through the use of the identical data structure.
- Exploit Scenario:  
```rust
#[program]
pub mod type_cosplay_insecure {
    use super::*;

    pub fn update_user(ctx: Context<UpdateUser>) -> ProgramResult {
        let user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
        if ctx.accounts.user.owner != ctx.program_id {
            return Err(ProgramError::IllegalOwner);
        }
        if user.authority != ctx.accounts.authority.key() {
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("GM {}", user.authority);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateUser<'info> {
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    authority: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Metadata {
    account: Pubkey,
}
```
- Recommendation:  
```rust
#[program]
pub mod type_cosplay_secure {
    use super::*;

    pub fn update_user(ctx: Context<UpdateUser>) -> ProgramResult {
        let user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
        if ctx.accounts.user.owner != ctx.program_id {
            return Err(ProgramError::IllegalOwner);
        }
        if user.authority != ctx.accounts.authority.key() {
            return Err(ProgramError::InvalidAccountData);
        }
        if user.discriminant != AccountDiscriminant::User {
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("GM {}", user.authority);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateUser<'info> {
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    discriminant: AccountDiscriminant,
    authority: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Metadata {
    discriminant: AccountDiscriminant,
    account: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq)]
pub enum AccountDiscriminant {
    User,
    Metadata,
}
```

### Check initialize
- Severity: High
- Description:  
In a business context, when data should only be initialized once, it's essential to use a flag to check whether it has already been set to "true."
- Exploit Scenario:  
```rust
#[program]
pub mod initialization_insecure {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> ProgramResult {
        let mut user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();

        user.authority = ctx.accounts.authority.key();

        let mut storage = ctx.accounts.user.try_borrow_mut_data()?;
        user.serialize(storage.deref_mut()).unwrap();
        Ok(())
    }
}

/*
- reinitialize
- create and dont initialize
- passing previously initialzed accounts from other programs
  (e.g. token program => need to check delegate and authority)
*/

#[derive(Accounts)]
pub struct Initialize<'info> {
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    authority: Pubkey,
}
```
- Recommendation:  
```rust
#[program]
pub mod reinitialization_secure_recommended {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> ProgramResult {
        let mut user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
        if !user.discriminator {
            return Err(ProgramError::InvalidAccountData);
        }

        user.authority = ctx.accounts.authority.key();
        user.discriminator = true;

        let mut storage = ctx.accounts.user.try_borrow_mut_data()?;
        user.serialize(storage.deref_mut()).unwrap();

        msg!("GM");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    discriminator: bool,
    authority: Pubkey,
}
```

### Arbitrary cpi
- Severity: High
- Description:  
During the audit, it's important to locate the CPI (Cross-Program Invocation) code logic within the program and ensure that the code includes checks on the target program id when conducting CPI. This is crucial for verifying the legitimacy of the target program.
- Exploit Scenario:  
```rust
#[program]
pub mod arbitrary_cpi_insecure {
    use super::*;

    pub fn cpi(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.source.key,
                ctx.accounts.destination.key,
                ctx.accounts.authority.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.source.clone(),
                ctx.accounts.destination.clone(),
                ctx.accounts.authority.clone(),
            ],
        )
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: AccountInfo<'info>,
    destination: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
}
```
- Recommendation:  
```rust
#[program]
pub mod arbitrary_cpi_secure {
    use super::*;

    pub fn cpi_secure(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        if &spl_token::ID != ctx.accounts.token_program.key {
            return Err(ProgramError::IncorrectProgramId);
        }
        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.source.key,
                ctx.accounts.destination.key,
                ctx.accounts.authority.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.source.clone(),
                ctx.accounts.destination.clone(),
                ctx.accounts.authority.clone(),
            ],
        )
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: AccountInfo<'info>,
    destination: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
}
```

### Duplicate mutable accounts
- Severity: High
- Description:  
During the audit, it's important to pay attention to whether passing the same Account as an input could result in unintended data overwriting.
- Exploit Scenario:  
These two accounts are both mutable and may be the same account.
```rust
#[program]
pub mod duplicate_mutable_accounts_insecure {
    use super::*;

    pub fn update(ctx: Context<Update>, a: u64, b: u64) -> ProgramResult {
        let user_a = &mut ctx.accounts.user_a;
        let user_b = &mut ctx.accounts.user_b;

        user_a.data = a;
        user_b.data = b;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    user_a: Account<'info, User>,
    user_b: Account<'info, User>,
}

#[account]
pub struct User {
    data: u64,
}
```
- Recommendation:  
```rust
#[program]
pub mod duplicate_mutable_accounts_secure {
    use super::*;

    pub fn update(ctx: Context<Update>, a: u64, b: u64) -> ProgramResult {
        if ctx.accounts.user_a.key() == ctx.accounts.user_b.key() {
            return Err(ProgramError::InvalidArgument)
        }
        let user_a = &mut ctx.accounts.user_a;
        let user_b = &mut ctx.accounts.user_b;

        user_a.data = a;
        user_b.data = b;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    user_a: Account<'info, User>,
    user_b: Account<'info, User>,
}

#[account]
pub struct User {
    data: u64,
}
```

### Bump seed canonicalization
- Severity: High
- Description:  
"create_program_address" and "find_program_address" are significantly different. "create_program_address" will generate a different PDA for the same program id if the bump seed is different, while "find_program_address" returns a PDA using the maximum valid bump seed. Therefore, if bump seed validation is not applied, and the bump seed is untrusted data, it can lead to security issues in the subsequent code logic.
- Exploit Scenario:  
```rust
#[program]
pub mod bump_seed_canonicalization_insecure {
    use super::*;

    pub fn set_value(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> ProgramResult {
        let address =
            Pubkey::create_program_address(&[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id)?;
        if address != ctx.accounts.data.key() {
            return Err(ProgramError::InvalidArgument);
        }

        ctx.accounts.data.value = new_value;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct BumpSeed<'info> {
    data: Account<'info, Data>,
}

#[account]
pub struct Data {
    value: u64,
}
```
- Recommendation:  
```rust
#[program]
pub mod bump_seed_canonicalization_secure {
    use super::*;

    pub fn set_value_secure(
        ctx: Context<BumpSeed>,
        key: u64,
        new_value: u64,
        bump: u8,
    ) -> ProgramResult {
        let (address, expected_bump) =
            Pubkey::find_program_address(&[key.to_le_bytes().as_ref()], ctx.program_id);

        if address != ctx.accounts.data.key() {
            return Err(ProgramError::InvalidArgument);
        }
        if expected_bump != bump {
            return Err(ProgramError::InvalidArgument);
        }

        ctx.accounts.data.value = new_value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct BumpSeed<'info> {
    data: Account<'info, Data>,
}

#[account]
pub struct Data {
    value: u64,
}
```

### Pda sharing
- Severity: High
- Description:  
During an audit, it's crucial to examine the CPI (Cross-Program Invocation) related code to ensure there is separation of permissions for calling PDA with different roles. This helps to prevent situations where multiple roles share the same seed.
- Exploit Scenario:  
```rust
#[program]
pub mod pda_sharing_insecure {
    use super::*;

    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>) -> ProgramResult {
        let amount = ctx.accounts.vault.amount;
        let seeds = &[ctx.accounts.pool.mint.as_ref(), &[ctx.accounts.pool.bump]];
        token::transfer(ctx.accounts.transfer_ctx().with_signer(&[seeds]), amount)
    }
}

#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    #[account(has_one = vault, has_one = withdraw_destination)]
    pool: Account<'info, TokenPool>,
    vault: Account<'info, TokenAccount>,
    withdraw_destination: Account<'info, TokenAccount>,
    authority: Signer<'info>,
    token_program: Program<'info, Token>,
}

impl<'info> WithdrawTokens<'info> {
    pub fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let program = self.token_program.to_account_info();
        let accounts = token::Transfer {
            from: self.vault.to_account_info(),
            to: self.withdraw_destination.to_account_info(),
            authority: self.authority.to_account_info(),
        };
        CpiContext::new(program, accounts)
    }
}

#[account]
pub struct TokenPool {
    vault: Pubkey,
    mint: Pubkey,
    withdraw_destination: Pubkey,
    bump: u8,
}
```
- Recommendation:  
```rust
#[program]
pub mod pda_sharing_secure {
    use super::*;

    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>) -> ProgramResult {
        let amount = ctx.accounts.vault.amount;
        let seeds = &[
            ctx.accounts.pool.withdraw_destination.as_ref(),
            &[ctx.accounts.pool.bump],
        ];
        token::transfer(ctx.accounts.transfer_ctx().with_signer(&[seeds]), amount)
    }
}

#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    #[account(has_one = vault, has_one = withdraw_destination)]
    pool: Account<'info, TokenPool>,
    vault: Account<'info, TokenAccount>,
    withdraw_destination: Account<'info, TokenAccount>,
    authority: Signer<'info>,
    token_program: Program<'info, Token>,
}

impl<'info> WithdrawTokens<'info> {
    pub fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let program = self.token_program.to_account_info();
        let accounts = token::Transfer {
            from: self.vault.to_account_info(),
            to: self.withdraw_destination.to_account_info(),
            authority: self.authority.to_account_info(),
        };
        CpiContext::new(program, accounts)
    }
}

#[account]
pub struct TokenPool {
    vault: Pubkey,
    mint: Pubkey,
    withdraw_destination: Pubkey,
    bump: u8,
}
```

### Closing accounts
- Severity: High
- Description:  
During the audit, if the program's code includes the ability to close an Account, it's important to take note of the following:

1. After transferring the Account's lamports, it should be filled with CLOSED_ACCOUNT_DISCRIMINATOR data.

2. In other functions within the program, there should be checks to prevent functions related to an Account filled with CLOSED_ACCOUNT_DISCRIMINATOR from being called.
- Exploit Scenario:  
```rust
#[program]
pub mod closing_accounts_insecure {
    use super::*;

    pub fn close(ctx: Context<Close>) -> ProgramResult {
        let dest_starting_lamports = ctx.accounts.destination.lamports();

        **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
            .checked_add(ctx.accounts.account.to_account_info().lamports())
            .unwrap();
        **ctx.accounts.account.to_account_info().lamports.borrow_mut() = 0;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Close<'info> {
    account: Account<'info, Data>,
    destination: AccountInfo<'info>,
}

#[account]
pub struct Data {
    data: u64,
}
```
- Recommendation:  
```rust
#[program]
pub mod closing_accounts_secure {
    use super::*;

    pub fn close(ctx: Context<Close>) -> ProgramResult {
        let dest_starting_lamports = ctx.accounts.destination.lamports();

        let account = ctx.accounts.account.to_account_info();
        **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
            .checked_add(account.lamports())
            .unwrap();
        **account.lamports.borrow_mut() = 0;

        let mut data = account.try_borrow_mut_data()?;
        for byte in data.deref_mut().iter_mut() {
            *byte = 0;
        }

        let dst: &mut [u8] = &mut data;
        let mut cursor = Cursor::new(dst);
        cursor.write_all(&CLOSED_ACCOUNT_DISCRIMINATOR).unwrap();

        Ok(())
    }

    pub fn force_defund(ctx: Context<ForceDefund>) -> ProgramResult {
        let account = &ctx.accounts.account;

        let data = account.try_borrow_data()?;
        assert!(data.len() > 8);

        let mut discriminator = [0u8; 8];
        discriminator.copy_from_slice(&data[0..8]);
        if discriminator != CLOSED_ACCOUNT_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }

        let dest_starting_lamports = ctx.accounts.destination.lamports();

        **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
            .checked_add(account.lamports())
            .unwrap();
        **account.lamports.borrow_mut() = 0;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Close<'info> {
    account: Account<'info, Data>,
    destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ForceDefund<'info> {
    account: AccountInfo<'info>,
    destination: AccountInfo<'info>,
}

#[account]
pub struct Data {
    data: u64,
}
```

### Sysvar address checking
- Severity: High
- Description:  
The system account could potentially be replaced by a forged account.
- Exploit Scenario:  
```rust
#[program]
pub mod insecure {
    use super::*;

    pub fn check_sysvar_address(ctx: Context<CheckSysvarAddress>) -> Result<()> {
        msg!("Rent Key -> {}", ctx.accounts.rent.key().to_string());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CheckSysvarAddress<'info> {
    rent: AccountInfo<'info>,
}
```
- Recommendation:  
```rust
#[program]
pub mod secure {
    use super::*;

    pub fn check_sysvar_address(ctx: Context<CheckSysvarAddress>) -> Result<()> {
        require_eq!(ctx.accounts.rent.key(), sysvar::rent::ID);
        msg!("Rent Key -> {}", ctx.accounts.rent.key().to_string());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CheckSysvarAddress<'info> {
    rent: AccountInfo<'info>,
}
```


### Account Reloading
- Severity: High
- Description:  
The problems CPIs can introduce do not end there. While Anchor does a lot for you automatically, one thing it doesn’t do is update deserialized accounts after a CPI.

For example, imagine you have a Mint account and are just about to mint some token for the caller to track their contribution to a liquidity pool. You perform a CPI to the token program to mint these tokens and then read the current supply from the Mint account for a calculation later on. While, intuitively, you might expect the supply to be accurate, accounts in Anchor don’t update their data after a CPI!
- Exploit Scenario:  
```rust
let authority_seeds = /* seeds */;

let mint_to = MintTo {
    mint: self.liquidity_mint.to_account_info(),
    to: self.user.to_account_info(),
    authority: self.liquidity_mint_authority.to_account_info()
};

msg!("Supply before: {}", self.liquidity_mint.supply);

anchor_spl::token::mint_to(
    CpiContext::new_with_signer(
        self.token_program.to_account_info(),
        mint_to,
        authority_seeds
    ),
    amount
)?;

msg!("Supply after: {}", self.liquidity_mint.supply); // stays the same!
```


- Recommendation:  
To get the expected behavior, make sure to call Anchor’s reload method on the account. This will refresh the struct’s fields with the current underlying data.



## Case Analysis
### Sysvar system account not checked

##### Vulnerability example

The function "load_current_index" does not verify that "sysvar account" is really "system sysvar".

```rust
pub fn verify_signatures(
    ctx: &ExecutionContext,
    accs: &mut VerifySignatures,
    data: VerifySignaturesData,
) -> Result<()> {
  	......
    let current_instruction = solana_program::sysvar::instructions::load_current_index(
        &accs.instruction_acc.try_borrow_mut_data()?,
    );
```


##### FixCode

The incoming address needs to be verified before the information in the account can be deserialized.

```rust
pub fn verify_signatures(
    ctx: &ExecutionContext,
    accs: &mut VerifySignatures,
    data: VerifySignaturesData,
) -> Result<()> {

    if *accs.instruction_acc.key != solana_program::sysvar::instructions::id() {
        return Err(SolitaireError::InvalidSysvar(*accs.instruction_acc.key));
    }
  	......
    let current_instruction = solana_program::sysvar::instructions::load_current_index(
        &accs.instruction_acc.try_borrow_mut_data()?,
    );
    
```



- Related Events

[Solana跨链桥虫洞协议(Wormhole Protocal)攻击事件](https://mp.weixin.qq.com/s/x39VlJM0tKQ7r8Xzzo25gQ)

### The PDA account is used but the caller's account and the beneficiary's account are not checked

##### Vulnerability example

This contract uses Anchor, a solana development framework. Since market_authority is a PDA account (using a PDA, the program can programmatically sign certain addresses without the need for a private key. At the same time, the PDA ensures that no external users can also generate for the same address. Valid signature), this function call only verifies whether the initiator depositor has signed or not. As long as the signature conditions are met, the market_authority will be signed directly, so that all users can use this function to burn other users' Tokens and then transfer the proceeds to their own. account.

```rust
pub struct WithdrawTokens<'info> {
    #[account(has_one = market_authority)]
    pub market: Loader<'info, Market>,
    pub market_authority: AccountInfo<'info>,
    #[account(mut,
              has_one = market,
              has_one = vault,
              has_one = deposit_note_mint)]
    pub reserve: Loader<'info, Reserve>,
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    #[account(mut)]
    pub deposit_note_mint: AccountInfo<'info>,
    #[account(signer)]
    pub depositor: AccountInfo<'info>,
    #[account(mut)]
    pub deposit_note_account: AccountInfo<'info>,
    #[account(mut)]
    pub withdraw_account: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}
impl<'info> WithdrawTokens<'info> {
    fn transfer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            Transfer {
                from: self.vault.to_account_info(),
                to: self.withdraw_account.to_account_info(),
                authority: self.market_authority.clone(),
            },
        )
    }
    fn note_burn_context(&self) -> CpiContext<'_, '_, '_, 'info, Burn<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            Burn {
                to: self.deposit_note_account.to_account_info(),
                mint: self.deposit_note_mint.to_account_info(),
                authority: self.market_authority.clone(),
            },
        )
    }
	...
}
```

##### FixCode

The first is that authority: self.market_authority.clone() is not used in the WithdrawTokens function, as a fixed verification. Instead, verify the signer, and then use Withdraw to call WithdrawTokens,

Then the deposit_account account is verified in Withdraw. This derived address is generated by reserve.key and depositor.key as seeds, and it is necessary to verify whether the depositor has a signature, so that the deposit_account account cannot be forged.

```rust
pub struct Withdraw<'info> {
    #[account(has_one = market_authority)]
    pub market: Loader<'info, Market>,
    pub market_authority: AccountInfo<'info>,
    #[account(mut,
              has_one = market,
              has_one = vault,
              has_one = deposit_note_mint)]
    pub reserve: Loader<'info, Reserve>,
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    #[account(mut)]
    pub deposit_note_mint: AccountInfo<'info>,
    #[account(signer)]
    pub depositor: AccountInfo<'info>,
    #[account(mut,
              seeds = [
                  b"deposits".as_ref(),
                  reserve.key().as_ref(),
                  depositor.key.as_ref()
              ],
              bump = bump)]
    pub deposit_account: AccountInfo<'info>,
    #[account(mut)]
    pub withdraw_account: AccountInfo<'info>,
    #[account(address = crate::ID)]
    pub jet_program: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

impl<'info> Withdraw<'info> {
    fn withdraw_tokens_context(&self) -> CpiContext<'_, '_, '_, 'info, WithdrawTokens<'info>> {
        CpiContext::new(
            self.jet_program.to_account_info(),
            WithdrawTokens {
                market: self.market.to_account_info(),
                market_authority: self.market_authority.to_account_info(),
                reserve: self.reserve.to_account_info(),
                vault: self.vault.to_account_info(),
                deposit_note_mint: self.deposit_note_mint.to_account_info(),
                depositor: self.market_authority.to_account_info(),
                deposit_note_account: self.deposit_account.to_account_info(),
                withdraw_account: self.withdraw_account.to_account_info(),
                token_program: self.token_program.clone(),
            },
        )
    }
}
```

```rust
pub struct WithdrawTokens<'info> {
    #[account(has_one = market_authority)]
    pub market: Loader<'info, Market>,
    pub market_authority: AccountInfo<'info>,
    #[account(mut,
              has_one = market,
              has_one = vault,
              has_one = deposit_note_mint)]
    pub reserve: Loader<'info, Reserve>,
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    #[account(mut)]
    pub deposit_note_mint: AccountInfo<'info>,
    #[account(signer)]
    pub depositor: AccountInfo<'info>,
    #[account(mut)]
    pub deposit_note_account: AccountInfo<'info>,
    #[account(mut)]
    pub withdraw_account: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}
impl<'info> WithdrawTokens<'info> {
    fn transfer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            Transfer {
                from: self.vault.to_account_info(),
                to: self.withdraw_account.to_account_info(),
                authority: self.market_authority.clone(),
            },
        )
    }
    fn note_burn_context(&self) -> CpiContext<'_, '_, '_, 'info, Burn<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            Burn {
                to: self.deposit_note_account.to_account_info(),
                mint: self.deposit_note_mint.to_account_info(),
                authority: self.depositor.clone(),
            },
        )
    }
  ...
}
```



- Related Events

[Jet Protocol 任意提款漏洞](https://mp.weixin.qq.com/s/Hxvaz8u21p94ChxCshIftA)

## Continuous update. . .
