# solana-smart-contract-security-best-practices

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/slowmist_team.svg?style=social&label=Follow%20%40SlowMist_Team)](https://twitter.com/slowmist_team)


  - [Common pitfalls of Solana smart contracts:](#Common-pitfalls-of-Solana-smart-contracts)
    - [Value overflow](#Value-overflow)
    - [Loss of precision](#Loss-of-precision)
    - [Error not handled](#Error-not-handled)
    - [Lack of initialization permission](#Lack-of-initialization-permission)
    - [Program substitution](#Program-substitution)
    - [PDA substitution check](#PDA-substitution-check)
    - [Missing signer/ownership check](#Missing-signerownership-check)
    - [Missing system account check](#Missing-system-account-check)
    - [Missing check for lamports](#Missing-check-for-lamports)
    - [Pyth oracle check](#pyth-oracle-check)
  - [Case Analysis](#Case-Analysis)
    - [Sysvar system account not checked](#Sysvar-system-account-not-checked)
    - [The PDA account is used but the caller's account and the beneficiary's account are not checked](#The-PDA-account-is-used-but-the-callers-account-and-the-beneficiarys-account-are-not-checked)

[[简体中文]](./README_CN.md)

## Common pitfalls of Solana smart contracts:

### Value overflow
- Severity: High
- Description:  
Caculate without checking for overflow.
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

### Lack of initialization permission
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

### Program substitution
- Severity: High
- Description:  
Not check the account owner before reading, it may be created by evil program and filled with fake data.
- Exploit Scenario:  
```rust
let pyth_price_info = next_account_info(account_info_iter)?;
let market_price = get_pyth_price(pyth_price_info, clock)?;
```
- Recommendation:  
Check whether the `pyth_price_info.owner` is the correct program.

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

### Missing signer/ownership check
- Severity: High
- Description:  
Only authorized users can write/modify account data.
- Exploit Scenario:  
```rust
let old_owner = next_account_info(account_info_iter)?;
let market_info = next_account_info(account_info_iter)?;
let mut market = Market::unpack(&market_info.data.borrow())?;
if &market.owner != old_owner.key {
    return Err(LendingError::InvalidMarketOwner.into());
}
market.owner = new_owner;
```
- Recommendation:  
Check `old_owner.is_signer` before modifying the owner's data.

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

- Use scenario:
None

- Suggestion:
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

## Case Analysis
### Sysvar system account not checked

##### Vulnerability example:

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


##### FixCode:

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

##### Vulnerability example:

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

##### FixCode:

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
