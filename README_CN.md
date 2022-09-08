# solana 智能合约安全最佳实践

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/slowmist_team.svg?style=social&label=Follow%20%40SlowMist_Team)](https://twitter.com/slowmist_team)


  - [Solana 智能合约常见问题:](#Solana-智能合约常见问题)
    - [数值溢出](#数值溢出)
    - [算术精度误差](#算术精度误差)
    - [未对返回错误进行处理](#未对返回错误进行处理)
    - [缺少对初始化函数的权限控制](#缺少对初始化函数的权限控制)
    - [Account Owner 未检查](#Account-Owner-未检查)
    - [PDA 账户检查](#PDA-账户检查)
    - [未对账户是否签名进行校验](#未对账户是否签名进行校验)
    - [缺少对 system account 的检查](#缺少对-system-account-的检查)
  - [案例分析](#案例分析)
    - [Sysvar 系统账号未检查](#Sysvar-系统账号未检查)
    - [使用PDA账户但是未对调用执行者账户与收益者账户进行检查](#使用PDA账户但是未对调用执行者账户与收益者账户进行检查)

[[English]](./README.md)

## Solana 智能合约常见问题:

### 数值溢出

- 严重性: 高
- 描述: 
  未对计算进行溢出检查。
- 利用场景:

```rust
pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
  let user_balance = ctx.accounts.user.balance + amount;
}
```

- 推荐: 

使用 `checked_add/checked_sub/checked_div/checked_mul`, 代替 `+-*/`。

### 算术精度误差

- 严重性: 高
- 描述: 
  使用 `try_round_u64()` 进行四舍五入会导致精度问题。
- 利用场景:

```rust
pub fn collateral_to_liquidity(&self, collateral_amount: u64) -> Result<u64, ProgramError> {
    Decimal::from(collateral_amount)
        .try_div(self.0)?
        .try_round_u64()
}
```

- 推荐: 

使用 try_floor_u64() 做去尾来达到精度完整，防止套利攻击。

### 未对返回错误进行处理

- 严重性: 高

- 描述: 
  未对函数的返回错误进行校验。

- 利用场景:

  ```rust
  &spl_token::instruction::transfer(
      //...
      );
  ```

- 推荐:  

需要对函数的调用的返回错误进行处理,可以使用rust的语法糖,在末尾加上 `?` 来做结果校验。

### 缺少对初始化函数的权限控制

- 严重性: 低
- 描述: 
  在初始化全局帐户时，如果不检查签名者是否是合法的管理员/创建者，黑客可能会创建一个假帐户进行攻击。
- 利用场景:

```rust
fn init_market(
    accounts: &[AccountInfo],
) -> ProgramResult {
    // Without checking if signer is a legitimate administrator/creator. Anyone can invoke this function.
    Ok(())
}
```

- 推荐:

在程序中硬编码管理员密钥并将调用签名者密钥设置为密钥。

### Account Owner 未检查

- 严重性: 高
- 描述: 
  在对一个账号进行反序列化之前必须要确认这个账号的 owner 是归属谁，是否是符合预期的，否则可以构造一个假数据账号。
- 利用场景:

```rust
let pyth_price_info = next_account_info(account_info_iter)?;
let market_price = get_pyth_price(pyth_price_info, clock)?;
```

- 推荐: 
  对储存的数据的账号进行反序列话之前必须要对其 owner 进行校验。

### PDA 账户检查 

- 严重性: 高
- 描述: 
  PDA 是一个由 program 控制的账号但是它可以由非官方创建，请注意检查帐户是否正确。
- 利用场景:

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

- 推荐

我们建议创建一个基于唯一帐户的 PDA，作为初始配置帐户。

### 未对账户是否签名进行校验

- 严重性: 高
- 描述: 
  只有授权用户才能写入和修改帐户数据。
- 利用场景:

```rust
let old_owner = next_account_info(account_info_iter)?;
let lending_market_info = next_account_info(account_info_iter)?;
let mut market = Market::unpack(&market_info.data.borrow())?;
if &market.owner != old_owner.key {
    return Err(LendingError::InvalidMarketOwner.into());
}
market.owner = new_owner;
```

- 建议:

必须要对`old_owner.is_signer`进行校验，才可以进行权限转让。

### 缺少对 system account 的检查

- 严重性: 高
- 描述: 
  sysvar account 包含了系统账号信息。
- 相关系统账号:

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

- 利用场景:

```rust
let token_program_id = next_account_info(account_info_iter)?;
//invoke token program without checking if it is the SPL token program.
spl_token_transfer(TokenTransferParams {
    //...
    token_program: token_program_id.clone(),
})?;
```

- 建议:

可以硬编码 sysvar 的 key 到合约里，然后在系统账号使用时对其进行比较。

### 缺少对 lamports 的检查

- 严重性: 低
- 描述: 
  Solana 账号在删除时（lamports置为零），在交易未执行结束前仍然可以读取到账号里的数据，如果在读取账号数据前未检查 lamports 值，可能会导致意外发生。

- 利用场景:
暂无

- 建议:
```
if **the_account_to_read.try_borrow_lamports()? > 0 {
    //logic here
}
```

## 案例分析

### Sysvar 系统账号未检查

##### 漏洞示例

函数 `load_current_index`并不能验证 `sysvar account` 是否真的是 `system sysvar`。

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


##### 防御代码

需先对传入的地址进行校验，才能去反序列化账号中的信息。

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



- 相关事件

[Solana跨链桥虫洞协议(Wormhole Protocal)攻击事件](https://mp.weixin.qq.com/s/x39VlJM0tKQ7r8Xzzo25gQ)


### 使用PDA账户但是未对调用执行者账户与收益者账户进行检查

##### 漏洞示例

此合约是使用了一个 solana 的开发框架 Anchor，由于 market_authority 是 PDA 账号(使用 PDA，程序可以以编程方式对某些地址进行签名，而无需私钥。同时 PDA 确保没有外部用户也可以为同一地址生成有效签名)，这个函数调用只验证了发起人 depositor 是否签名，只要满足签名条件就直接给与 market_authority 签名，这样导致所有用户都可以通过此函数去焚烧其他用户的 Token 之后在把收益转给自己的账号。

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

##### 防御代码

首先是 WithdrawTokens 函数中不在使用 authority: self.market_authority.clone() ,作为固定验证。改为对签名者进行验证,其次用 Withdraw 来调用 WithdrawTokens。

然后在 Withdraw 对 deposit_account 账号进行了校验,这个派生地址是由 reserve.key 和 depositor.key 作为种子生成,并且需要校验 depositor 是否有签名，这样 deposit_account 这个账号就无法伪造。

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



- 相关事件

[Jet Protocol 任意提款漏洞](https://mp.weixin.qq.com/s/Hxvaz8u21p94ChxCshIftA)

## 持续更新。。。

