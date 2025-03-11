# solana 智能合约安全最佳实践

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/slowmist_team.svg?style=social&label=Follow%20%40SlowMist_Team)](https://twitter.com/slowmist_team)

  - [Solana 智能合约常见问题:](#solana-智能合约常见问题)
    - [数值溢出](#数值溢出)
    - [算术精度误差](#算术精度误差)
    - [未对返回错误进行处理](#未对返回错误进行处理)
    - [缺少对初始化函数的权限控制](#缺少对初始化函数的权限控制)
    - [Account Owner 未检查](#account-owner-未检查)
    - [PDA 账户检查](#pda-账户检查)
    - [未对账户是否签名进行校验](#未对账户是否签名进行校验)
    - [缺少对 system account 的检查](#缺少对-system-account-的检查)
    - [缺少对 lamports 的检查](#缺少对-lamports-的检查)
    - [Pyth预言机检查](#pyth预言机检查)
    - [及时状态重置](#及时状态重置)
  - [利用Anchor框架的攻击](#利用anchor框架的攻击)
    - [签名者授权](#签名者授权)
    - [账户数据匹配](#账户数据匹配)
    - [所有者检查](#所有者检查)
    - [类型伪装 cosplay](#类型伪装-cosplay)
    - [初始化检查](#初始化检查)
    - [任意 CPI](#任意-cpi)
    - [重复的可变账户](#重复的可变账户)
    - [碰撞种子规范化](#碰撞种子规范化)
    - [PDA共享](#pda共享)
    - [关闭账户](#关闭账户)
    - [Sysvar地址检查](#sysvar地址检查)
    - [账户重新加载](#账户重新加载)
  - [案例分析](#案例分析)
    - [Sysvar 系统账号未检查](#sysvar-系统账号未检查)
        - [漏洞示例](#漏洞示例)
        - [防御代码](#防御代码)
    - [使用PDA账户但是未对调用执行者账户与收益者账户进行检查](#使用pda账户但是未对调用执行者账户与收益者账户进行检查)
        - [漏洞示例](#漏洞示例-1)
        - [防御代码](#防御代码-1)
  - [持续更新。。。](#持续更新)

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

### Pyth预言机检查

- 严重性：高

- 描述：

Pyth预言机价格有时失败，我们应该小心检查其状态。

- 利用场景：

```rust
if pyth_price.agg.status != PriceStatus::Trading {
    return Err(ErrorCode::InvalidPythConfig);
}
```

- 建议：

升级Pyth sdk至最新版本。

### 及时状态重置

- 严重性：高

- 描述：

变更所有者时重置权限。

- 利用场景：

```rust
if letOption C::Some(authority) = new_authority {
    account.owner = authority;
} else {
    return Err(TokenError::InvalidInstruction.into());
}
```

- 建议：

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

## 利用Anchor框架的攻击

### 签名者授权

- 严重性：高

- 描述：

签名者检查是为了确保发起执行调用的角色是经过认证的。

- 利用场景：

账户缺少签名者检查。

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

- 建议：

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

### 账户数据匹配

- 严重性：高

- 描述：

在审计过程中，重点关注从Account的元数据解析出的数据结构。特别注意与权限相关的检查，如代币所有权和代币铸造权威。

- 利用场景：

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

- 建议：

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

### 所有者检查

- 严重性：高

- 描述：

所有者检查有两种形式：

1. 第一种类型涉及检查Account的元数据中的Owner字段，例如验证SPL代币的所有者。

2. 第二种类型是对Account本身的所有者检查。通常，在PDA（程序派生账户）的情况下，所有者是在派生过程中使用的程序ID。然而，需要注意的是，程序可以在派生过程中将所有者更改为另一个程序ID，并且只有Account的所有者可以操作Account的数据。

在审计过程中，确定应用哪种所有者检查取决于程序的业务逻辑。

- 利用场景：

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

- 建议：

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

### 类型伪装 cosplay

- 严重性：高

- 描述：

在审计过程中，识别程序中共享相同数据结构的账户。尝试推断这些不同账户可能通过使用相同的数据结构相互伪装的风险。

- 利用场景：

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

- 建议：

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

### 初始化检查

- 严重性：高

- 描述：

在商业环境中，当数据应该只被初始化一次时，使用一个标志来检查它是否已经被设置为“真”是至关重要的。

- 利用场景：

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

- 重新初始化

- 创建且不初始化

- 从其他程序传递先前初始化的账户

(例如：代币程序 => 需要检查代理人和权限)

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

- 建议：

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

### 任意 CPI

- 严重性：高

- 描述：

在审计过程中，重要的是要定位程序中的 CPI（跨程序调用）代码逻辑，并确保代码在进行 CPI 时包含对目标程序 ID 的检查。这对于验证目标程序的合法性至关重要。

- 利用场景：

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

- 建议：

```rust
#[program]
pub mod arbitrary_cpi_secure {
    use super::*;
    pub fn cpi_secure(ctx Context:<Cpi>, amount: u64) -> ProgramResult {
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

### 重复的可变账户

- 严重性：高

- 描述：

在审计过程中，重要的是要注意传递相同的 Account 作为输入是否可能导致意外的数据覆盖。

- 利用场景：

这两个账户都是可变的，并且可能是同一个账户。

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

- 建议：

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

### 碰撞种子规范化

- 严重性：高

- 描述：

"create_program_address" 和 "find_program_address" 之间存在显著差异。"create_program_address" 如果碰撞种子（bump seed）不同，即使对于相同的程序ID，也会生成不同的PDA（Program Derived Address）， "而find_program_address" 使用最大有效碰撞种子返回PDA。因此，如果不应用碰撞种子验证，并且碰撞种子是不可信任的数据，可能会导致后续代码逻辑中的安全问题。

- 利用场景：

```rust
#[program]
pub mod bump_seed_canonicalization_insecure {
use super::*;

pub fn set_value(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> ProgramResult {
    let address = Pubkey::create_program_address(&[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id)?;
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

- 建议：

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
    let (address, expected_bump) = Pubkey::find_program_address(&[key.to_le_bytes().as_ref()], ctx.program_id);
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

### PDA共享

- 严重性：高

- 描述：

在审计过程中，检查与CPI（跨程序调用）相关的代码至关重要，以确保调用具有不同角色的PDA时权限分离。这有助于防止多个角色共享相同的种子。

- 利用场景：

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
 from           : self.vault.to_account_info(),
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

- 建议：

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

### 关闭账户

- 严重性：高

- 描述：

审计在过程中，如果程序代码包含关闭账户的功能，需要注意以下几点：

1. 转移账户的lamports后，应该用CLOSED_ACCOUNT_DISCRIMINATOR数据填充。

2. 在程序的其他函数中，应该有检查以防止调用与填充了CLOSED_ACCOUNT_DISCRIMINATOR的账户相关的函数。

- 漏洞场景：

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

- 建议：

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

### Sysvar地址检查

- 严重性：高

- 描述：

系统账户可能被伪造账户替换。

- 漏洞场景：

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

- 建议：

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

### 账户重新加载

- 严重性：高

- 描述：

CPIs可能引入的问题不止于此。虽然Anchor会自动为你做很多事情，但它不会在CPI之后更新反序列化的账户。

例如，假设你有一个Mint账户，并且你即将为调用者铸造一些代币，以便他们跟踪他们对流动性池的贡献。你执行一个CPI到代币程序来铸造这些代币，然后读取Mint账户的当前供应量以供稍后计算。然而，直观上，你可能会期望供应量是准确的，Anchor中的账户在CPI之后不会更新他们的数据！

- 利用场景：

```rust

let authority_seeds = /* seeds */;

let mint_to = MintTo {

mint: self.liquidity_mint.to_account_info(),

to: self.user.to_account_info(),

authority: self.liquidityint_m_authority.to_account_info()

};

msg!("供应前: {}", self.liquidity_mint.supply);

anchor_spl::token::mint_to(

CpiContext::new_with_signer(

self.token_program.to_account_info(),

mint_to,

authority_seeds

),

amount

)?;

msg!("供应后: {}", self.liquidity_mint.supply); // 保持不变！

```

- 建议：

为了获得预期的行为，请确保在账户上调用Anchor的reload方法。这将用当前底层数据刷新结构体的字段。

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

