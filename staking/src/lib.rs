use anchor_lang::{
    error,
    prelude::*,
    solana_program::{
        program::{invoke, invoke_signed},
        system_instruction,
    },
};
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, /*SetAuthority,*/ Token, TokenAccount, Transfer},
};
use mpl_token_metadata::{self, accounts::*, instructions, types};
use solana_program::entrypoint::ProgramResult;
// use spl_token::instruction::AuthorityType;

declare_id!("ratnSpwdsporDA6rBDCnZzi5BvuoGhQy6hqzeHc66QE");

#[program]
pub mod staking {
    use super::*;

    pub fn init_pool(ctx: Context<InitPool>) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;
        pool.owner = ctx.accounts.owner.key();
        pool.rand = *ctx.accounts.rand.key;
        pool.reward_mint = ctx.accounts.reward_mint.key();
        pool.reward_account = ctx.accounts.reward_account.key();
        Ok(())
    }

    pub fn transfer_ownership(ctx: Context<UpdatePoolData>, _new_owner: Pubkey) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;
        pool.owner = _new_owner;
        Ok(())
    }

    pub fn update_pool_properties(
        ctx: Context<UpdatePoolData>,
        _reward_period: u64,
        _reward_amount: u64,
        _reward_amount_for_lock: u64,
        _lock_duration: u64,
        _collection: Pubkey,
        _unstake_fee_amount: u64,
    ) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;
        if _reward_period == 0 {
            return Err(error!(PoolError::InvalidRewardPeriod).into());
        }
        pool.reward_period = _reward_period;
        pool.reward_amount = _reward_amount;
        pool.reward_amount_for_lock = _reward_amount_for_lock;
        pool.lock_duration = _lock_duration;
        pool.collection = _collection;
        pool.unstake_fee_amount = _unstake_fee_amount;
        Ok(())
    }

    pub fn redeem_token(ctx: Context<RedeemToken>, amount: u64) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;
        let pool_seeds = &[pool.rand.as_ref(), &[ctx.bumps.pool]];
        let signer = &[&pool_seeds[..]];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info().clone(),
            Transfer {
                from: ctx.accounts.token_from.to_account_info().clone(),
                to: ctx.accounts.token_to.to_account_info().clone(),
                authority: pool.to_account_info().clone(),
            },
            signer,
        );
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    pub fn init_staking_data(ctx: Context<InitStakingData>) -> ProgramResult {
        let pool = &ctx.accounts.pool;
        let staking_data = &mut ctx.accounts.staking_data;
        let metadata = Metadata::try_from(&ctx.accounts.metadata)?;
        let _edition = MasterEdition::try_from(&ctx.accounts.edition)?;
        if metadata.mint != ctx.accounts.nft_mint.key() {
            msg!("metadata is not matched");
            return Err(error!(PoolError::InvalidMetadata).into());
        }
        let mut verified = false;
        if metadata.creators.is_some() {
            if let Some(creators) = &metadata.creators {
                if creators.is_empty() {
                    return Err(error!(PoolError::InvalidMetadata).into());
                }
                for creator in creators.iter() {
                    if creator.address == pool.collection && creator.verified == true {
                        verified = true;
                    }
                }
            }
        }
        if !verified {
            return Err(error!(PoolError::InvalidMetadata).into());
        }
        staking_data.pool = pool.key();
        staking_data.nft_mint = ctx.accounts.nft_mint.key();
        Ok(())
    }

    pub fn stake_nft(ctx: Context<StakeNft>) -> ProgramResult {
        let pool_key = ctx.accounts.pool.key();
        let pool_account = ctx.accounts.pool.to_account_info().clone();
        let pool = &mut ctx.accounts.pool;
        let staking_data = &mut ctx.accounts.staking_data;
        let clock = (&ctx.accounts.clock).unix_timestamp as u64;
        // let cpi_ctx = CpiContext::new(
        //     ctx.accounts.token_program.to_account_info().clone(),
        //     SetAuthority {
        //         current_authority: ctx.accounts.staker.to_account_info().clone(),
        //         account_or_mint: ctx.accounts.nft_account.to_account_info().clone(),
        //     },
        // );
        // token::set_authority(cpi_ctx, AuthorityType::AccountOwner, Some(pool.key()))?;
        // let cpi_ctx = CpiContext::new(
        //     ctx.accounts.token_program.to_account_info().clone(),
        //     Transfer {
        //         from: ctx.accounts.nft_account.to_account_info().clone(),
        //         to: ctx.accounts.to_nft_account.to_account_info().clone(),
        //         authority: ctx.accounts.staker.to_account_info().clone()
        //     }
        // );
        // token::transfer(cpi_ctx, 1)?;

        invoke(
            &instructions::Transfer {
                token: ctx.accounts.nft_account.key(),
                token_owner: ctx.accounts.staker.key(),
                destination_token: ctx.accounts.to_nft_account.key(),
                destination_owner: pool_key,
                mint: ctx.accounts.nft_mint.key(),
                metadata: *ctx.accounts.metadata.key,
                edition: Option::Some(*ctx.accounts.edition.key),
                token_record: Option::Some(*ctx.accounts.owner_token_record.key),
                destination_token_record: Option::Some(*ctx.accounts.destination_token_record.key),
                authority: ctx.accounts.staker.key(),
                payer: ctx.accounts.staker.key(),
                system_program: ctx.accounts.system_program.key(),
                sysvar_instructions: *ctx.accounts.sysvar_rent.key,
                spl_token_program: ctx.accounts.token_program.key(),
                spl_ata_program: ctx.accounts.ata_program.key(),
                authorization_rules_program: Option::Some(*ctx.accounts.authorization_rules_program.key),
                authorization_rules: Option::Some(*ctx.accounts.authorization_rules.key),
            }.instruction(instructions::TransferInstructionArgs {
                transfer_args: types::TransferArgs::V1 {
                    amount: 1,
                    authorization_data: Option::None,
                },
            }),
            &[
                ctx.accounts.metadata_program.to_account_info().clone(),
                ctx.accounts.nft_account.to_account_info().clone(),
                ctx.accounts.staker.to_account_info().clone(),
                ctx.accounts.to_nft_account.to_account_info().clone(),
                pool_account,
                ctx.accounts.nft_mint.to_account_info().clone(),
                ctx.accounts.metadata.clone(),
                ctx.accounts.edition.clone(),
                ctx.accounts.owner_token_record.clone(),
                ctx.accounts.destination_token_record.clone(),
                ctx.accounts.metadata_program.clone(),
                ctx.accounts.system_program.to_account_info().clone(),
                ctx.accounts.sysvar_rent.clone(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.ata_program.to_account_info().clone(),
                ctx.accounts.authorization_rules_program.clone(),
                ctx.accounts.authorization_rules.clone()
            ],
        )?;

        staking_data.nft_account = ctx.accounts.to_nft_account.key();
        staking_data.staker = ctx.accounts.staker.key();
        staking_data.stake_time = clock;
        staking_data.claim_time = clock;
        staking_data.is_staked = true;
        pool.total_number += 1;
        Ok(())
    }

    pub fn lock_nft(ctx: Context<LockNft>) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;
        let staking_data = &mut ctx.accounts.staking_data;
        let clock = (&ctx.accounts.clock).unix_timestamp as u64;
        staking_data.lock_status = 1;
        staking_data.lock_time = clock;
        pool.locked_number += 1;
        Ok(())
    }

    pub fn unstake_nft(ctx: Context<UnstakeNft>) -> ProgramResult {
        let pool_key = ctx.accounts.pool.key();
        let pool_account = ctx.accounts.pool.to_account_info().clone();
        let pool = &mut ctx.accounts.pool;
        let temp_pool = pool.clone();
        let staking_data = &mut ctx.accounts.staking_data;
        let clock = (&ctx.accounts.clock).unix_timestamp as u64;
        let pool_signer_seeds = &[temp_pool.rand.as_ref(), &[ctx.bumps.pool]];
        let signer = &[&pool_signer_seeds[..]];

        if staking_data.lock_status == 1 && staking_data.lock_time + pool.lock_duration > clock {
            return Err(error!(PoolError::InvalidUnstakeTime).into());
        }

        if pool.unstake_fee_amount > 0 {
            invoke(
                &system_instruction::transfer(
                    &ctx.accounts.staker.key(),
                    ctx.accounts.pool_owner.key,
                    pool.unstake_fee_amount,
                ),
                &[
                    ctx.accounts.staker.to_account_info().clone(),
                    ctx.accounts.pool_owner.clone(),
                    ctx.accounts.system_program.to_account_info().clone(),
                ],
            )?;
        }

        let amount = get_reward_amount(pool, staking_data, clock);
        let cpi_ctx_token = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info().clone(),
            Transfer {
                from: ctx.accounts.token_from.to_account_info().clone(),
                to: ctx.accounts.token_to.to_account_info().clone(),
                authority: pool.to_account_info().clone(),
            },
            signer,
        );
        token::transfer(cpi_ctx_token, amount)?;
        staking_data.claim_time = clock;

        // let cpi_ctx = CpiContext::new_with_signer(
        //     ctx.accounts.token_program.to_account_info().clone(),
        //     SetAuthority {
        //         current_authority: temp_pool.to_account_info().clone(),
        //         account_or_mint: ctx.accounts.nft_account.to_account_info().clone(),
        //     },
        //     signer,
        // );
        // token::set_authority(
        //     cpi_ctx,
        //     AuthorityType::AccountOwner,
        //     Some(staking_data.staker),
        // )?;
        // let cpi_ctx = CpiContext::new_with_signer(
        //     ctx.accounts.token_program.to_account_info().clone(),
        //     Transfer {
        //         from: ctx.accounts.nft_account.to_account_info().clone(),
        //         to: ctx.accounts.to_nft_account.to_account_info().clone(),
        //         authority: pool.to_account_info().clone(),
        //     },
        //     signer,
        // );
        // token::transfer(cpi_ctx, 1)?;

        invoke_signed(
            &instructions::Transfer {
                token: ctx.accounts.nft_account.key(),
                token_owner: pool_key,
                destination_token: ctx.accounts.to_nft_account.key(),
                destination_owner: ctx.accounts.staker.key(),
                mint: ctx.accounts.nft_mint.key(),
                metadata: *ctx.accounts.metadata.key,
                edition: Option::Some(*ctx.accounts.edition.key),
                token_record: Option::Some(*ctx.accounts.owner_token_record.key),
                destination_token_record: Option::Some(*ctx.accounts.destination_token_record.key),
                authority: pool_key,
                payer: ctx.accounts.staker.key(),
                system_program: ctx.accounts.system_program.key(),
                sysvar_instructions: *ctx.accounts.sysvar_rent.key,
                spl_token_program: ctx.accounts.token_program.key(),
                spl_ata_program: ctx.accounts.ata_program.key(),
                authorization_rules_program: Option::Some(*ctx.accounts.authorization_rules_program.key),
                authorization_rules: Option::Some(*ctx.accounts.authorization_rules.key),
            }.instruction(instructions::TransferInstructionArgs {
                transfer_args: types::TransferArgs::V1 {
                    amount: 1,
                    authorization_data: Option::None,
                },
            }),
            &[
                ctx.accounts.metadata_program.to_account_info().clone(),
                ctx.accounts.nft_account.to_account_info().clone(),
                ctx.accounts.staker.to_account_info().clone(),
                ctx.accounts.to_nft_account.to_account_info().clone(),
                pool_account,
                ctx.accounts.nft_mint.to_account_info().clone(),
                ctx.accounts.metadata.clone(),
                ctx.accounts.edition.clone(),
                ctx.accounts.owner_token_record.clone(),
                ctx.accounts.destination_token_record.clone(),
                ctx.accounts.metadata_program.clone(),
                ctx.accounts.system_program.to_account_info().clone(),
                ctx.accounts.sysvar_rent.clone(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.ata_program.to_account_info().clone(),
                ctx.accounts.authorization_rules_program.clone(),
                ctx.accounts.authorization_rules.clone()
            ],
            signer,
        )?;

        staking_data.is_staked = false;
        staking_data.staker = Pubkey::default();
        if staking_data.lock_status == 1 {
            staking_data.lock_status = 2;
        }
        pool.total_number -= 1;
        Ok(())
    }

    pub fn claim_reward(ctx: Context<ClaimReward>) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;
        let staking_data = &mut ctx.accounts.staking_data;
        let clock = (&ctx.accounts.clock).unix_timestamp as u64;

        let amount = get_reward_amount(pool, staking_data, clock);

        let pool_signer_seeds = &[pool.rand.as_ref(), &[ctx.bumps.pool]];
        let signer = &[&pool_signer_seeds[..]];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info().clone(),
            Transfer {
                from: ctx.accounts.token_from.to_account_info().clone(),
                to: ctx.accounts.token_to.to_account_info().clone(),
                authority: pool.to_account_info().clone(),
            },
            signer,
        );
        token::transfer(cpi_ctx, amount)?;
        staking_data.claim_time = clock;
        Ok(())
    }

}

pub fn get_reward_amount(pool: &Pool, staking_data: &StakingData, current_time: u64) -> u64 {
    if staking_data.lock_status == 0 || staking_data.lock_status == 2 {
        return pool.reward_amount * (current_time - staking_data.claim_time) / pool.reward_period;
    }
    if staking_data.claim_time < staking_data.lock_time {
        if staking_data.lock_time + pool.lock_duration > current_time {
            return (pool.reward_amount * (staking_data.lock_time - staking_data.claim_time)
                + pool.reward_amount_for_lock * (current_time - staking_data.lock_time))
                / pool.reward_period;
        } else {
            return (pool.reward_amount
                * (current_time - staking_data.claim_time - pool.lock_duration)
                + pool.reward_amount_for_lock * pool.lock_duration)
                / pool.reward_period;
        }
    }
    if staking_data.claim_time < staking_data.lock_time + pool.lock_duration {
        if staking_data.lock_time + pool.lock_duration > current_time {
            return pool.reward_amount_for_lock * (current_time - staking_data.claim_time)
                / pool.reward_period;
        } else {
            return (pool.reward_amount_for_lock
                * (staking_data.lock_time + pool.lock_duration - staking_data.claim_time)
                + pool.reward_amount
                    * (current_time - staking_data.lock_time - pool.lock_duration))
                / pool.reward_period;
        }
    }
    return pool.reward_amount * (current_time - staking_data.claim_time) / pool.reward_period;
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    #[account(mut)]
    staker: Signer<'info>,

    #[account(mut, seeds=[pool.rand.as_ref()], bump)]
    pool: Account<'info, Pool>,

    #[account(mut, has_one=staker, has_one=pool, constraint=staking_data.is_staked==true)]
    staking_data: Account<'info, StakingData>,

    #[account(mut, address=pool.reward_account)]
    token_from: Account<'info, TokenAccount>,

    #[account(mut,
        constraint= token_to.mint==pool.reward_mint)]
    token_to: Account<'info, TokenAccount>,

    token_program: Program<'info, Token>,

    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct UnstakeNft<'info> {
    #[account(mut)]
    staker: Signer<'info>,

    #[account(mut, seeds=[pool.rand.as_ref()], bump)]
    pool: Account<'info, Pool>,

    #[account(mut, has_one=staker, has_one=pool, has_one=nft_account, constraint=staking_data.is_staked==true)]
    staking_data: Account<'info, StakingData>,

    #[account(mut)]
    nft_account: Account<'info, TokenAccount>,

    #[account(mut, constraint=to_nft_account.mint==staking_data.nft_mint)]
    to_nft_account: Account<'info, TokenAccount>,

    token_program: Program<'info, Token>,

    #[account(mut, address=pool.reward_account)]
    token_from: Account<'info, TokenAccount>,

    #[account(mut,
        constraint= token_to.mint==pool.reward_mint)]
    token_to: Account<'info, TokenAccount>,

    clock: Sysvar<'info, Clock>,

    #[account(mut, address=pool.owner)]
    /// CHECK: Pool owner Address
    pool_owner: AccountInfo<'info>,

    system_program: Program<'info, System>,

    nft_mint: Account<'info, Mint>,

    #[account(mut, owner=mpl_token_metadata::ID)]
    /// CHECK: Metadata Account
    metadata: AccountInfo<'info>,

    #[account(owner=mpl_token_metadata::ID)]
    /// CHECK: Edition Account
    edition: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: Token Record
    owner_token_record: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: Token Record
    destination_token_record: AccountInfo<'info>,

    #[account(address=mpl_token_metadata::ID)]
    metadata_program: AccountInfo<'info>,

    /// CHECK: Sysvar_instructions
    sysvar_rent: AccountInfo<'info>,

    ata_program: Program<'info, AssociatedToken>,

    /// CHECK: Authorization Rules Program
    authorization_rules_program: AccountInfo<'info>,

    /// CHECK: Authorization Rules PDA
    authorization_rules: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct LockNft<'info> {
    #[account(mut)]
    staker: Signer<'info>,

    #[account(mut)]
    pool: Account<'info, Pool>,

    #[account(mut, has_one=staker, has_one=pool, constraint=staking_data.is_staked==true && staking_data.lock_status==0)]
    staking_data: Account<'info, StakingData>,

    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct StakeNft<'info> {
    #[account(mut)]
    staker: Signer<'info>,

    #[account(mut)]
    pool: Account<'info, Pool>,

    #[account(mut, has_one=pool, has_one=nft_mint, constraint=staking_data.is_staked==false)]
    staking_data: Account<'info, StakingData>,

    #[account(mut, constraint=nft_account.mint==staking_data.nft_mint
            && nft_account.owner==staker.key()
            && nft_account.amount==1)]
    nft_account: Account<'info, TokenAccount>,

    #[account(mut, constraint=to_nft_account.mint==staking_data.nft_mint
            && to_nft_account.owner==pool.key())]
    to_nft_account: Account<'info, TokenAccount>,

    token_program: Program<'info, Token>,

    clock: Sysvar<'info, Clock>,

    nft_mint: Account<'info, Mint>,

    #[account(mut, owner=mpl_token_metadata::ID)]
    /// CHECK: Metadata Account
    metadata: AccountInfo<'info>,

    #[account(owner=mpl_token_metadata::ID)]
    /// CHECK: Edition Account
    edition: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: Token Record
    owner_token_record: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: Token Record
    destination_token_record: AccountInfo<'info>,

    #[account(address=mpl_token_metadata::ID)]
    metadata_program: AccountInfo<'info>,

    system_program: Program<'info, System>,

    /// CHECK: Sysvar_instructions
    sysvar_rent: AccountInfo<'info>,

    ata_program: Program<'info, AssociatedToken>,

    /// CHECK: Authorization Rules Program
    authorization_rules_program: AccountInfo<'info>,

    /// CHECK: Authorization Rules PDA
    authorization_rules: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct InitStakingData<'info> {
    #[account(mut)]
    payer: Signer<'info>,

    pool: Account<'info, Pool>,

    #[account(constraint=nft_mint.decimals==0 && nft_mint.supply==1)]
    nft_mint: Account<'info, Mint>,

    #[account(owner=mpl_token_metadata::ID)]
    /// CHECK: Metadata Account
    metadata: AccountInfo<'info>,

    #[account(seeds=["metadata".as_bytes(), mpl_token_metadata::ID.as_ref(), nft_mint.key().as_ref(), "edition".as_bytes()], seeds::program= mpl_token_metadata::ID, bump, owner=mpl_token_metadata::ID)]
    /// CHECK: Metadata Account
    edition: AccountInfo<'info>,

    #[account(init,
            seeds=[nft_mint.key().as_ref(),pool.key().as_ref()],
            bump,
            payer=payer,
            space=8+STAKING_DATA_SIZE)]
    staking_data: Account<'info, StakingData>,

    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RedeemToken<'info> {
    #[account(mut)]
    owner: Signer<'info>,

    #[account(mut, has_one=owner, seeds=[pool.rand.as_ref()], bump)]
    pool: Account<'info, Pool>,

    #[account(mut, address=pool.reward_account)]
    token_from: Account<'info, TokenAccount>,

    #[account(mut)]
    token_to: Account<'info, TokenAccount>,

    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UpdatePoolData<'info> {
    #[account(mut)]
    owner: Signer<'info>,

    #[account(mut, has_one=owner)]
    pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(mut)]
    owner: Signer<'info>,

    #[account(init,
        seeds=[(*rand.key).as_ref()],
        bump,
        payer=owner,
        space=8+MAX_POOL_SIZE
    )]
    pool: Account<'info, Pool>,

    /// CHECK: Random Address
    rand: AccountInfo<'info>,

    reward_mint: Account<'info, Mint>,

    #[account(constraint=reward_account.owner==pool.key()
            && reward_account.mint==reward_mint.key())]
    reward_account: Account<'info, TokenAccount>,

    system_program: Program<'info, System>,
}

pub const MAX_POOL_SIZE: usize = 32 + 32 + 32 + 32 + 8 + 8 + 8 + 32 + 8 + 8 + 8 + 32;
pub const STAKING_DATA_SIZE: usize = 32 + 32 + 32 + 1 + 32 + 8 + 8 + 8 + 1 + 40;

#[account]
pub struct Pool {
    pub owner: Pubkey,
    pub rand: Pubkey,
    pub reward_mint: Pubkey,
    pub reward_account: Pubkey,
    pub reward_period: u64,
    pub reward_amount: u64,
    pub lock_duration: u64,
    pub reward_amount_for_lock: u64,
    pub collection: Pubkey,
    pub total_number: u64,
    pub locked_number: u64,
    pub unstake_fee_amount: u64,
}

#[account]
pub struct StakingData {
    pub pool: Pubkey,
    pub nft_mint: Pubkey,
    pub nft_account: Pubkey,
    pub is_staked: bool,
    pub staker: Pubkey,
    pub stake_time: u64,
    pub lock_time: u64,
    pub claim_time: u64,
    pub lock_status: u8,
}

#[error_code]
pub enum PoolError {
    #[msg("Invalid metadata")]
    InvalidMetadata,

    #[msg("Invalid reward period")]
    InvalidRewardPeriod,

    #[msg("Invalid unstake time")]
    InvalidUnstakeTime,
}
