use anchor_lang::prelude::*;
use switchboard_v2::{VrfAccountData, VrfRequestRandomness,SbState, OracleQueueAccountData, 
    SWITCHBOARD_PROGRAM_ID, PermissionAccountData};
use anchor_lang::solana_program::native_token::LAMPORTS_PER_SOL;
pub const MAX_PLAYERS: u32 = 5000;
use anchor_spl::token::{self, TokenAccount, Transfer, Token, Mint, SetAuthority};
use anchor_spl::associated_token::{self, AssociatedToken};
const VRF_REQUEST_COST: u64 = 2 * LAMPORTS_PER_SOL / 1000;

pub const TIME_BUFFER: i64 = 20;
const RAFFLE_SEED: &[u8] = b"RAFFLESTATESEED";
const PLAYER_SEED: &[u8] = b"PLAYERSTATESEED";
declare_id!("9mHtGQcBPNyVcWZMbx7gDQXrPTqHMta5CgLfmrV5aDeq");

#[program]
pub mod switch_raffler {
    use anchor_spl::token::spl_token::instruction::AuthorityType;
    use super::*;
    pub fn create_raffle(
        ctx: Context<CreateRaffle>,
        end_timestamp: i64,
        ticket_price: u64,
        max_players: u32,
    ) -> Result<()> {
        let raffle = &mut ctx.accounts.raffle;
        raffle.authority = *ctx.accounts.creator.key;
        raffle.total_prizes = 0;
        raffle.claimed_prizes = 0;
        raffle.winning_randomness_result = None;
        raffle.end_timestamp = end_timestamp;
        raffle.ticket_price = ticket_price;
        raffle.players = ctx.accounts.players.key();
        let mut players = ctx.accounts.players.load_init()?;
        if max_players > MAX_PLAYERS {
            return Err(RaffleError::MaxPlayersReached.into());
        }
        players.max = max_players;
        Ok(())

    }
    pub fn init_player(ctx: Context<InitPlayer>, params: PlayerInitParams) -> Result<()> {
        msg!("initializing your account, please wait...");
        let mut player = ctx.accounts.player.load_mut()?;
        player.bump = ctx.bumps.get("player").unwrap().clone();
        player.switchboard_escrow = ctx.accounts.switchboard_escrow.key();
        player.reward_address = ctx.accounts.reward_account.key();
        player.vrf = ctx.accounts.vrf.key();
        player.switchboard_state_bump = params.switchboard_state_bump;
        player.vrf_permission_bump = params.vrf_permission_bump;
        player.authority = ctx.accounts.authority.key().clone();
        player.raffle = ctx.accounts.raffle.key();
        
        drop(player);
        let vrf = ctx.accounts.vrf.load_init()?;
        if vrf.counter != 0 {
            return Err(error!(RaffleError::InvalidInitialVrfCounter));
        }
        if vrf.authority != ctx.accounts.player.key() {
            return Err(error!(RaffleError::InvalidVrfAuthority));
        }

        let raffle = &ctx.accounts.raffle;
        let seeds: &[&[&[u8]]] = &[
            &[RAFFLE_SEED],
            &[&[raffle.bump]],
        ];
        msg!("transferring ownership of escrow account to raffle program");
        token::set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority{
                account_or_mint: ctx.accounts.switchboard_escrow.to_account_info(),
                current_authority: ctx.accounts.authority.to_account_info(),
                },
                seeds
            ),
            AuthorityType::AccountOwner,
            Some(raffle.key()),
        )?;
        msg!("removing escrow close authority");
        token::set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info().clone(),
                SetAuthority {
                    account_or_mint: ctx.accounts.switchboard_escrow.to_account_info().clone(),
                    current_authority: ctx.accounts.raffle.to_account_info().clone(),
                },
                seeds,
            ),
            AuthorityType::CloseAccount,
            None,
        )?;
        Ok(())
    }

    pub fn buy_tickets(ctx: Context<BuyTickets>, amount: u64) -> Result<()> {
        let raffle = &mut ctx.accounts.raffle;
        let mut players = ctx.accounts.players.load_mut()?;

        for i in 0..amount {
            if players.players.len() as u64  >= players.max as u64 {
                return Err(RaffleError::MaxPlayersReached.into());
            }
            players.append(*ctx.accounts.buyer_token_account.to_account_info().key)?;
        }
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer{ 
                    from: ctx.accounts.buyer_token_account.to_account_info(),
                    to: ctx.accounts.proceeds.to_account_info(),
                    authority: ctx.accounts.buyer_transfer_authority.to_account_info(),
                }),
            raffle.ticket_price.checked_mul(amount as u64).ok_or(RaffleError::InvalidCalculation)?)?;

        Ok(())
    }
    pub fn add_prizes(ctx: Context<AddPrizes>, prize_index: u32, amount: u64) -> Result<()> {
        let clock = Clock::get()?;
        let raffle = &mut ctx.accounts.raffle;
        if clock.unix_timestamp > raffle.end_timestamp {
            return Err(RaffleError::RaffleEnded.into());
        }
        if prize_index != raffle.total_prizes {
            return Err(RaffleError::InvalidPrizeIndex.into());
        }
        if amount == 0 {
            return Err(RaffleError::NoPrize.into());
        }
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.from.to_account_info(),
                    to: ctx.accounts.prize.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        raffle.total_prizes = raffle
            .total_prizes
            .checked_add(1)
            .ok_or(RaffleError::InvalidCalculation)?;
        Ok(())
    }

    pub fn request_randomness(
        ctx: Context<RequestRandomness>,
        switchboard_state_bump: u8,
        vrf_permission_bump: u8,
    ) -> Result<()> {
        let clock = Clock::get()?;
        let raffle = &mut ctx.accounts.raffle;
        let end_timestamp_with_buffer = raffle
            .end_timestamp
            .checked_add(TIME_BUFFER)
            .ok_or(RaffleError::InvalidCalculation)?;
        if clock.unix_timestamp < end_timestamp_with_buffer {
            return Err(RaffleError::RaffleStillRunning.into());
        }
        if raffle.winning_randomness_result.is_some() {
            return Err(RaffleError::RandomnessAlreadyUsed.into());
        }
        let combined_balance = ctx
            .accounts
            .vrf_payer
            .amount
            .checked_add(ctx.accounts.vrf_escrow.amount)
            .unwrap_or(0);
        if combined_balance < VRF_REQUEST_COST {
            msg!(
                "missing funds to request randomness, need {}, have {}",
                VRF_REQUEST_COST,
                combined_balance
            );
            return Err(error!(RaffleError::InsufficientFunds));
        }
        else {
            msg!("requesting randomness...");
            let request_randomness_ctx = VrfRequestRandomness{
                authority: ctx.accounts.player.to_account_info(),
                vrf: ctx.accounts.vrf.to_account_info(),
                oracle_queue: ctx.accounts.oracle_queue.to_account_info(),
                queue_authority: ctx.accounts.queue_authority.to_account_info(),
                data_buffer: ctx.accounts.data_buffer.clone(),
                permission: ctx.accounts.permission.to_account_info(),
                escrow: *ctx.accounts.vrf_escrow.clone(),
                payer_wallet: ctx.accounts.vrf_payer.clone(),
                payer_authority: ctx.accounts.payer.to_account_info(),
                recent_blockhashes: ctx.accounts.recent_blockhashes.clone(),
                program_state: ctx.accounts.switchboard_program_state.to_account_info(),
                token_program: ctx.accounts.token_program.to_account_info(),
            };
            request_randomness_ctx.invoke_signed(
                ctx.accounts.switchboard_program.clone(),
                switchboard_state_bump,
                vrf_permission_bump, 
                &[&[
                    PLAYER_SEED,
                    ctx.accounts.raffle.key().as_ref(),
                    ctx.accounts.player.key().as_ref(),
                    &[ctx.accounts.player.load()?.bump],
                ]])?;
                msg!("randomness requested successfully");
        }

        Ok(())
    }

    pub fn reveal_winners(ctx: Context<RevealWinners>) -> Result<()> {
        let raffle = &mut ctx.accounts.raffle;
        let clock = Clock::get()?;
        let end_timestamp_with_buffer = raffle.end_timestamp;
            if clock.unix_timestamp < end_timestamp_with_buffer {
                return Err(RaffleError::RaffleStillRunning.into());
            }
            let vrf = ctx.accounts.vrf.load()?;
            if vrf.authority != ctx.accounts.player.key() {
                return Err(error!(RaffleError::InvalidVrfAuthority));
            }
            let result_buffer = vrf.get_result()?;
            let vrf_value: &[u32] = bytemuck::cast_slice(&result_buffer[..]);
            match raffle.winning_randomness_result {
                Some(_) => return Err(RaffleError::WinnersAlreadyDrawn.into()),
                None => raffle.winning_randomness_result = Some(vrf_value[0]),
            }
            //raffle.winning_randomness_result = Some(vrf_value[0]);

        Ok(())
    }
    pub fn claim_prizes(
        ctx: Context<ClaimPrizes>,
        prize_index: u32,
        ticket_index: u32,
    )-> Result<()> {
        let raffle = &mut ctx.accounts.raffle;
        let clock = Clock::get()?;
        let end_timestamp_with_buffer = raffle.end_timestamp;
            if clock.unix_timestamp < end_timestamp_with_buffer {
                return Err(RaffleError::RaffleStillRunning.into());
            }
            let vrf = ctx.accounts.vrf.load()?;
            if vrf.authority != ctx.accounts.player.key() {
                return Err(error!(RaffleError::InvalidVrfAuthority));
            }
            let players = ctx.accounts.players.load()?;
            let winning_randomness_result = raffle.winning_randomness_result.unwrap();
            let winning_ticket = winning_randomness_result % players.total;
            if winning_ticket != ticket_index {
                return Err(RaffleError::NotAWinner.into());
            }
            if ctx.accounts.reward_account.to_account_info().key != &ctx.accounts.player.load()?.reward_address{
                return Err(RaffleError::InvalidRewardAccount.into());
            }
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.prize.to_account_info(),
                        to: ctx.accounts.reward_account.to_account_info(),
                        authority: ctx.accounts.authority.to_account_info(),
                    },
                ),
                ctx.accounts.prize.amount,
            )?;
            raffle.claimed_prizes = raffle
            .claimed_prizes
            .checked_add(1)
            .ok_or(RaffleError::InvalidCalculation)?;
            Ok(())
    }


    pub fn collect_proceeds(ctx: Context<CollectProceeds>) -> Result<()> {
        let raffle = &ctx.accounts.raffle;
        if !raffle.winning_randomness_result.is_some() {
            return Err(RaffleError::WinnerNotDrawn.into());
        }
        let (_, nonce) = Pubkey::find_program_address(
            &[b"raffle".as_ref(), raffle.players.as_ref()],
            ctx.program_id,
        );
        let seeds = &[b"raffle".as_ref(), raffle.players.as_ref(), &[nonce]];
        let signer_seeds = &[&seeds[..]];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.proceeds.to_account_info(),
                    to: ctx.accounts.creator_proceeds.to_account_info(),
                    authority: ctx.accounts.raffle.to_account_info(),
                },
                signer_seeds,
            ),
            ctx.accounts.proceeds.amount,
        )?;
        Ok(())
    }

}


#[derive(Accounts)]
pub struct CreateRaffle<'info> {
    #[account(
        init,
        seeds = [b"raffle".as_ref(), players.key().as_ref()],
        bump,
        payer = creator,
        space = 8 + 300
        )]
    pub raffle: Account<'info, Raffle>,
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        init,
        seeds = [raffle.key().as_ref(), b"proceeds"],
        bump,
        payer = creator,
        token::mint = proceeds_mint,
        token::authority = raffle,
    )]
    pub proceeds: Account<'info, TokenAccount>,
    pub proceeds_mint: Account<'info, Mint>,
    #[account(zero)]
    pub players: AccountLoader<'info, Players>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}
#[derive(Accounts)]
pub struct InitPlayer<'info>{
    #[account(
        init,
        seeds = [b"player".as_ref(), raffle.key().as_ref(), authority.key().as_ref()],
        bump,
        payer = payer,
        space = 8 + std::mem::size_of::<PlayerState>()
    )]
    pub player: AccountLoader<'info, PlayerState>,
    pub raffle: Account<'info, Raffle>,
    #[account(
        init,
        payer = payer,
        token::mint = mint,
        token::authority = authority,
    )]
    pub switchboard_escrow: Account<'info, TokenAccount>,
    #[account(mut, signer)]
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        seeds = [raffle.key().as_ref(),player.to_account_info().key().as_ref()],
        bump,
        payer = payer,
        token::mint = mint,
        token::authority = authority,
    )]
    pub reward_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        owner = SWITCHBOARD_PROGRAM_ID @RaffleError::InvalidSwitchBoardAccount,
        constraint = vrf.load()?.authority == player.key(),
        constraint = vrf.load()?.oracle_queue == raffle.switchboard_queue @ RaffleError::InvalidSwitchBoardQueue,
    )]
    pub vrf: AccountLoader<'info, VrfAccountData>,
    pub mint: Account<'info, Mint>,
   
    pub system_program: Program<'info,System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}
#[derive(Accounts)]
pub struct BuyTickets<'info> {
    #[account(mut, has_one = players)]
    pub raffle: Account<'info, Raffle>,
    #[account(mut)]
    pub players: AccountLoader<'info, Players>,
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        mut,
        seeds = [b"proceeds".as_ref(), raffle.key().as_ref()],
        bump)]
    pub proceeds: Account<'info, TokenAccount>,
    #[account(mut)]
    pub buyer_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub buyer_transfer_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}
#[derive(Accounts)]
#[instruction(prize_index: u32)]
pub struct AddPrizes<'info> {
    #[account(mut, has_one = authority)]
    pub raffle: Account<'info, Raffle>,
    #[account(
        init,
        seeds = [b"prize".as_ref(), raffle.key().as_ref()],
        bump,
        payer = authority,
        token::mint = mint,
        token::authority = raffle,
    )]
    pub prize: Account<'info, TokenAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,

    #[account(address = anchor_spl::token::ID)]
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}
#[derive(Accounts)]
pub struct RequestRandomness<'info> {
    #[account(
        mut,
        seeds = [
            PLAYER_SEED,  
            raffle.key().as_ref(), 
            authority.key().as_ref()
        ],
        bump = player.load()?.bump,
        has_one = vrf,
        has_one = authority,
        has_one = switchboard_escrow,
    )]
    pub player: AccountLoader<'info, PlayerState>,

    #[account(mut, has_one = authority)]
    pub raffle: Account<'info, Raffle>,

    #[account(mut)]
    pub switchboard_escrow: Account<'info, TokenAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut, 
        owner = SWITCHBOARD_PROGRAM_ID @ RaffleError::InvalidSwitchBoardAccount,
    )]
    pub permission: AccountLoader<'info, PermissionAccountData>,
    
    #[account(
        mut,
        owner = SWITCHBOARD_PROGRAM_ID @RaffleError::InvalidSwitchBoardAccount,
        constraint = vrf.load()?.authority == raffle.key(),
        constraint = vrf.load()?.oracle_queue == raffle.switchboard_queue @ RaffleError::InvalidSwitchBoardQueue,
    )]
    pub vrf: AccountLoader<'info, VrfAccountData>,

    #[account(address = anchor_lang::solana_program::sysvar::recent_blockhashes::ID)]
    pub recent_blockhashes: AccountInfo<'info>,

    #[account(
        mut,
        token::mint = raffle.switchboard_mint,
        token::authority = payer,
    )]
    pub vrf_payer: Account<'info, TokenAccount>,

    #[account(
        executable,
        address = SWITCHBOARD_PROGRAM_ID @ RaffleError::InvalidSwitchBoardAccount,
    )]
    pub switchboard_program: AccountInfo<'info>,
    
    #[account(mut, 
        owner = SWITCHBOARD_PROGRAM_ID @ RaffleError::InvalidSwitchBoardAccount,
    )]
    pub data_buffer: AccountInfo<'info>,
    #[account(
        mut, 
        token::mint = raffle.switchboard_mint,
        token::authority = switchboard_program_state,
    )]
    pub vrf_escrow: Box<Account<'info, TokenAccount>>,
    /// CHECK: Will be checked in the CPI instruction
    #[account(mut, 
        owner = SWITCHBOARD_PROGRAM_ID @ RaffleError::InvalidSwitchBoardAccount,
    )]
    pub switchboard_program_state: AccountLoader<'info, SbState>,

    #[account(mut, 
        has_one = data_buffer,
        owner = SWITCHBOARD_PROGRAM_ID @ RaffleError::InvalidSwitchBoardAccount,
        constraint = 
        oracle_queue.load()?.authority == queue_authority.key()
    )]
    pub oracle_queue: AccountLoader<'info, OracleQueueAccountData>,
    pub queue_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(address = anchor_spl::token::ID)]
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct RevealWinners<'info> {
    #[account(mut, has_one = authority)]
    pub raffle: Account<'info, Raffle>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [
            PLAYER_SEED, 
            raffle.key().as_ref(), 
            player.load()?.authority.key().as_ref()
        ],
        bump = player.load()?.bump,
        has_one = vrf, // ensures a copy cat VRF account wasnt submitted
        has_one = raffle,
        has_one = switchboard_escrow,
    )]
    pub player: AccountLoader<'info, PlayerState>,
    
    #[account(mut)]
    pub switchboard_escrow: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vrf_escrow: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vrf_payer: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vrf: AccountLoader<'info, VrfAccountData>,

}

#[derive(Accounts)]
#[instruction(prize_index: u32)]
pub struct ClaimPrizes<'info> {
    #[account(mut, has_one = authority)]
    pub raffle: Account<'info, Raffle>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [
            PLAYER_SEED, 
            raffle.key().as_ref(), 
            player.load()?.authority.key().as_ref()
        ],
        bump = player.load()?.bump,
        has_one = vrf, // ensures a copy cat VRF account wasnt submitted
        has_one = raffle,
    )]
    pub player: AccountLoader<'info, PlayerState>,

    #[account(
        mut,
        seeds = [b"prize".as_ref(), raffle.key().as_ref(), prize_index.to_le_bytes().as_ref()],
        bump,
        token::mint = mint,
        token::authority = raffle,
    )]
    pub prize: Account<'info, TokenAccount>,

    #[account(
        owner = SWITCHBOARD_PROGRAM_ID @RaffleError::InvalidSwitchBoardAccount,
        constraint = vrf.load()?.authority == player.key(),
        constraint = vrf.load()?.oracle_queue == raffle.switchboard_queue @ RaffleError::InvalidSwitchBoardQueue,
    )]
    pub vrf: AccountLoader<'info, VrfAccountData>,

    #[account(
        mut,
        constraint = player.load()?.reward_address == reward_account.key(),
        seeds = [raffle.key().as_ref(),player.to_account_info().key().as_ref()],
        bump = player.load()?.bump,
    )]
    pub reward_account: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub players: AccountLoader<'info, Players>,
    #[account(address = anchor_spl::token::ID)]
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CollectProceeds<'info>{
    #[account(has_one = authority)]
    pub raffle: Account<'info, Raffle>,
    #[account(
        mut,
        seeds = [raffle.key().as_ref(), b"proceeds"],
        bump
    )]
    pub proceeds: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    #[account(
        mut,
        constraint = creator_proceeds.owner == authority.key()
    )]
    pub creator_proceeds: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}



#[repr(packed)]
#[account(zero_copy)]
pub struct PlayerState {
    pub bump: u8,
    pub authority: Pubkey,
    pub raffle: Pubkey,
    pub switchboard_escrow: Pubkey,
    pub reward_address: Pubkey,
    pub vrf: Pubkey,
    pub switchboard_state_bump: u8,
    pub vrf_permission_bump: u8,
    pub _ebuf: [u8; 1024],
}
impl Default for PlayerState {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}


#[account]
#[derive(Default, Debug)]
pub struct Raffle {
    pub authority: Pubkey,
    pub switchboard_queue: Pubkey,
    pub switchboard_mint: Pubkey,
    pub total_prizes: u32,
    pub claimed_prizes: u32,
    pub winning_randomness_result: Option<u32>,
    pub end_timestamp: i64,
    pub ticket_price: u64,
    pub players: Pubkey,
    bump: u8,
}




#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PlayerInitParams{
    pub switchboard_state_bump: u8,
    pub vrf_permission_bump: u8,
}

#[account(zero_copy)]
pub struct Players{
    pub total: u32,
    pub max: u32,
    pub players: [Pubkey; 5000],
}


impl Players {
    fn append(&mut self, entrant: Pubkey) -> Result<()>  {
        if self.total >= self.max {
            return Err(RaffleError::NotEnoughTicketsLeft.into());
        }
        self.players[self.total as usize] = entrant;
        self.total += 1;
        Ok(())
    }
}

#[error_code]
pub enum RaffleError {
    NotEnoughTicketsLeft,
    RaffleStillRunning,
    RaffleEnded,
    MaxPlayersReached,
    InvalidCalculation,
    InvalidSwitchBoardAccount,
    InvalidSwitchBoardQueue,
    InvalidPrizeIndex,
    InvalidInitialVrfCounter,
    InvalidVrfAuthority,
    InsufficientFunds,
    InvalidRewardAccount,
    WinnersAlreadyDrawn,
    WinnerNotDrawn,
    NotAWinner,
    RandomnessAlreadyUsed,
    NoPrize,
}
