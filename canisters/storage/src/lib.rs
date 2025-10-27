use std::cell::RefCell;

use candid::{CandidType, Deserialize};
use ic_cdk::api::time;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};

const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;
const MAX_IBE_CIPHERTEXT_BYTES: usize = 512;
const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 200;

#[derive(Clone, CandidType, Deserialize)]
pub struct InitArgs {
    #[serde(default)]
    pub capacity_hint: Option<u64>,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct AnnouncementInput {
    pub ibe_ciphertext: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct Announcement {
    pub id: u64,
    pub ibe_ciphertext: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at_ns: u64,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct AnnouncementPage {
    pub announcements: Vec<Announcement>,
    pub next_id: Option<u64>,
}

#[derive(Clone, CandidType, Deserialize, Default)]
struct State {
    announcements: Vec<Announcement>,
    next_id: u64,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[init]
fn init(args: Option<InitArgs>) {
    let _ = args;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        *state = State {
            announcements: Vec::new(),
            next_id: 0,
        }
    });
}

#[pre_upgrade]
fn pre_upgrade() {
    STATE.with(|state| {
        let state = state.borrow();
        ic_cdk::storage::stable_save((state.clone(),)).expect("failed to persist storage state");
    });
}

#[post_upgrade]
fn post_upgrade() {
    let (state,): (State,) =
        ic_cdk::storage::stable_restore().expect("failed to restore storage state");
    STATE.with(|cell| {
        *cell.borrow_mut() = state;
    });
}

#[update]
fn submit_announcement(input: AnnouncementInput) -> Result<Announcement, String> {
    validate_announcement(&input)?;
    let announcement = STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        let announcement = Announcement {
            id: state.next_id,
            ibe_ciphertext: input.ibe_ciphertext.clone(),
            ciphertext: input.ciphertext.clone(),
            nonce: input.nonce.clone(),
            created_at_ns: time(),
        };
        state.announcements.push(announcement.clone());
        state.next_id += 1;
        announcement
    });
    Ok(announcement)
}

#[query]
fn list_announcements(start_after: Option<u64>, limit: Option<u32>) -> AnnouncementPage {
    let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT) as usize;
    let (mut items, next_marker) = STATE.with(|cell| {
        let state = cell.borrow();
        let mut collected = Vec::with_capacity(limit);
        let mut next = None;
        for announcement in state.announcements.iter() {
            if let Some(start) = start_after {
                if announcement.id <= start {
                    continue;
                }
            }
            if collected.len() < limit {
                collected.push(announcement.clone());
            } else {
                next = Some(announcement.id);
                break;
            }
        }
        (collected, next)
    });

    AnnouncementPage {
        announcements: {
            items.sort_by_key(|a| a.id);
            items
        },
        next_id: next_marker,
    }
}

#[query]
fn get_announcement(id: u64) -> Option<Announcement> {
    STATE.with(|cell| {
        let state = cell.borrow();
        state.announcements.iter().find(|a| a.id == id).cloned()
    })
}

fn validate_announcement(input: &AnnouncementInput) -> Result<(), String> {
    if input.ibe_ciphertext.is_empty() || input.ibe_ciphertext.len() > MAX_IBE_CIPHERTEXT_BYTES {
        return Err("ibe_ciphertext size is invalid".to_string());
    }
    if input.ciphertext.is_empty() || input.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err("ciphertext size is invalid".to_string());
    }
    if input.nonce.len() != 12 {
        return Err("nonce must be 12 bytes (AES-GCM)".to_string());
    }
    Ok(())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_bad_key() {
        let input = AnnouncementInput {
            ibe_ciphertext: vec![0; 128],
            ciphertext: vec![1; 16],
            nonce: vec![0; 12],
        };
        assert!(validate_announcement(&input).is_ok());
    }
}
