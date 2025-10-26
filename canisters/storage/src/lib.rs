use std::cell::RefCell;

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::time;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};

const MAX_PLAINTEXT_BYTES: usize = 16 * 1024;
const MAX_METADATA_BYTES: usize = 4 * 1024;

#[derive(Clone, CandidType, Deserialize)]
pub struct InitArgs {
    #[serde(default)]
    pub capacity_hint: Option<u64>,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct AnnouncementInput {
    pub address: Vec<u8>,
    pub view_tag: u8,
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    #[serde(default)]
    pub payload_type: Option<String>,
    #[serde(default)]
    pub metadata: Option<Vec<u8>>,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct Announcement {
    pub id: u64,
    pub address: Vec<u8>,
    pub view_tag: u8,
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload_type: Option<String>,
    pub metadata: Option<Vec<u8>>,
    pub sender: Principal,
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
            address: input.address.clone(),
            view_tag: input.view_tag,
            ephemeral_public_key: input.ephemeral_public_key.clone(),
            ciphertext: input.ciphertext.clone(),
            nonce: input.nonce.clone(),
            payload_type: input.payload_type.clone(),
            metadata: input.metadata.clone(),
            sender: ic_cdk::caller(),
            created_at_ns: time(),
        };
        state.announcements.push(announcement.clone());
        state.next_id += 1;
        announcement
    });
    Ok(announcement)
}

#[query]
fn list_announcements(
    start_after: Option<u64>,
    limit: Option<u32>,
    address_filter: Option<Vec<u8>>,
    view_tag: Option<u8>,
) -> AnnouncementPage {
    let limit = limit.unwrap_or(50).min(200) as usize;
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
            if let Some(address) = &address_filter {
                if &announcement.address != address {
                    continue;
                }
            }
            if let Some(tag) = view_tag {
                if announcement.view_tag != tag {
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
    if input.address.len() != 20 {
        return Err("address must be 20 bytes".to_string());
    }
    if input.ephemeral_public_key.len() != 96 {
        return Err("ephemeral_public_key must be 96 bytes (G2 compressed)".to_string());
    }
    if input.ciphertext.is_empty() || input.ciphertext.len() > MAX_PLAINTEXT_BYTES {
        return Err("ciphertext size is invalid".to_string());
    }
    if input.nonce.len() != 12 {
        return Err("nonce must be 12 bytes (AES-GCM)".to_string());
    }
    if let Some(ref metadata) = input.metadata {
        if metadata.len() > MAX_METADATA_BYTES {
            return Err("metadata too large".to_string());
        }
    }
    Ok(())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_bad_key() {
        let mut input = AnnouncementInput {
            address: vec![0; 20],
            view_tag: 0,
            ephemeral_public_key: vec![0; 96],
            ciphertext: vec![1; 16],
            nonce: vec![0; 12],
            payload_type: None,
            metadata: None,
        };
        assert!(validate_announcement(&input).is_ok());
        input.address = vec![];
        assert!(validate_announcement(&input).is_err());
    }
}
