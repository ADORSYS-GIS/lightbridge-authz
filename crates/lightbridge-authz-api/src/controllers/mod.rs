pub mod accounts;
pub mod api_keys;
pub mod projects;

use serde::Deserialize;
use utoipa::IntoParams;

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 100;

#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct PaginationQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_list_limit")]
    pub limit: u32,
}

fn default_list_limit() -> u32 {
    DEFAULT_LIST_LIMIT
}

impl PaginationQuery {
    pub fn normalized(self) -> (u32, u32) {
        let limit = self.limit.clamp(1, MAX_LIST_LIMIT);
        (self.offset, limit)
    }
}
