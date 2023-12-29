use chrono::{DateTime, Utc};

pub struct Event {
    pub now: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub is_request_blocked: bool,
}