use crate::config::UserPassConf;
use crate::userbase::{LookupResult, UserBase};
use std::collections::HashMap;
use tracing::debug;

pub struct UserPass {
    users: HashMap<String, String>,
}

impl UserPass {
    pub fn new(config: &UserPassConf) -> UserPass {
        UserPass {
            users: config.users.iter().cloned().collect(),
        }
    }
}

#[async_trait::async_trait]
impl UserBase for UserPass {
    #[tracing::instrument(skip(self, user, password))]
    async fn lookup(&self, user: &str, password: &str) -> anyhow::Result<LookupResult> {
        return match self.users.get(user) {
            None => {
                debug!("user not found");
                Ok(LookupResult::NoSuchUser)
            }
            Some(expected) if password == expected => {
                debug!("successful user lookup");
                Ok(LookupResult::Success)
            }
            Some(_) => {
                debug!("incorrect password");
                Ok(LookupResult::IncorrectPassword)
            }
        };
    }
}
