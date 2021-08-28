mod userpass;

use crate::config::UserBaseConf;
use crate::userbase::userpass::UserPass;
use anyhow::Result;

#[derive(Debug)]
pub enum LookupResult {
    Success,
    NoSuchUser,
    IncorrectPassword,
    Other(String),
}

pub type DynUserBase = dyn UserBase + Send + Sync + 'static;

#[async_trait::async_trait]
pub trait UserBase {
    async fn lookup(&self, user: &str, password: &str) -> Result<LookupResult>;
}

pub fn get_user_base(conf: &UserBaseConf) -> Result<Box<DynUserBase>> {
    match conf {
        UserBaseConf::Ldap(_) => todo!(),
        UserBaseConf::UserPass(conf) => Ok(Box::new(UserPass::new(conf))),
    }
}
