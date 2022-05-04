mod userpass;
mod ldap;

use crate::config::UserBaseConf;
use crate::userbase::userpass::UserPass;
use anyhow::Result;
use crate::userbase::ldap::Ldap;

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

pub async fn get_user_base(conf: &UserBaseConf) -> Result<Box<DynUserBase>> {
    Ok(match conf {
        UserBaseConf::Ldap(conf) => Ldap::new(conf).await?,
        UserBaseConf::UserPass(conf) => Box::new(UserPass::new(conf)),
    })
}
