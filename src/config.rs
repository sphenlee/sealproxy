use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use url::Url;

pub static CONFIG: Lazy<ArcSwapOption<Config>> = Lazy::new(|| ArcSwapOption::empty());

#[derive(Deserialize, Debug)]
pub struct Server {
    pub bind: Option<String>,
}

// #[derive(Deserialize, Debug)]
// pub struct MatchDef {
//     pub pattern: String,
//     pub method: Option<String>,
//     pub filters: Vec<FilterConf>,
// }

#[derive(Deserialize, Debug)]
pub struct LdapConf {
    pub addr: Url,
    pub bind_dn: String,
}

#[derive(Deserialize, Debug)]
pub struct UserPassConf {
    pub users: Vec<(String, String)>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum UserBaseConf {
    Ldap(LdapConf),
    UserPass(UserPassConf),
}

#[derive(Deserialize, Debug)]
pub struct Target {
    pub url: Url,
    //pub r#match: Match,
}

#[derive(Deserialize, Debug)]
pub struct CookieSessionFilterConf {
    pub public_key_file: String,
}

#[derive(Deserialize, Debug)]
pub struct BasicFilterConf {
    pub user_base: UserBaseConf,
}

#[derive(Deserialize, Debug)]
pub struct FormLoginConf {
    pub path: String,
    pub success_redirect: String,
    pub failure_redirect: Option<String>,
    pub user_base: UserBaseConf,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FilterConf {
    CookieSession(CookieSessionFilterConf),
    Basic(BasicFilterConf),
    FormLogin(FormLoginConf),
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub server: Server,
    pub target: Target,
    pub filters: Vec<FilterConf>,
}

pub fn load(path: &Path) -> Result<()> {
    let reader = std::fs::File::open(path)
        .with_context(|| format!("Error loading config file: {}", path.to_string_lossy()))?;
    let config = Arc::new(serde_yaml::from_reader(reader)?);

    CONFIG.store(Some(config));

    Ok(())
}
