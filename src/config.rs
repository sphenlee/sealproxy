use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use url::Url;

#[derive(Deserialize, Debug)]
pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Deserialize, Debug)]
pub struct Server {
    pub bind: Option<String>,
    pub tls: Option<TlsConfig>,
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
pub struct AnonymousFilterConf {
    pub paths: Vec<String>,
    #[serde(default)]
    pub not_paths: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct RedirectFilterConf {
    pub location: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub not_paths: Vec<String>,
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
    Anonymous(AnonymousFilterConf),
    CookieSession(CookieSessionFilterConf),
    Basic(BasicFilterConf),
    FormLogin(FormLoginConf),
    Redirect(RedirectFilterConf),
}

#[derive(Deserialize, Debug)]
pub struct Session {
    pub private_key: String,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub server: Server,
    pub target: Target,
    pub session: Session,
    pub filters: Vec<FilterConf>,
}

pub fn load(path: &Path) -> Result<Config> {
    let reader = std::fs::File::open(path)
        .with_context(|| format!("Error loading config file: {}", path.to_string_lossy()))?;

    let config = serde_yaml::from_reader(reader)?;

    Ok(config)
}
