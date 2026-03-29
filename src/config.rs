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
    pub url: Url,
    pub base_dn: String,
    pub user_attr: Option<String>,
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

fn default_true() -> bool {
    true
}

#[derive(Deserialize, Debug)]
pub struct RedirectFilterConf {
    pub location: String,
    #[serde(default = "default_true")]
    pub with_return: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub not_paths: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct CookieSessionFilterConf;

#[derive(Deserialize, Debug)]
pub struct BasicFilterConf {
    pub user_base: UserBaseConf,
}

#[derive(Deserialize, Debug)]
pub struct Oauth2FilterConf {
    pub path: String,
    pub redirect_url: Url,
    pub auth_url: Url,
    pub token_url: Url,
    pub userinfo_url: Option<Url>,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub success_redirect: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct FormLoginConf {
    pub path: String,
    pub success_redirect: Option<String>,
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
    Oauth2(Box<Oauth2FilterConf>),
}

#[derive(Deserialize, Debug)]
pub struct Session {
    pub private_key_file: String,
    pub public_key_file: String,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub server: Server,
    pub target: Target,
    pub session: Session,
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub filters: Vec<FilterConf>,
}

pub fn load(path: &Path) -> Result<Config> {
    let reader = std::fs::File::open(path)
        .with_context(|| format!("Error loading config file: {}", path.to_string_lossy()))?;

    let config = serde_yaml::from_reader(reader)?;

    Ok(config)
}
