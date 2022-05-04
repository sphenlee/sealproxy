use anyhow::Result;
use crate::config::LdapConf;
use crate::userbase::{DynUserBase, LookupResult, UserBase};
use ldap3::SearchEntry;
use tokio::sync::Mutex;

pub struct Ldap {
    ldap: Mutex<ldap3::Ldap>,
    user_attr: String,
    base_dn: String,
}

impl Ldap {
    pub async fn new(config: &LdapConf) -> Result<Box<DynUserBase>> {
        let (conn, ldap) = ldap3::LdapConnAsync::from_url(&config.url).await?;

        ldap3::drive!(conn); // TODO - handle this better!

        Ok(Box::new(Ldap {
            ldap: Mutex::new(ldap),
            user_attr: config.user_attr.clone().unwrap_or("uid".into()),
            base_dn: config.base_dn.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl UserBase for Ldap {
    #[tracing::instrument(skip(self, user, password))]
    async fn lookup(&self, user: &str, password: &str) -> anyhow::Result<LookupResult> {
        let query = format!("{}={}", self.user_attr, user);

        let mut ldap = self.ldap.lock().await;

        let (data, _) = ldap.search(&self.base_dn,
                                 ldap3::Scope::OneLevel, &query, &["*"]).await?
            .success()?;

        match data.len() {
            0 => return Ok(LookupResult::NoSuchUser),
            1 => (),
            _ => return Ok(LookupResult::Other("user lookup returned more than one user".to_owned()))
        };

        for result in data {
            let parsed = SearchEntry::construct(result);
            let user_dn = parsed.dn;

            ldap.simple_bind(&user_dn, password).await?.success()?;

            return Ok(LookupResult::Success)
        }

        unreachable!()
    }
}
