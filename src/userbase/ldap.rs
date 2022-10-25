use anyhow::Result;
use crate::config::LdapConf;
use crate::userbase::{DynUserBase, LookupResult, UserBase};
use ldap3::SearchEntry;
use url::Url;

pub struct Ldap {
    url: Url,
    user_attr: String,
    base_dn: String,
}

impl Ldap {
    pub fn new(config: &LdapConf) -> Result<Box<DynUserBase>> {
        Ok(Box::new(Ldap {
            url: config.url.clone(),
            user_attr: config.user_attr.clone().unwrap_or("uid".into()),
            base_dn: config.base_dn.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl UserBase for Ldap {
    #[tracing::instrument(skip(self, user, password))]
    async fn lookup(&self, user: &str, password: &str) -> anyhow::Result<LookupResult> {
        let (conn, mut ldap) = ldap3::LdapConnAsync::from_url(&self.url).await?;

        ldap3::drive!(conn);

        let query = format!("{}={}", self.user_attr, user);

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

            let result = ldap.simple_bind(&user_dn, password).await?;

            return Ok(match result.rc {
                0 => LookupResult::Success,
                49 => LookupResult::IncorrectPassword,
                _ => LookupResult::Other(format!("error from LDAP bind: {}", result))
            });
        }

        unreachable!()
    }
}
