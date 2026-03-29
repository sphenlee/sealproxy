use crate::config::Oauth2FilterConf;
use crate::filters::{empty_body, Context, Filter};
use crate::session::Claims;
use anyhow::{Context as _, Result, anyhow};
use bytes::Bytes;
use cookie::{Cookie, SameSite};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::header;
use hyper::{Method, Request, Response, StatusCode};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, RedirectUrl, Scope, TokenResponse, TokenUrl};
use rand::Rng;
use tracing::info;

pub struct Oauth2Filter {
    callback_path: String,
    client: BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    http_client: oauth2::reqwest::Client,
    login_path: String,
    scopes: Vec<String>,
    success_redirect: String,
    userinfo_url: Option<url::Url>,
}

impl Oauth2Filter {
    pub fn new(config: &Oauth2FilterConf) -> Result<Self> {
        let callback_path = config.redirect_url
            .path()
            .to_string();

        let client = BasicClient::new(
            ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(AuthUrl::from_url(config.auth_url.clone()))
            .set_token_uri(TokenUrl::from_url(config.token_url.clone()))
            .set_redirect_uri(RedirectUrl::from_url(config.redirect_url.clone()));

        let success_redirect = config.success_redirect.clone().unwrap_or_else(|| "/".to_owned());

        let http_client = oauth2::reqwest::ClientBuilder::new()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            login_path: config.path.clone(),
            callback_path,
            client,
            http_client,
            scopes: config.scopes.clone(),
            success_redirect,
            userinfo_url: config.userinfo_url.clone(),
        })
    }

    fn find_cookie_value(req: &Request<Incoming>, name: &str) -> Option<String> {
        // TODO - use cookiejat to parse the cookie
        for val in req.headers().get_all(header::COOKIE) {
            if let Ok(s) = val.to_str() {
                for cookie in s.split(';') {
                    let cookie = cookie.trim();
                    if let Some((k, v)) = cookie.split_once('=') {
                        if k == name {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    fn set_state_cookie(value: &str) -> String {
        Cookie::build(Cookie::new("oauth2_state", value.to_string()))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .to_string()
    }

    fn clear_state_cookie() -> String {
        Cookie::build(Cookie::new("oauth2_state", "".to_string()))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(0))
            .to_string()
    }

    async fn handle_login(&self, _req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let state: String = (0..32)
            .map(|_| rand::thread_rng().sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let mut auth_url = self.client.authorize_url(|| CsrfToken::new(state.clone()));

        for scope in &self.scopes {
            auth_url = auth_url.add_scope(Scope::new(scope.to_string()));
        }

        let (url, _csrf_token) = auth_url.url();

        let response = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, url.to_string())
            .header(header::SET_COOKIE, Self::set_state_cookie(&state))
            .body(empty_body())?;

        Ok(response)
    }

    async fn handle_callback(
        &self,
        req: Request<Incoming>,
        ctx: Context<'_>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let Some(query) = req.uri().query() else {
            return Err(anyhow!("missing query in oauth2 callback"));
        };

        let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        let code = params.get("code").ok_or_else(|| anyhow!("missing code parameter"))?;
        let state = params.get("state").ok_or_else(|| anyhow!("missing state parameter"))?;

        let cookie_state = Self::find_cookie_value(&req, "oauth2_state").ok_or_else(|| {
            anyhow!("missing oauth2_state cookie for callback state validation")
        })?;

        if &cookie_state != state {
            return Err(anyhow!("oauth2 state mismatch"));
        }

        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(&self.http_client)
            .await
            .context("oauth2 token exchange failed")?;

        let subject = if let Some(userinfo_url) = &self.userinfo_url {
            let response = self
                .http_client
                .get(userinfo_url.as_str())
                .bearer_auth(token.access_token().secret())
                .send()
                .await
                .context("failed to request userinfo")?;

            let userinfo: serde_json::Value = response
                .json()
                .await
                .context("failed to read userinfo response")?;

            userinfo["sub"]
                .as_str()
                .ok_or_else(|| anyhow!("missing or invalid 'sub' in userinfo"))?
                .to_string()
        } else {
            token.access_token().secret().to_string()
        };

        info!("oauth2 login success for subject {}", subject);

        // TODO - include other claims into the session claims
        let claims = Claims {
            issuer: "seal/oauth2".to_string(),
            subject,
        };

        let resp = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, self.success_redirect.clone())
            .header(header::SET_COOKIE, Self::clear_state_cookie())
            .body(empty_body())?;

        ctx.establish_session(resp, claims)
    }
}

#[async_trait::async_trait]
impl Filter for Oauth2Filter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(
        &self,
        req: Request<Incoming>,
        ctx: Context<'_>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let path = req.uri().path();

        if path == self.login_path {
            if req.method() != Method::GET {
                let body = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(empty_body())?;
                return Ok(body);
            }
            return self.handle_login(req).await;
        }

        if path == self.callback_path {
            if req.method() != Method::GET {
                let body = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(empty_body())?;
                return Ok(body);
            }
            return self.handle_callback(req, ctx).await;
        }

        ctx.next(req).await
    }
}
