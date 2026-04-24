use anyhow::Result;
use hyper::body::Incoming;
use hyper::Request;
use route_recognizer::Router;

use crate::config::MatchConf;

pub struct Match {
    router: Router<()>,
    not_router: Router<()>,
    methods: Vec<String>,
}

impl Match {
    pub fn new(conf: &MatchConf) -> Result<Match> {
        Self::new_from_rules(&conf.paths, &conf.not_paths, &conf.methods)
    }

    pub fn new_from_rules(paths: &[String], not_paths: &[String], methods: &[String]) -> Result<Match> {
        let mut router = Router::new();
        let mut not_router = Router::new();

        for path in paths {
            router.add(path.as_ref(), ());
        }
        for path in not_paths {
            not_router.add(path.as_ref(), ());
        }

        Ok(Self {
            router,
            not_router,
            methods: methods.to_vec(),
        })
    }

    pub fn matches_path(&self, path: &str) -> Result<bool> {
        let matches = self.router.recognize(path).is_ok();
        let not_matches = self.not_router.recognize(path).is_ok();

        Ok(matches && !not_matches)
    }

    pub fn matches_method(&self, method: &str) -> bool {
        // If no methods are specified, match any method
        if self.methods.is_empty() {
            return true;
        }
        // Otherwise check if the request method is in the allowed list
        self.methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    }

    pub fn matches_request(&self, req: &Request<Incoming>) -> Result<bool> {
        let path_matches = self.matches_path(req.uri().path())?;
        let method_matches = self.matches_method(req.method().as_str());
        Ok(path_matches && method_matches)
    }
}
