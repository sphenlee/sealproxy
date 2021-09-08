use anyhow::Result;
use route_recognizer::Router;

pub struct PathMatch {
    router: Router<()>,
    not_router: Router<()>,
}

impl PathMatch {
    pub fn new(paths: &[String], not_paths: &[String]) -> Result<PathMatch> {
        let mut router = Router::new();
        let mut not_router = Router::new();

        for path in paths {
            router.add(path.as_ref(), ());
        }
        for path in not_paths {
            not_router.add(path.as_ref(), ());
        }

        Ok(Self { router, not_router })
    }

    pub fn matches(&self, path: &str) -> Result<bool> {
        let matches = self.router.recognize(path).is_ok();
        let not_matches = self.not_router.recognize(path).is_ok();

        Ok(matches && !not_matches)
    }
}
