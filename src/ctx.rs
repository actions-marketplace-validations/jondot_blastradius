//! What every command gets: the environment and a way to load the View.

use std::path::PathBuf;

use crate::error::{BrError, BrResult};
use crate::view::View;

#[derive(Debug, Clone)]
pub struct Ctx {
    /// `BR_NOW`, else the system clock, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub now: String,
    /// `BR_HOME`, else `~/.blastradius`.
    pub home: PathBuf,
    /// `BR_USER`, else config.yaml `operator.name`, else the git user name.
    pub user: Option<String>,
    /// `BR_HOST`, else config.yaml `operator.host`: this machine's name for `scan --local` (else the system hostname).
    pub host: Option<String>,
    /// false under `NO_COLOR` or when stdout is not a TTY.
    pub color: bool,
}

/// `--color auto|always|never`: always and never are explicit (an explicit flag beats NO_COLOR); auto is on for a
/// terminal when NO_COLOR is not set.
pub fn resolve_color(mode: Option<&str>, no_color_set: bool, tty: bool) -> bool {
    match mode {
        Some("always") => true,
        Some("never") => false,
        _ => !no_color_set && tty,
    }
}

impl Ctx {
    /// Apply a `--color` flag on top of what the environment said.
    pub fn set_color_mode(&mut self, mode: Option<&str>) {
        use std::io::IsTerminal;
        if mode.is_some() {
            self.color = resolve_color(mode, std::env::var_os("NO_COLOR").is_some(), std::io::stdout().is_terminal());
        }
    }

    /// The index as a View. `BR_DEV_VIEW=FILE` loads a `view-dump` JSON instead of the store (a debugging aid).
    pub fn view(&self) -> BrResult<View> {
        // A scan of this machine with no owner belongs to the operator, for every command that reads the index
        crate::query::coverage::set_operator(self.user.as_deref());
        if let Some(path) = std::env::var_os("BR_DEV_VIEW") {
            return View::from_json_file(std::path::Path::new(&path)).map_err(|e| BrError::with_code(format!("cannot read BR_DEV_VIEW: {e}"), None, 1));
        }
        crate::store::load_view(self)
    }
}

impl Ctx {
    /// Read the environment: BR_NOW, BR_HOME, BR_USER (else the git user name), BR_HOST, NO_COLOR.
    pub fn from_env() -> BrResult<Ctx> {
        use std::io::IsTerminal;
        let now = match std::env::var("BR_NOW") {
            Ok(s) if !s.is_empty() => crate::collect::util::norm_iso(&s)?,
            _ => crate::collect::util::system_now(),
        };
        let home = match std::env::var_os("BR_HOME") {
            Some(h) if !h.is_empty() => PathBuf::from(h),
            _ => dirs::home_dir().map(|h| h.join(".blastradius")).unwrap_or_else(|| PathBuf::from(".blastradius")),
        };
        let (op_name, op_host) = operator(&home);
        let user = std::env::var("BR_USER").ok().filter(|s| !s.is_empty()).or(op_name).or_else(git_user);
        let host = std::env::var("BR_HOST").ok().filter(|s| !s.is_empty()).or(op_host);
        let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
        Ok(Ctx { now, home, user, host, color })
    }

    /// The GitHub token: GITHUB_TOKEN, else GH_TOKEN, else what `gh auth token` prints (the gh CLI's own login).
    /// BR_NO_GH=1 skips the gh lookup.
    pub fn token(&self) -> Option<String> {
        let env = ["GITHUB_TOKEN", "GH_TOKEN"].iter().find_map(|k| std::env::var(k).ok().filter(|s| !s.is_empty()));
        env.or_else(gh_token)
    }
}

/// `gh auth token` prints the token gh is logged in with (https://cli.github.com/manual/gh_auth_token).
fn gh_token() -> Option<String> {
    if std::env::var_os("BR_NO_GH").is_some() {
        return None;
    }
    let o = std::process::Command::new("gh").args(["auth", "token"]).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output().ok()?;
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !s.is_empty()).then_some(s)
}

fn git_user() -> Option<String> {
    let o = std::process::Command::new("git").args(["config", "user.name"]).stderr(std::process::Stdio::null()).output().ok()?;
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !s.is_empty()).then_some(s)
}

/// `operator: {name, host}` from BR_HOME/config.yaml.
fn operator(home: &std::path::Path) -> (Option<String>, Option<String>) {
    let Some(v) = std::fs::read_to_string(home.join("config.yaml")).ok().and_then(|t| serde_yaml::from_str::<serde_yaml::Value>(&t).ok()) else { return (None, None) };
    let get = |k: &str| v["operator"][k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    (get("name"), get("host"))
}

#[cfg(test)]
mod token_tests {
    use super::*;

    #[test]
    fn token_prefers_env_and_gh_lookup_can_be_skipped() {
        let ctx = Ctx { now: "2026-05-12T07:10:00Z".into(), home: std::path::PathBuf::from("."), user: None, host: None, color: false };
        std::env::set_var("BR_NO_GH", "1");
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GH_TOKEN");
        assert_eq!(ctx.token(), None);
        std::env::set_var("GH_TOKEN", "t-gh");
        assert_eq!(ctx.token().as_deref(), Some("t-gh"));
        std::env::set_var("GITHUB_TOKEN", "t-github");
        assert_eq!(ctx.token().as_deref(), Some("t-github"));
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GH_TOKEN");
    }
}
