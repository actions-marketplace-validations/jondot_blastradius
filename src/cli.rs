//! The command line: every command and flag. Usage errors print as `error:` and `hint:` lines.

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const TOP_HELP: &str = "Find where a bad package, action or file lives, and what it could reach.

start here
  0. br demo                    try everything below on a sample org, with no token and no network
  1. br init --org ORG          index every repo and registry your GitHub token can read (and the runners you register)
                                (or br init --path DIR to index this machine, no token needed)
  2. br hunt npm:name@1.2.3     ask \"are we exposed?\"; or --advisory GHSA-... / --text FILE
                                for execs and customers: add --format summary (a short answer, no internal names with --audience customers)
  3. br status                  see how fresh each source is and what the answer did not cover
  4. br fix, br purge           how to get to a fixed version; what to delete (never runs anything)
  5. br diff                    what changed in the index since the last scan, or since a time
  6. br evidence                a sealed file for an auditor or a customer (check it with br verify)

words
  finding   one indicator at one location (a package in one lockfile, a hash at one path)
  place     where it sits: a repo, cache, artifact, image or host. One place can hold several findings;
            a CI run that installed it is counted apart, as a run.

examples
  br hunt --advisory GHSA-q7vr-4xhc-m2jw --owner frontend
  br hunt pypi:netprobe-py@0.4.2 --fail-if found --quiet        (CI gate: exit 10 when found)
  br evidence --advisory GHSA-q7vr-4xhc-m2jw --out evidence.json --sign PATH_TO_SSH_KEY

recipes
  CI gate        br hunt npm:name@1.2.3 --now --repo $REPO --only repos --fail-if found
                 exit 10 means found; fix it and merge, then the gate passes. --only repos keeps the gate to the
                 repo's own lockfiles. --strict adds exit 3 when some sources were not checked. When both apply,
                 found wins: you get 10, never 3. A version first seen after the advisory's window still trips it.
  checkout gate  br hunt npm:name@1.2.3 --path . --fail-if found --strict
                 reads the lockfiles and manifests under the directory, with no index and no network; --strict
                 fails only on what it could not read there (an unparsable lockfile), not on the org's other sources
  laptops        on the laptop:  br scan --local --export NAME.brx --seal      (BR_HOST names the machine)
                 on the central machine:  br import NAME.brx      br hosts lists who is still missing
  private        br init --registry HOST   or   br scan --registry HOST     (uses your docker login, no token)
  registry
  one index per  br --home ~/clients/acme init --org acme      (the same as BR_HOME=~/clients/acme)
  client         --home goes before or after the command; each client's index, notes and custody log stay in their own directory

exit codes
  0   clear (or the command succeeded)      10  found (wins over 3 when both apply)
      only br hunt and --fail-if return 10; br evidence exits 0 once the file is written (the finding is in the file)
  3   --strict and some sources were not checked
  5   no index, or the index is stale for what you asked
  2   usage error (bad flag, value or indicator)
  1   failure   4  auth (token missing or not authorised)
  11  --fail-if none and nothing was found
";

#[derive(Parser, Debug)]
#[command(name = "br", version = VERSION, about = TOP_HELP, long_about = TOP_HELP, disable_help_subcommand = true,
    help_template = "{about}\n{usage-heading} {usage}\n\n{all-args}", subcommand_value_name = "COMMAND", subcommand_help_heading = "commands")]
pub struct Cli {
    /// keep the index, notes, teams and custody log in DIR instead of ~/.blastradius (the same as BR_HOME; one directory per client)
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<String>,
    /// color the output: auto (a terminal without NO_COLOR), always or never
    #[arg(long, global = true, value_name = "WHEN", value_parser = ["auto", "always", "never"])]
    pub color: Option<String>,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// build the first index from a GitHub org and/or this machine
    #[command(after_help = "example:\n  br init --org acme        (needs GITHUB_TOKEN or GH_TOKEN, or a gh login; read-only is enough)")]
    Init(InitArgs),
    /// re-read sources, or scan this machine and export the result
    #[command(
        after_help = "example:\n  br scan --stale        |        br scan --local --export laptop.brx --seal\n\nbr scan --local reads your home directory and the package and tool caches br knows about. For the whole machine: br scan --local --path /\nA scan prints its progress to stderr (every 2 s on a terminal, every 10 s otherwise); --quiet turns that off."
    )]
    Scan(ScanArgs),
    /// show how fresh each source is
    #[command(after_help = "example:\n  br status --all        |        br status --owner frontend")]
    Status(crate::cmd::status::StatusArgs),
    /// find where an indicator lives and what it could reach
    #[command(after_help = "example:\n  br hunt --advisory GHSA-q7vr-4xhc-m2jw --owner frontend\n\n--only sections: repos, ci (alias runs), caches, artifacts, images, hosts, releases")]
    Hunt(crate::cmd::hunt::HuntArgs),
    /// draft one message per owning team, with the fix and the secrets to rotate
    #[command(after_help = "example:\n  br notify --advisory GHSA-q7vr-4xhc-m2jw --format slack --now")]
    Notify(NotifyArgs),
    /// say how to get to a fixed version, per repo and per ecosystem
    #[command(after_help = "example:\n  br fix --advisory GHSA-q7vr-4xhc-m2jw --repo acme/web")]
    Fix(FixArgs),
    /// list the caches, artifacts, images and paths to delete (never runs them)
    #[command(after_help = "example:\n  br purge --advisory GHSA-q7vr-4xhc-m2jw --commands > purge.sh")]
    Purge(PurgeArgs),
    /// which names you resolve privately could a stranger have claimed on a public registry (dependency confusion)
    #[command(
        after_help = "example:\n  br claimcheck --fail-if exposed --strict        CI gate: 10 exposed, 3 if anything could not be checked\n  br claimcheck --path ./my-repo --org acme\n  br claimcheck --as-of 2026-06-09                what was true on that day\n  br claimcheck --record                          store a snapshot; br diff --claimcheck shows what changed since\n  br notify --claimcheck                          one message per owning team\n  br evidence --claimcheck --out claim.json --question \"are you exposed to dependency confusion?\"\n  br demo claimcheck                              try it on a sample registry, no token, no network\n\nbr reads manifests, lockfiles, registry settings and source maps, then asks the public registries about each name (read-only GETs, only when you run this). It never publishes or claims anything, and writes nothing unless you pass --record. Under --fail-if a run that checked nothing exits 3, with or without --strict."
    )]
    Claimcheck(crate::cmd::claimcheck::ClaimcheckArgs),
    /// what changed since the last scan, or since a time
    #[command(after_help = "example:\n  br diff npm:name@1.2.3 --last")]
    Diff(DiffArgs),
    /// write a dated evidence file (JSON + .md + seal) for an auditor or customer
    #[command(after_help = "example:\n  br evidence --advisory GHSA-q7vr-4xhc-m2jw --out ev.json --case INC-42")]
    Evidence(EvidenceArgs),
    /// check an evidence file or .brx against its seal
    #[command(after_help = "example:\n  br verify ev.json\n  br verify ev.json --allowed-signers signers     (one line per signer: NAME ssh-ed25519 AAAA..., from the signer's .pub)")]
    Verify(VerifyArgs),
    /// merge a .brx exported from another machine into the index
    #[command(after_help = "example:\n  br import laptop-priya.brx")]
    Import(ImportArgs),
    /// list the machines in the index and the org members with no laptop scan here; register or remove one
    #[command(after_help = "example:\n  br hosts\n  br hosts add ci-07 --kind runner --reach ssh      (then: br scan --host ci-07)\n  br hosts remove ci-07")]
    Hosts(HostsArgs),
    /// query the index directly (read-only SQL)
    #[command(after_help = "example:\n  br sql 'SELECT name, indexed_at FROM sources'")]
    Sql(SqlArgs),
    /// list the teams, or set the Slack channel and Jira project of one (GitHub does not know them)
    #[command(
        after_help = "example:\n  br teams                 (the same as br teams list)\n  br teams web             (one team: channel, lead, members, what it owns)\n  br teams set @acme/web --slack '#web' --jira WEB"
    )]
    Teams(TeamsArgs),
    /// list the advisories br knows, show one, or keep a note about one (window, indicators, fixed versions)
    #[command(
        after_help = "example:\n  br advisory               (the same as br advisory list)\n  br advisory show GHSA-q7vr-4xhc-m2jw\n  br advisory note GHSA-q7vr-4xhc-m2jw --window 2026-05-11T14:00Z..2026-05-11T18:00Z"
    )]
    Advisory(AdvisoryArgs),
    /// try br on a sample org built into the binary: no token, no network (bare: a 6-step tour)
    #[command(after_help = "example:\n  br demo\n  br demo hunt --advisory GHSA-q7vr-4xhc-m2jw\n\nThe sample org has its own clock (2026-05-12T07:10:00Z). It never opens your index.")]
    Demo(crate::cmd::demo::DemoArgs),
    /// serve hunt, status, advisory_show, hosts, evidence_summary and claimcheck to an AI agent over MCP (stdio, read-only; claimcheck makes read-only GETs to public registries)
    #[command(after_help = "example:\n  claude mcp add blastradius -- br mcp        (see docs/mcp.md)")]
    Mcp(crate::cmd::mcp::McpArgs),
    /// debugging aids (BR_DEV_VIEW=FILE loads the index View from a view-dump JSON instead of the store)
    #[command(hide = true, after_help = "BR_DEV_VIEW=FILE makes every command read the View from FILE (a `br view-dump` file) instead of the index.")]
    Debug(DebugArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// index this GitHub org: repos, CI runs, caches and GHCR images; lists the org's self-hosted runners the token can see, and reads the ones registered with br hosts add --reach ssh
    #[arg(long, value_name = "ORG")]
    pub org: Option<String>,
    /// also index this directory on this machine (repeatable; needs no token)
    #[arg(long, value_name = "DIR")]
    pub path: Vec<String>,
    /// with --path: turn the hash filter off and hash every file
    #[arg(long = "hash-all")]
    pub hash_all: bool,
    /// do not call GitHub or need a token; index only the --path directories
    #[arg(long = "no-github")]
    pub no_github: bool,
    /// also index this container registry with the credentials docker login stored (no GitHub token)
    #[arg(long, value_name = "HOST")]
    pub registry: Option<String>,
    /// with --org: do not also read the registries docker is logged into (by default they are indexed too, and init says which)
    #[arg(long = "no-registries")]
    pub no_registries: bool,
    /// replace an index that already holds sources (the old one and its chain-of-custody history are discarded)
    #[arg(long)]
    pub force: bool,
    /// print no progress lines while indexing
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// rescan the sources that matched this indicator, plus all stale ones
    #[arg(long, value_name = "INDICATOR")]
    pub affected: Option<String>,
    /// rescan only the stale sources
    #[arg(long)]
    pub stale: bool,
    /// rescan every source br can reach, fresh or stale; the import-only machines it cannot reach are listed
    #[arg(long)]
    pub all: bool,
    /// rescan this repository
    #[arg(long, value_name = "ORG/NAME")]
    pub repo: Option<String>,
    /// rescan this host (a machine registered with br hosts add --reach ssh; laptops use --local)
    #[arg(long, value_name = "NAME")]
    pub host: Option<String>,
    /// read this container registry with the credentials docker login stored (no GitHub token)
    #[arg(long, value_name = "HOST")]
    pub registry: Option<String>,
    /// scan this machine (named by BR_HOST) without an index
    #[arg(long)]
    pub local: bool,
    /// with --local: write the .brx even if no file was hashed (the host then stays NOT CHECKED)
    #[arg(long = "allow-empty")]
    pub allow_empty: bool,
    /// with --local: scan this directory (repeatable; default: your home directory and the package and tool caches; --path / is the whole machine)
    #[arg(long, value_name = "DIR")]
    pub path: Vec<String>,
    /// with --local: also hash files matching this glob (repeatable)
    #[arg(long, value_name = "GLOB")]
    pub hash: Vec<String>,
    /// with --local: turn the hash filter off and hash every file (slower; the stage line says so)
    #[arg(long = "hash-all")]
    pub hash_all: bool,
    /// with --local: write the result as a portable .brx file
    #[arg(long, value_name = "FILE")]
    pub export: Option<String>,
    /// with --export: also write FILE.sha256 so br verify can check it
    #[arg(long)]
    pub seal: bool,
    /// with --export: record this case id in the chain of custody
    #[arg(long, value_name = "ID")]
    pub case: Option<String>,
    /// with --export: who asked, for the chain of custody (default: BR_USER, then the git user name)
    #[arg(long = "requested-by", value_name = "NAME")]
    pub requested_by: Option<String>,
    /// with --local: record YARA hits from these rules in the export
    #[arg(long, value_name = "RULES")]
    pub yara: Option<String>,
    /// with --export --seal: sign the seal with this ssh private key
    #[arg(long, value_name = "KEY")]
    pub sign: Option<String>,
    /// print no progress lines while scanning
    #[arg(long)]
    pub quiet: bool,
}

/// The flags that say what to look for and where (with `--now`).
#[derive(Args, Debug, Default)]
pub struct QueryArgs {
    /// indicators such as npm:name@1.2.3, pypi:, cargo:, go:, action:, sha256:
    #[arg(value_name = "INDICATOR")]
    pub iocs: Vec<String>,
    /// an advisory id (GHSA, OSV, CVE) or a local advisory JSON file
    #[arg(long, value_name = "ID|FILE")]
    pub advisory: Option<String>,
    /// extract indicators from pasted advisory text (FILE, - for stdin, or the text itself)
    #[arg(long, value_name = "FILE|-|TEXT", allow_hyphen_values = true)]
    pub text: Option<String>,
    /// only this repository (and the images built from it)
    #[arg(long, value_name = "ORG/NAME")]
    pub repo: Option<String>,
    /// only what this team or person owns (frontend, @acme/frontend, dana)
    #[arg(long, value_name = "TEAM")]
    pub owner: Option<String>,
    /// only what is present now: drop removed packages and past CI runs
    #[arg(long)]
    pub now: bool,
    /// exposure window, e.g. 2026-05-11T14:00Z..2026-05-11T18:00Z (default: from the advisory)
    #[arg(long, value_name = "FROM..TO")]
    pub window: Option<String>,
    /// for secret:NAME, the rotation cutoff: a secret last updated before this date is NOT ROTATED (default: the window start)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,
}

/// The same without `--now` (diff, evidence).
#[derive(Args, Debug, Default)]
pub struct QueryArgsNoNow {
    /// indicators such as npm:name@1.2.3, pypi:, cargo:, go:, action:, sha256:
    #[arg(value_name = "INDICATOR")]
    pub iocs: Vec<String>,
    /// an advisory id (GHSA, OSV, CVE) or a local advisory JSON file
    #[arg(long, value_name = "ID|FILE")]
    pub advisory: Option<String>,
    /// extract indicators from pasted advisory text (FILE, - for stdin, or the text itself)
    #[arg(long, value_name = "FILE|-|TEXT", allow_hyphen_values = true)]
    pub text: Option<String>,
    /// only this repository (and the images built from it)
    #[arg(long, value_name = "ORG/NAME")]
    pub repo: Option<String>,
    /// only what this team or person owns (frontend, @acme/frontend, dana)
    #[arg(long, value_name = "TEAM")]
    pub owner: Option<String>,
    /// exposure window, e.g. 2026-05-11T14:00Z..2026-05-11T18:00Z (default: from the advisory)
    #[arg(long, value_name = "FROM..TO")]
    pub window: Option<String>,
}

#[derive(Args, Debug)]
pub struct NotifyArgs {
    #[command(flatten)]
    pub q: QueryArgs,
    /// slack (default), jira, md or json
    #[arg(long, value_name = "FMT")]
    pub format: Option<String>,
    /// write the messages to files here instead of printing them
    #[arg(long, value_name = "DIR|FILE")]
    pub out: Option<String>,
    /// the version to move to, the same as br fix --to; default: the advisory's fixed version
    #[arg(long, value_name = "VERSION")]
    pub to: Option<String>,
    /// do not ask GitHub or a package registry anything while planning (repos that moved since indexing are not checked)
    #[arg(long)]
    pub offline: bool,
    /// for a hash found inside a package's install, also plan for files like the others shipped with it (reported apart as
    /// "similar, not identical")
    #[arg(long)]
    pub similar_related: bool,
    #[command(flatten)]
    pub cc: crate::cmd::claimcheck::ClaimHand,
}

#[derive(Args, Debug)]
pub struct FixArgs {
    #[command(flatten)]
    pub q: QueryArgs,
    /// the version to move to (for an action: a 40-hex commit SHA); default: the advisory's fixed version
    #[arg(long, value_name = "VERSION")]
    pub to: Option<String>,
    /// write the plan to this file instead of printing it
    #[arg(long, value_name = "FILE")]
    pub out: Option<String>,
    /// do not ask GitHub or a package registry anything while planning (repos that moved since indexing are not checked)
    #[arg(long)]
    pub offline: bool,
}

#[derive(Args, Debug)]
pub struct PurgeArgs {
    #[command(flatten)]
    pub q: QueryArgs,
    /// print only the commands, ready to review and run as a script
    #[arg(long)]
    pub commands: bool,
    /// write the purge plan to this file instead of printing it
    #[arg(long, value_name = "FILE")]
    pub out: Option<String>,
    /// text (default) or json
    #[arg(long, value_name = "FMT", value_parser = ["text", "json"])]
    pub format: Option<String>,
    /// with --commands: leave out the save-the-evidence step before each deletion (the script says so in its header)
    #[arg(long)]
    pub no_preserve: bool,
    /// for a hash found inside a package's install, also plan for files like the others shipped with it (reported apart as
    /// "similar, not identical")
    #[arg(long)]
    pub similar_related: bool,
    /// do not ask GitHub or a package registry anything while planning (repos that moved since indexing are not checked)
    #[arg(long)]
    pub offline: bool,
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    #[command(flatten)]
    pub q: QueryArgsNoNow,
    /// text (default) or json
    #[arg(long, value_name = "FMT", value_parser = ["text", "json"])]
    pub format: Option<String>,
    /// compare with the index before the last scan
    #[arg(long)]
    pub last: bool,
    /// compare with the index as known at this time (2026-05-11 or 2026-05-11T14:00Z; the year is required)
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// list every changed place instead of collapsing them
    #[arg(short = 'v', long)]
    pub verbose: bool,
    #[command(flatten)]
    pub cc: crate::cmd::claimcheck::ClaimHand,
}

#[derive(Args, Debug)]
pub struct EvidenceArgs {
    #[command(flatten)]
    pub q: QueryArgsNoNow,
    /// the evidence JSON to write; with --out ev.json the report is ev.md, the seal is ev.json.sha256 (and ev.json.sha256.sig with --sign), and --audience customers adds ev.customers.md
    #[arg(long, value_name = "FILE")]
    pub out: Option<String>,
    /// still write the file, but exit 3 when sources, kinds of source or laptops were not checked
    #[arg(long)]
    pub strict: bool,
    /// exit 10 when the file says found (or 11 with none and nothing found); by default a written file exits 0
    #[arg(long = "fail-if", value_name = "found|none")]
    pub fail_if: Option<String>,
    /// who asked, for the chain of custody (default: BR_USER, then the git user name)
    #[arg(long = "requested-by", value_name = "NAME")]
    pub requested_by: Option<String>,
    /// case or ticket id, for the chain of custody
    #[arg(long, value_name = "ID")]
    pub case: Option<String>,
    /// sign the evidence with ssh-keygen -Y sign -n br-evidence -f KEY (a private key, or its .pub when ssh-agent holds it)
    #[arg(long, value_name = "KEY")]
    pub sign: Option<String>,
    /// do not write a seal (br verify will report UNVERIFIED)
    #[arg(long = "no-seal")]
    pub no_seal: bool,
    /// who reads it: auditor (default, the full file) or customers (also writes FILE.customers.md, a plain statement with no internal names)
    #[arg(long, value_name = "WHO", value_parser = ["auditor", "customers"])]
    pub audience: Option<String>,
    /// the customer's own question, word for word; it goes into QUESTION and the JSON
    #[arg(long, value_name = "TEXT")]
    pub question: Option<String>,
    /// the date the question was received (YYYY-MM-DD, or a full time)
    #[arg(long, value_name = "DATE")]
    pub received: Option<String>,
    /// for secret:NAME, the rotation cutoff: a secret updated before this date is NOT ROTATED (default: the advisory window start, then --window)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,
    #[command(flatten)]
    pub cc: crate::cmd::claimcheck::ClaimHand,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// the evidence JSON or .brx to check; FILE.sha256 must sit next to it
    #[arg(value_name = "FILE")]
    pub file: String,
    /// no seal file: check only the internal manifest
    #[arg(long = "no-seal")]
    pub no_seal: bool,
    /// ssh-keygen allowed-signers file: the signature must come from a key listed there (identity). Without it the
    /// signature is checked with check-novalidate: it proves the key signed, not whose key it is
    #[arg(long = "allowed-signers", value_name = "FILE")]
    pub allowed_signers: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// a .brx written by br scan --local --export
    #[arg(value_name = "FILE")]
    pub file: String,
    /// who asked, for the chain of custody (default: BR_USER, then the git user name)
    #[arg(long = "requested-by", value_name = "NAME")]
    pub requested_by: Option<String>,
    /// case or ticket id, for the chain of custody (default: the one in the file)
    #[arg(long, value_name = "ID")]
    pub case: Option<String>,
    /// import a file that has no seal, checked against its own manifest only
    #[arg(long = "no-seal")]
    pub no_seal: bool,
    /// tie the imported machine to a person (@login) or a team (@org/team), so hunts can name the owner
    #[arg(long, value_name = "@LOGIN")]
    pub owner: Option<String>,
    /// what the machine is: laptop, runner or server (default: what the machine itself showed, else unset)
    #[arg(long, value_name = "KIND", value_parser = ["runner", "laptop", "server"])]
    pub kind: Option<String>,
    /// index the machine under NAME instead of the name in the file (two laptops that are both called "MacBook-Pro")
    #[arg(long = "as", value_name = "NAME")]
    pub as_name: Option<String>,
    /// swap the whole host for this file; by default a second file for a host is merged in by path, the newer scan winning
    #[arg(long)]
    pub replace: bool,
}

#[derive(Args, Debug)]
pub struct HostsArgs {
    /// take an imported host out of the index (its chain-of-custody entries are kept)
    #[arg(long, value_name = "NAME")]
    pub remove: Option<String>,
    #[command(subcommand)]
    pub sub: Option<HostsSub>,
}

#[derive(Subcommand, Debug)]
pub enum HostsSub {
    /// register a machine: who owns it, what kind it is, how it is reached
    Add(HostsAdd),
    /// list the machines in the index (the same as br hosts)
    List,
    /// take an imported host out of the index (its chain-of-custody entries are kept)
    Remove {
        #[arg(value_name = "NAME")]
        name: String,
    },
}

#[derive(Args, Debug)]
pub struct HostsAdd {
    #[arg(value_name = "NAME")]
    pub name: String,
    /// the owner: @login for a person, @org/team for a team's machine
    #[arg(long, value_name = "@LOGIN")]
    pub owner: Option<String>,
    /// runner, laptop or server (a name never decides the kind; unset stays "host")
    #[arg(long, value_name = "KIND", value_parser = ["runner", "laptop", "server"])]
    pub kind: Option<String>,
    /// ssh (br can read it) or import-only (a .brx brings it in)
    #[arg(long, value_name = "HOW", value_parser = ["ssh", "import-only"])]
    pub reach: Option<String>,
    /// ssh target, if it is not NAME (user@host)
    #[arg(long, value_name = "TARGET")]
    pub target: Option<String>,
    /// scan root on that machine (repeatable; default: the whole machine)
    #[arg(long = "root", value_name = "DIR")]
    pub roots: Vec<String>,
}

#[derive(Args, Debug)]
pub struct SqlArgs {
    /// a SELECT statement
    #[arg(value_name = "SQL")]
    pub query: Option<String>,
    /// print the tables and columns instead of running a query
    #[arg(long)]
    pub schema: bool,
    /// table (default), csv or json
    #[arg(long, default_value = "table", value_name = "FMT")]
    pub format: String,
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct TeamsArgs {
    /// show one team: where it is told, its lead, its members, and the repos and machines it owns (@org/team or the short name)
    #[arg(value_name = "TEAM")]
    pub team: Option<String>,
    #[command(subcommand)]
    pub sub: Option<TeamsSub>,
}

#[derive(Subcommand, Debug)]
pub enum TeamsSub {
    /// list the teams (GitHub's and teams.yaml's) with their Slack channel, Jira project and lead
    List,
    /// set where a team is told: a Slack channel, a Jira project
    Set {
        #[arg(value_name = "@ORG/TEAM")]
        team: String,
        #[arg(long, value_name = "CHANNEL")]
        slack: Option<String>,
        #[arg(long, value_name = "PROJECT")]
        jira: Option<String>,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct AdvisoryArgs {
    /// an advisory id: the same as br advisory show ID
    #[arg(value_name = "ID")]
    pub id: Option<String>,
    #[command(subcommand)]
    pub sub: Option<AdvisorySub>,
}

#[derive(Subcommand, Debug)]
pub enum AdvisorySub {
    /// keep what you know about an advisory: its window, indicators, hashes and fixed versions (every command reads the note with the OSV data)
    #[command(
        after_help = "example:\n  br advisory note GHSA-q7vr-4xhc-m2jw --ioc npm:name@1.2.3 --ioc pypi:other@0.4.2 --fixed 1.2.4 --window 2026-05-11T14:00Z..2026-05-11T18:00Z\n\nA note is one record per advisory. Run it again to add to it; the reply lists everything stored."
    )]
    Note {
        #[arg(value_name = "ID")]
        id: String,
        /// when the bad versions were live: FROM..TO, e.g. 2026-05-11T14:00Z..2026-05-11T18:00Z (the advisory's own exposure window)
        #[arg(long, value_name = "FROM..TO")]
        window: Option<String>,
        /// the version that fixes it: VERSION for every package of the advisory, or eco:name@VERSION for one package (repeatable)
        #[arg(long, value_name = "[eco:name@]VERSION")]
        fixed: Vec<String>,
        /// an affected package version or range the advisory does not list: eco:name@1.2.3 (repeatable)
        #[arg(long, value_name = "eco:name@VER")]
        ioc: Vec<String>,
        /// a file hash that belongs to this advisory, as sha256:HEX, or sha256:HEX=NAME to say which file it is (repeatable)
        #[arg(long, value_name = "sha256:HASH[=NAME]")]
        hash: Vec<String>,
        /// a file hash that is not part of this advisory (the genuine binary), as sha256:HEX
        #[arg(long, value_name = "sha256:HASH", requires = "why")]
        benign: Option<String>,
        /// why the hash is benign
        #[arg(long, value_name = "TEXT")]
        why: Option<String>,
    },
    /// print one advisory as br reads it: packages, fixes, window, hashes, and where each came from (OSV or your note)
    Show {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// list the advisories br knows: your notes and the OSV records cached in the index
    List,
}

#[derive(Args, Debug)]
pub struct DebugArgs {
    #[command(subcommand)]
    pub sub: DebugSub,
}

#[derive(Subcommand, Debug)]
pub enum DebugSub {
    /// print the index as a View (JSON, sorted keys, indent 1)
    View,
}

// ---- usage errors ---------------------------------------------------------------------------------------------
/// The visible commands, read from the clap definition so the list can never drift from the real commands.
fn command_names() -> Vec<String> {
    Cli::command().get_subcommands().filter(|c| !c.is_hide_set()).map(|c| c.get_name().to_string()).collect()
}

/// `br advisory WORD` is `show WORD`; a word that cannot be an advisory id (they all have a dash) is a mistyped subcommand.
pub fn invalid_subcommand(group: &str, word: &str) -> BrError {
    let list: Vec<String> = group_subcommands(group).iter().map(|c| format!("'{c}'")).collect();
    BrError::new(format!("argument SUBCOMMAND: invalid choice: '{word}' (choose from {})", list.join(", ")), Some(&format!("run br {group} --help")))
}

/// The subcommands of a command group (empty for a command that has none).
fn group_subcommands(group: &str) -> Vec<String> {
    Cli::command().find_subcommand(group).map(|c| c.get_subcommands().filter(|x| !x.is_hide_set()).map(|x| x.get_name().to_string()).collect()).unwrap_or_default()
}

fn first_command(argv: &[String]) -> Option<String> {
    argv.iter().skip(1).find(|a| !a.starts_with('-')).cloned().filter(|a| Cli::command().find_subcommand(a).is_some())
}

/// Turn a clap error into the `error:` / `hint:` shape.
pub fn usage_error(e: clap::Error, argv: &[String]) -> Result<(), BrError> {
    use clap::error::{ContextKind, ErrorKind};
    match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            print!("{}", e);
            return Ok(());
        }
        _ => {}
    }
    let cmd = first_command(argv);
    let hint_for = |c: &Option<String>| match c {
        Some(c) => format!("run br {c} --help"),
        None => "run br --help".to_string(),
    };
    let ctx_str = |k: ContextKind| e.get(k).map(|v| v.to_string());
    Err(match e.kind() {
        ErrorKind::UnknownArgument => {
            let a = ctx_str(ContextKind::InvalidArg).unwrap_or_default();
            let a = a.split(" ").next().unwrap_or("").to_string();
            let mut hint = match &cmd {
                Some(c) => format!("run br {c} --help to see the flags it takes"),
                None => "run br --help".to_string(),
            };
            if cmd.as_deref() == Some("purge") && a == "--to" {
                hint = format!("purge does not choose versions; br fix --to VERSION does. {hint}");
            }
            BrError::new(format!("unrecognized arguments: {}", unknown_tail(argv, &a)), Some(&hint))
        }
        ErrorKind::InvalidSubcommand => {
            let s = ctx_str(ContextKind::InvalidSubcommand).unwrap_or_default();
            // inside a group (teams, hosts, advisory) the choices are that group's own subcommands, never the top-level commands
            let (names, label, hint) = match cmd.as_deref().map(group_subcommands) {
                Some(g) if !g.is_empty() => (g, "SUBCOMMAND", hint_for(&cmd)),
                _ => (command_names(), "COMMAND", "run br --help".to_string()),
            };
            let list: Vec<String> = names.iter().map(|c| format!("'{c}'")).collect();
            BrError::new(format!("argument {label}: invalid choice: '{s}' (choose from {})", list.join(", ")), Some(&hint))
        }
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand | ErrorKind::MissingSubcommand => match cmd.as_deref().map(|c| (c, group_subcommands(c))) {
            Some((c, g)) if !g.is_empty() => BrError::new(format!("br {c} needs a subcommand"), Some(&format!("br {c} takes: {}; br {c} --help shows how", g.join(", ")))),
            _ => no_command(),
        },
        ErrorKind::InvalidValue => {
            let flag = ctx_str(ContextKind::InvalidArg).unwrap_or_default();
            let val = ctx_str(ContextKind::InvalidValue).unwrap_or_default();
            let flag_name = flag.split(' ').next().unwrap_or("").to_string();
            let opts = ctx_str(ContextKind::ValidValue).unwrap_or_default();
            BrError::new(format!("argument {flag_name}: invalid choice: '{val}' (choose from {opts})"), Some(&hint_for(&cmd)))
        }
        _ => {
            let text = e.to_string();
            let first = text.lines().next().unwrap_or("").trim_start_matches("error: ").to_string();
            BrError::new(first, Some(&hint_for(&cmd)))
        }
    })
}

/// argparse collects every unknown token; so do we: the unknown flag and whatever else follows that clap did not use.
fn unknown_tail(argv: &[String], first: &str) -> String {
    match argv.iter().position(|a| a == first || a.starts_with(&format!("{first}="))) {
        Some(i) => argv[i].clone(),
        None => first.to_string(),
    }
}

// ---- validation --------------------------------------------------
pub fn validate(cmd: &Cmd) -> BrResult<()> {
    match cmd {
        Cmd::Scan(a) => {
            if !a.local {
                for (flag, set) in [
                    ("--export", a.export.is_some()),
                    ("--hash", !a.hash.is_empty()),
                    ("--hash-all", a.hash_all),
                    ("--path", !a.path.is_empty()),
                    ("--allow-empty", a.allow_empty),
                    ("--yara", a.yara.is_some()),
                ] {
                    if set {
                        return Err(BrError::new(format!("{flag} only applies with --local"), Some("add --local to scan this machine")));
                    }
                }
            }
            if (a.seal || a.case.is_some()) && a.export.is_none() {
                return Err(BrError::new("--seal and --case only apply with --export FILE", Some("add --export FILE")));
            }
            if a.local && (a.all || a.stale || a.affected.is_some() || a.repo.is_some() || a.host.is_some() || a.registry.is_some()) {
                return Err(BrError::new("--local scans this machine and cannot be combined with --all, --stale, --affected, --repo, --host or --registry", Some("run them as two commands")));
            }
        }
        Cmd::Init(a) => {
            if a.hash_all && a.path.is_empty() {
                return Err(BrError::new("--hash-all only applies with --path", Some("add --path DIR")));
            }
            if a.no_github && a.org.is_some() && a.path.is_empty() && a.registry.is_none() {
                return Err(BrError::new("--org with --no-github leaves nothing to index", Some("add --path DIR or --registry HOST, or drop --no-github")));
            }
        }
        Cmd::Sql(a) => {
            if !["table", "csv", "json"].contains(&a.format.as_str()) {
                return Err(BrError::new(format!("unknown format \"{}\"", a.format), Some("choose table, csv, json")));
            }
            if a.schema && a.query.is_some() {
                return Err(BrError::new("--schema takes no query", Some("run br sql --schema on its own")));
            }
        }
        Cmd::Diff(a) => {
            if a.last && a.since.is_some() {
                return Err(BrError::new("--last and --since both pick the comparison point", Some("use one of them")));
            }
        }
        Cmd::Verify(a) => {
            if a.allowed_signers.is_some() && a.no_seal {
                return Err(BrError::new("--allowed-signers checks a signature, and --no-seal skips the seal that carries it", Some("drop --no-seal")));
            }
        }
        Cmd::Evidence(a) => {
            if let Some(f) = &a.fail_if {
                if f != "found" && f != "none" {
                    return Err(BrError::new(format!("--fail-if takes found or none (got \"{f}\")"), Some("example: --fail-if found")));
                }
            }
        }
        Cmd::Notify(a) => {
            if let Some(f) = &a.format {
                if !["slack", "jira", "md", "json"].contains(&f.as_str()) {
                    return Err(BrError::new(format!("unknown format \"{f}\""), Some("choose slack, jira, md, json")));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn no_command() -> BrError {
    BrError::new("no command given", Some(&format!("commands: {}; br --help shows where to start", command_names().join(" "))))
}

pub fn dispatch(cmd: Cmd, ctx: &Ctx) -> BrResult<i32> {
    validate(&cmd)?;
    use crate::collect::cmds;
    match cmd {
        Cmd::Init(a) => cmds::init(ctx, &a),
        Cmd::Scan(a) => cmds::scan(ctx, &a),
        Cmd::Status(a) => crate::cmd::status::run(&a, ctx),
        Cmd::Hunt(a) => crate::cmd::hunt::run(&a, ctx),
        Cmd::Import(a) => cmds::import(ctx, &a),
        Cmd::Hosts(a) => cmds::hosts(ctx, &a),
        Cmd::Teams(a) => cmds::teams(ctx, &a),
        Cmd::Advisory(a) => crate::cmd::advisory::run(&a, ctx),
        Cmd::Debug(a) => cmds::debug(ctx, &a),
        Cmd::Notify(a) => crate::cmd::notify::run(&a, ctx),
        Cmd::Fix(a) => crate::cmd::fix::run(&a, ctx),
        Cmd::Purge(a) => crate::cmd::purge::run(&a, ctx),
        Cmd::Claimcheck(a) => crate::cmd::claimcheck::run(&a, ctx),
        Cmd::Diff(a) => crate::cmd::diff::run(&a, ctx),
        Cmd::Evidence(a) => crate::cmd::evidence::run(&a, ctx),
        Cmd::Verify(a) => crate::cmd::verify::run(&a, ctx),
        Cmd::Sql(a) => crate::cmd::sql::run(&a, ctx),
        Cmd::Demo(a) => crate::cmd::demo::run(&a, ctx),
        Cmd::Mcp(a) => crate::cmd::mcp::run(&a, ctx),
    }
}

/// Parse argv (program name first), run the command and return the exit code.
pub fn run(argv: Vec<String>) -> i32 {
    let res = (|| -> Result<i32, BrError> {
        let cli = match Cli::try_parse_from(&argv) {
            Ok(c) => c,
            Err(e) => {
                usage_error(e, &argv)?;
                return Ok(0);
            }
        };
        let Some(cmd) = cli.cmd else {
            return Err(no_command());
        };
        validate(&cmd)?;
        // --home DIR is BR_HOME for this command
        if let Some(h) = cli.home.as_ref().filter(|h| !h.is_empty()) {
            std::env::set_var("BR_HOME", h);
        }
        let mut ctx = Ctx::from_env()?;
        ctx.set_color_mode(cli.color.as_deref());
        dispatch(cmd, &ctx)
    })();
    use std::io::Write;
    let _ = std::io::stdout().flush();
    match res {
        Ok(c) => c,
        Err(e) => fail(&e.msg, e.hint.as_deref(), e.code),
    }
}

pub fn fail(msg: &str, hint: Option<&str>, code: i32) -> i32 {
    eprintln!("error: {msg}");
    if let Some(h) = hint {
        if !h.is_empty() {
            eprintln!("hint: {h}");
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_follows_the_crate() {
        // clap prints the command name before it: "br 0.1.0"
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn command_list_is_the_real_one() {
        let n = command_names();
        for c in ["init", "scan", "hunt", "teams", "advisory", "evidence", "verify", "sql"] {
            assert!(n.iter().any(|x| x == c), "{c} missing from {n:?}");
        }
        assert!(!n.iter().any(|x| x == "debug"));
        assert!(no_command().hint.unwrap().contains("advisory"));
    }

    #[test]
    fn claimcheck_takes_a_checkout_an_org_and_the_gates() {
        assert!(Cli::try_parse_from(["br", "claimcheck", "--path", "a", "--path", "b", "--org", "acme", "--fail-if", "exposed", "--strict", "--format", "json", "--max-names", "10"]).is_ok());
        assert!(Cli::try_parse_from(["br", "claimcheck", "--repo", "acme/web"]).is_ok());
        assert!(command_names().iter().any(|x| x == "claimcheck"));
    }

    #[test]
    fn hosts_add_takes_server_and_evidence_takes_audience() {
        assert!(Cli::try_parse_from(["br", "hosts", "add", "h", "--kind", "server"]).is_ok());
        assert!(Cli::try_parse_from(["br", "evidence", "--audience", "customers"]).is_ok());
        assert!(Cli::try_parse_from(["br", "evidence", "--audience", "press"]).is_err());
        assert!(Cli::try_parse_from(["br", "verify", "f.json", "--allowed-signers", "a"]).is_ok());
    }
}
