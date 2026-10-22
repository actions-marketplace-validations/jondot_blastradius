# Incident playbooks

One page per role. Each page gives the incident as that person meets it, three to six commands, and what the output means and does not mean.

Every example runs against the sample org that ships inside `br`:

```sh
br demo            # the 6-step tour
br demo hunt --advisory GHSA-q7vr-4xhc-m2jw
```

The story: on 2026-05-12 at 07:10 UTC, three `@tanstack` packages published the day before turn out to be malicious. The sample org (`acme`) has 40 repos, two CI runners, two laptops and a container registry. The demo clock is pinned, so the output does not change from one day to the next. On your own org, drop `demo`: `br hunt --advisory ...`. The quoted output in these pages is checked against the real binary in CI.

| Role | Page | The question |
|---|---|---|
| On-call AppSec engineer | [appsec-oncall.md](appsec-oncall.md) | Are we hit, where, and what do I paste in #security? |
| Platform / DevOps | [platform-eng.md](platform-eng.md) | Which caches, artifacts, runners and images do I clean, in what order? |
| Team lead | [team-lead.md](team-lead.md) | What do I change in my repos, and how do I know I am done? |
| CISO | [ciso.md](ciso.md) | What is the number for the CEO, and how sure are we? |
| Auditor / customer assurance | [auditor.md](auditor.md) | What can I send a customer that holds up? |
| IR consultant | [ir-consultant.md](ir-consultant.md) | What do I hand counsel, and what is outside my reach? |
| SOC analyst | [soc-analyst.md](soc-analyst.md) | Where does this package or file live? |
| Startup CTO | [startup-cto.md](startup-cto.md) | Yes or no in five minutes, with no security team? |
| AppSec or CISO, with no advisory | [claimcheck.md](claimcheck.md) | Which of our own package names could a stranger already own? (try `br demo claimcheck`: a sample registry, no network) |

Also in CI and in an agent: the GitHub Action, `--format sarif` and the pre-commit hook ([docs/action.md](../action.md)), and `br mcp` ([docs/mcp.md](../mcp.md)).

## Three things that hold on every page

- **A clean answer names what it did not check.** `CLEAR WITH GAPS` is not `CLEAR`. `--strict` turns the gaps into exit 3.
- **`br` reads. It never changes anything.** `fix`, `purge` and `notify` print what to do, and a person runs it.
- **The index has an age.** Every answer starts with how old the index is and which sources are stale. Refresh with `br scan --stale` before you rely on a number.

## What the demo cannot show

- `--now` and `--live` need a network, so `br demo` refuses them. They re-read GitHub or a machine before answering.
- `br demo claimcheck` runs on a small sample of manifests and a sample registry snapshot built into the binary, not on the demo org's own 40 repos, and every line that depends on the sample says "sample registry". It cannot `--record` (the demo keeps nothing). [claimcheck.md](claimcheck.md) shows it.
- `br init`, `br scan` and `br import` build or change an index. The demo has a fixed one.
- `br fix` in the demo says it "could not check" whether bumping a package also moves its dependency, because it cannot reach the npm registry. On a real org it checks.
- Changes you make in a demo run (a note, a `--progress` baseline) are thrown away when the command ends.
