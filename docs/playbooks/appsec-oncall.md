# On-call AppSec engineer

## The incident

The pager goes off at 07:10 with an advisory id: `GHSA-q7vr-4xhc-m2jw`. Malicious `@tanstack/*` 1.120.3 was live from 14:00 to 18:00 UTC the day before. Slack is asking "are we hit?". The incident call is at 09:00. You need a list you can paste into #security, and you need to know what the list leaves out.

## Commands

**1. Check the index before you trust it.**

```
$ br demo status
45 sources: 42 fresh, 3 stale (threshold 24h)
stale laptops: laptop-priya (a laptop is only as fresh as its last import)
run br scan --stale to refresh acme/mobile-web, ci-runner-04; laptop-priya can only be refreshed on that machine (br scan --local --export NAME.brx --seal there, then br import NAME.brx here)
[exit 0]
```

Three sources are stale. `br scan --stale` fixes two. A laptop can only be scanned on the laptop.

**2. Ask the question.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw
FOUND  3 indicators (GHSA-q7vr-4xhc-m2jw)
In 7 repos owned by 5 teams; ran in 8 CI runs that could read 9 secret names, 11 secrets; 2 images, 2 hosts, 2 caches and 2 build artifacts to clean.
index as of 05-08 10:00Z–05-12 06:30Z (oldest: laptop-priya; newest 40m old) | 3 of 45 sources stale | 3 stale + 1 laptop gap = 4 gaps | window 05-11 14:00Z..18:00Z (from your note 05-11 18:20Z)
45 findings in 15 places and 8 CI runs | repos 7 (5 present, 1 removed, 1 install-only) | ci runs 8 | caches 2 | artifacts 2 | images 2 | hosts 2 | possible 4 people and 2 machines (not counted above)
...
[exit 10]
```

The first four lines are the answer. After them come the tables: repos with file and depth, CI runs with the secret names they could read, caches, artifacts, images (deleted layers included), hosts, and the secrets to rotate.

**3. Get the version you paste.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --format summary
Yes. 7 repos, 2 images, 2 machines, 2 caches and 2 build artifacts contain or contained the affected packages (GHSA-q7vr-4xhc-m2jw).
4 people and 2 machines may also be affected but could not be confirmed.
Still present: 5 repos, 2 images, 2 machines, 2 caches and 2 build artifacts.
First seen 05-11 14:20Z (laptop-omar). 8 CI runs saw it; 9 secret names, 11 secrets were in reach.
...
Data as of 05-08 10:00Z–05-12 06:30Z (oldest: laptop-priya). Not checked: 4 sources (acme/mobile-web; ci-runner-04; laptop-priya; laptops: 11 of 12 members visible to this token in GitHub have no laptop scan here). The number can still change.
[exit 10]
```

**4. Tell each team what to do.**

```
$ br demo notify --advisory GHSA-q7vr-4xhc-m2jw --format slack
To @omar (Omar Idowu, #team-data)
...
To #team-billing (@acme/billing, lead Lena Fischer)
...
```

One draft per owning team, with the fix line, the CI runs and the secrets to rotate. `br notify` only prints. You send it.

**5. Close the incident record.** See [auditor.md](auditor.md) for `br evidence`.

## Beyond this advisory

- **Gate it before the next one.** `br hunt npm:name@1.2.3 --path . --fail-if found --strict` in CI, or the GitHub Action with `--format sarif` so findings land in code scanning ([docs/action.md](../action.md)). A pre-commit hook checks the lockfiles a commit changes.
- **Nobody has said a package is bad, but someone says they registered your internal name:** [claimcheck.md](claimcheck.md).
- **Ask from your agent.** `br mcp` lets an AI agent call `hunt`, `status` and `claimcheck` read-only ([docs/mcp.md](../mcp.md)). It must pass the gaps on; it cannot scan, write or notify.

## Reading the output

- **FOUND** means br saw the exact package and version in a place it indexed. A name is matched whole: `lodash` never matches `lodash.merge`.
- **POSSIBLE** means there is evidence but br cannot confirm it. Here: four people authored commits that took the bad version, and none of their laptops is scanned. These are not counted as found.
- **NOT CHECKED** lists each gap and the command that closes it. "11 of 12 members have no laptop scan here" is a real hole: br cannot see a laptop nobody exported.
- **Exit 10** is found. Use it in scripts. Exit 3 is "clear, but with gaps" under `--strict`.

## What br does not tell you

- It does not say the bad code ran. The advisory says a postinstall script runs on install; br shows where the package was installed and which secret names the CI job could read. Whether a secret was taken is a different question.
- It reads an index, not live systems. The data is as old as the oldest source. `--now` re-reads before it answers, on your own org.
- The default tables are wide; the images table runs past 200 columns. Testers found that hard to read. `--format summary` is the short version, and `--format md` gives tables you can paste into a ticket.
