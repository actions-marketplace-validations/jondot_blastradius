# Dependency confusion: `br claimcheck`

A different incident from the other playbooks. Nothing is known to be bad yet. A researcher, a bug-bounty report or a blog post says "someone registered your internal package name", and the question is which of your own names a stranger could already own. For the role pages, see [the index](README.md); this page is for the on-call AppSec engineer and the CISO.

**Where the output on this page comes from.** `br demo claimcheck` runs on a small sample built into the binary: three repos of the demo org with a few manifests and registry settings, and a snapshot of what the public registries would say about their names. It is a **sample registry**: nothing is asked over the network, and every line that states a registry fact says "sample registry". The clock is pinned at 2026-05-12T07:10:00Z. On your own org the commands are the same and the registries are the real ones. The blocks that start with `$ br demo` are run against the binary in CI.

## The incident

It is 08:00. Jun Park (on-call AppSec) has 20 minutes to say which internal names are open to a stranger, and the answer must separate "someone already owns this name" from "nobody does yet, and only the right people could publish it".

## What br reads, and what it asks

From your index's repos (through the GitHub API) or a checkout (`--path DIR`), br reads manifests (package.json, pyproject and setup files, Cargo.toml, go.mod), the settings that map a scope or an index to a private registry (`.npmrc`, `.yarnrc.yml`, pip.conf, `--index-url` and `--extra-index-url`, poetry and uv sources, `.cargo/config.toml`), lockfiles, `bin` command names and the package names in shipped source maps. Each name keeps the file where it was seen, and the team that owns that repo (the same owner lookup the hunt uses). It then asks the public registry of the name's ecosystem about each name, once, with read-only GETs, and only when you run `br claimcheck`. A hunt never makes these calls. br publishes, claims and changes nothing, and writes nothing unless you pass `--record`.

A checkout that sets a private registry but has no lockfile cannot say which of its dependencies resolve privately. br asks about all of them, lists the ones no public registry has, and counts the ones a public registry also has under NOT CHECKED, with that reason. It never skips them silently.

## Commands

**1. Ask.** One line carries the verdict and every count, in names.

```
$ br demo claimcheck
CLAIMCHECK  clock 2026-05-12T07:10:00Z (sample registry)
EXPOSED: 7 names (3 squatted, 3 free, 1 scope held by someone else); 2 shown to be yours (1 verified by the registry, 1 declared by the publisher)
no index: the manifests and the registry answers are the sample inside this binary
MOST URGENT:
  acme-billing-core (a stranger published 9999.0.0, and it runs code when installed)
  acme-data-svc (99.0 was published by an owner the registry does not show, and it runs code when installed)
  @acme (the scope @acme is held by someone else (tom-t), so they can publish any name under it)
...
SQUATTED: a public package has a name you use, and nothing shows it is yours (3)
  npm  acme-billing-core
      what it means: a stranger published 9999.0.0, and it runs code when installed
      public (sample registry): 9999.0.0, published 2026-05-02 (newest version), name first claimed 2025-01-01, install script: yes, publisher: mallory-x
      FLAG higher_version: public version 9999.0.0 is above the highest you use (1.4.2)
      highest version you use: 1.4.2
      why listed: own package
      seen: acme/billing-portal: package.json
      owner: @acme/billing
      not pinned in: acme/billing-portal
...
SCOPE UNCLAIMED: an npm scope you use that the public registry does not show as yours (1)
  npm scope  @acme
      what it means: the scope @acme is held by someone else (tom-t), so they can publish any name under it
      public packages under it (sample registry): @acme/legacy
...
FREE: no public package has this name; each name says who could publish it (3)
  npm  @acme/ui
      what it means: only the scope's holder (tom-t) could publish it, because @acme is held by someone else
...
  pypi  acme-etl
      what it means: no public package has this name, so anyone could publish it
...
OURS: public, and shown to be yours (2)
  npm  acme-ledger  [declared by the publisher]  (the package's repository URL points at github.com/acme (declared by the publisher, not verified by the registry))  owner: @acme/billing
  cargo  acme-core  [verified by the registry]  (the registry lists the org's GitHub team github:acme:platform as an owner)  owner: @acme/growth
...
[exit 0]
```

The classes, each with its own meaning:

- **SQUATTED**: the public registry has a package with a name you use, and nothing shows it is yours. br prints its highest version, the date of that newest version, when the name was first claimed (the earliest publish time the registry gives, so a name squatted last year reads "name first claimed 2025-01-01" next to the newest version's date), whether it runs a script at install, and the publisher if the registry says. `owner not shown` means the registry did not say; br then does not say "a stranger" either: it says the version "was published by an owner the registry does not show".
- **What to do depends on the class.** A squatted name cannot be claimed or covered with a placeholder: WHAT TO DO says pin the registry (or the scope) or rename it, report the package to its registry, and gives the `br hunt npm:NAME@THEIRVERSION` that shows whether anything installed their version. A free name can be claimed (publish a placeholder) or pinned. A scope someone else holds, and a free name under it, cannot be claimed: pin the scope to your registry, or rename the scope. `br notify --claimcheck` and `br evidence --claimcheck` use the same steps.
- **FREE**: no public package has the name. Who could publish it depends on the scope. A plain name: anyone. A name under an npm scope someone else holds: only the scope's holder (here tom-t), and the line says so. A name under a scope nobody is shown to hold: anyone could claim the scope first.
- **SCOPE UNCLAIMED**: an npm scope you use that the public registry does not show as yours. When public packages sit under it they are listed on the scope's row, and its holders are named. A held scope cannot be claimed, so the advice is to move your packages to a scope you own.
- **OURS**: public and shown to be yours, with the proof beside it and how strong it is. **Verified by the registry**: the registry lists your GitHub team, or a verified org member, as an owner. **Declared by the publisher**: the package's own metadata points at your GitHub, which anyone can type. A result that rests only on declared names is never a bare CLEAR: it reads "CLEAR, but N names are ours only by the publisher's word".

Exposed names are ordered by one rule, by what happens if nothing is done: an install script by a stranger, then a stranger's higher version, then a scope held by someone else, then a command name of yours that a stranger's package also installs, then a name a stranger already has, then free names. Each is said in plain words ("a stranger published 9999.0.0, and it runs code when installed"). The flags `higher_version`, `bin_match` and `scope_held` stay on the rows, and in JSON and SARIF, for tools.

**2. Read the part that is not an answer.** Every gap is counted in names, in every format. Names cut by `--max-names` are names not checked too, and they appear in the JSON `names[]` with that reason.

```
$ br demo claimcheck --max-names 2
CLAIMCHECK  clock 2026-05-12T07:10:00Z (sample registry)
...
NOT CHECKED:
  WHAT                          WHY                                                                                 TO CLOSE
  7 names beyond --max-names 2  not asked about: acme-ledger, acme-data-svc, acme-core, acme-proto, acme-bill, ...  raise --max-names
...
[exit 0]
```

A registry that was throttled or unreachable is a gap, never "free" and never "clear". After three rate-limited answers in a row br stops asking that registry and lists the rest. `--strict` exits 3 when there are gaps. Under `--fail-if exposed`, a run that checked nothing (for instance `--max-names 0`) exits 3 even without `--strict`: a gate that asked nothing is not a pass.

**3. The sentence for the channel, or the board.**

```
$ br demo claimcheck --format summary
Dependency-confusion check, 2026-05-12: EXPOSED: 7 names (3 squatted, 3 free, 1 scope held by someone else); 2 shown to be yours (1 verified by the registry, 1 declared by the publisher).
no index: the manifests and the registry answers are the sample inside this binary.
Most urgent: acme-billing-core (a stranger published 9999.0.0, and it runs code when installed); acme-data-svc (99.0 was published by an owner the registry does not show, and it runs code when installed); @acme (the scope @acme is held by someone else (tom-t), so they can publish any name under it).
The answers are from a sample registry, not a public one.
Limits: br read manifests, lockfiles, registry settings and source maps; it did not open images, caches or laptops, and a public registry does not show who really owns a name.
Nothing was published, claimed or changed.
[exit 0]
```

`--format md` pastes into a ticket or a risk register (with the owner column), and `--format slack` into a channel.

**4. A date, not only today.** `--as-of DATE` judges each public package by the versions published on or before that date, using the registry's own publish times. It rewinds the org's side where br has evidence: a CI artifact created after the date did not exist then, so it is set aside and the names seen only there are left out (the output counts them). Repos are read as they are today, because the index keeps no older state of a repo's files, and the output says so. The headline, in every format, names the as-of date first. A name whose every version came later was free that day. Where a registry gives no publish time (the Go proxy lists versions without dates), br says so on that name and counts the version as published. npm shows no dates for the packages under a scope, so scopes are as of today, and the output says that. The clock stays honest too: a public version published after the clock does not exist yet.

```
$ br demo claimcheck --as-of 2026-05-01 --format summary
Dependency-confusion check as of 2026-05-01 (run on 2026-05-12): EXPOSED: 7 names (2 squatted, 4 free, 1 scope held by someone else); 2 shown to be yours (1 verified by the registry, 1 declared by the publisher).
Judged as of 2026-05-01.
...
[exit 0]
```

**5. Tell the owning teams.** `br notify --claimcheck` drafts one message per team that owns an exposed name, with the WHAT TO DO steps for that team's names. A name seen in two teams' repos goes to both. `--format slack|md|jira|json`, `--owner`, `--out` work as in the incident notify.

```
$ br demo notify --claimcheck
To #team-billing (@acme/billing, lead Lena Fischer)
...
- acme-billing-core (npm): a stranger published 9999.0.0, and it runs code when installed [higher_version]. Seen in acme/billing-portal: package.json (sample registry)
...
To #team-data (@acme/data, lead Omar Idowu)
...
In all: 7 names for 3 teams; 0 names not checked.
[exit 0]
```

**6. Seal it for an auditor or a customer.** `br evidence --claimcheck --out FILE` writes the sealed JSON, a report, and with `--audience customers` a plain statement with no internal names. Its first sentence answers `--question`: "Yes: on 2026-05-12, 7 names that we use inside our own systems are exposed to dependency confusion on a public registry (...)", or "No: ...", or "Not that we found, but this is not a full answer: ...". The file carries the verdict, the counts, the proof behind each OURS, the names not checked and the limits. `br verify` checks the seal. This replaces asking `br evidence` about a package indicator, which answers a different question.

```
$ br demo evidence --claimcheck --out claim.json --audience customers --question "are you exposed to dependency confusion?"
EXPOSED: 7 names (3 squatted, 3 free, 1 scope held by someone else); 2 shown to be yours (1 verified by the registry, 1 declared by the publisher)
Yes: on 2026-05-12, 7 names that we use inside our own systems are exposed to dependency confusion on a public registry (3 already on a public registry and not shown to be ours; 3 not taken, so open to whoever can publish them; 1 under an npm scope that is not shown to be ours).
wrote claim.json
wrote claim.md
wrote claim.customers.md
wrote claim.json.sha256
sealed claim.json and claim.md and claim.customers.md together
the seal is an integrity check (the files are unchanged), not proof of who made them; add --sign KEY for that
[exit 0]
```

**7. What changed since last week.** By default br writes nothing. `br claimcheck --record` stores the run under `BR_HOME/claimcheck/`, and `br diff --claimcheck` runs the check again and compares it with the newest snapshot (`--since TIME` picks the one recorded at or before that time). It shows what is newly squatted, newly free, newly an unclaimed scope, now ours, newly not checked, changed, or no longer listed. The two runs are compared by the dates they describe (the clock, or the `--as-of` date): when the run is as of a date before the snapshot's, br says it is going back in time and lists differences between the two dates, never "newly". The `claimcheck` tool of `br mcp` never records.

```sh
br claimcheck --record                       # Monday: store a snapshot
br diff --claimcheck                         # next Monday: what became SQUATTED since
br diff --claimcheck --since 2026-06-01      # against the snapshot recorded on or before that date
```

The demo keeps nothing, so `br demo claimcheck --record` is refused.

**8. Put it in CI.**

```sh
br claimcheck --path ./my-repo --org acme --fail-if exposed --strict
```

Exit 10 when any name is FREE, SQUATTED or SCOPE UNCLAIMED. Exposure wins over gaps; `--strict` adds exit 3 for gaps. Without `--org`, nothing can be shown to be yours and br says so. A checkout is not in the index, so its names carry owner "unresolved".

**9. Send it to code scanning.**

```sh
br claimcheck --path . --org acme --format sarif --fail-if exposed > claims.sarif
```

SARIF 2.1.0 with a result on each file where an exposed name was seen, and the gaps as notifications. [docs/action.md](../action.md) has the workflow, and says why this is not an Action mode.

**10. Ask from an agent.** `br mcp` offers a `claimcheck` tool (`path`, `repo`, `org`, `max_names`, `as_of`), which makes the same read-only GETs and writes nothing: [docs/mcp.md](../mcp.md).

## What to do about it

br prints text under WHAT TO DO and never acts on it: pin the registry per scope or index (`@scope:registry=URL` in `.npmrc`; `--index-url`, not `--extra-index-url`, for pip; `registry = "NAME"` for cargo; `GOPRIVATE` for Go), claim a scope nobody holds, move packages out of a scope someone else holds, or publish a placeholder under the name. A person does it.

## What br does not tell you

- A public registry shows a name and its metadata, not who really owns it. A name is OURS only on the proof printed beside it, and a declared proof is weaker than a verified one.
- It does not open image layers, caches or laptops, so a name that shows up only there is not on the list.
- What your private registries serve, and how they proxy a public one, is not visible. A name pinned to a private registry is still listed.
- npm does not show whether a scope with no public package is registered; such a scope is listed as unclaimed.
- Names that only a source map or an extra index listed, and that a public registry has, are left out as most likely ordinary public dependencies. The output says how many.
