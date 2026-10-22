# Team lead

## The incident

Someone from security pinged you: your repos are affected. Standup is in 15 minutes. You do not need the vocabulary. For each of your repos you want the file, the line, the from and to version and the command, then what else needs a rebuild, and one command that says you are done.

## Commands

**1. See only your part.** `--owner` takes a team (`frontend`) or a login (`dana`).

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --owner frontend
FOUND  2 of 3 indicators (GHSA-q7vr-4xhc-m2jw)
In 3 repos owned by 2 teams; ran in 4 CI runs that could read 4 secret names, 5 secrets; 2 images and 1 cache to clean.
...
2 other repos of yours are clear
...
[exit 10]
```

The second line is your standup answer: 3 repos, 4 CI runs, 2 images and 1 cache. The line "2 other repos of yours are clear" does not name them. `br teams frontend` shows what the team owns.

**2. Get the fix for one repo.**

```
$ br demo fix --advisory GHSA-q7vr-4xhc-m2jw --repo acme/web
acme/web  (owner @acme/frontend)
  in a checkout of acme/web, start a branch (the default branch is usually protected):  git switch -c br/fix-ghsa-q7vr-4xhc-m2jw
  package.json line 23  @tanstack/react-router 1.120.3 -> 1.120.4
...
[exit 0]
```

Each repo gets a branch name, the line to change, the commands for its package manager, and the commit message. When a bump does not move a dependency, br says so and gives the override to add. Here `@tanstack/router-core` stays at 1.120.3 unless you pin it. In the demo, br cannot reach the npm registry, so it says "could not check" and keeps the override. On a real org it checks.

**3. After you merge, check one repo.** Run this on your own org. It needs the network, so `br demo` cannot run it:

```sh
br scan --repo acme/web && br hunt --advisory GHSA-q7vr-4xhc-m2jw --repo acme/web --now --only repos --fail-if found
```

Exit 0 means the repo no longer holds the version. If your fix is not merged yet, check a local clone instead. It needs no index and no network:

```sh
br hunt npm:@tanstack/react-router@1.120.3 --path . --fail-if found
```

**4. Send the secrets list to whoever rotates.**

```
$ br demo notify --advisory GHSA-q7vr-4xhc-m2jw --format slack
...
To #team-frontend (@acme/frontend, lead Dana Okafor)
...
```

The draft for your team lists each CI run that could read a secret. It names org-level secrets too, and says who owns them.

## Reading the output

- **Owner** comes from CODEOWNERS and from GitHub teams. When they disagree, br suggests an owner and says why. For `acme/legacy-admin` it suggests `@dokafor` because she archived it, and notes that CODEOWNERS names a team GitHub does not resolve.
- **direct** and **via A > B** tell you whether you can bump the package yourself. A transitive hit needs an override, and the plan says which one.
- A repo marked **removed** or **archived** is still listed. An archived repo has to be unarchived before a fix can be pushed.
- A laptop under **POSSIBLE** is evidence, not a finding. It means a person on your team committed the bad version and nobody has scanned their machine.

## What br does not tell you

- It does not know your team's channel unless you set it: `br teams set @acme/web --slack '#web'`.
- "Rotate" has no command. Where a secret is rotated depends on the service.
- Your own laptop is not in the answer unless it was scanned. Run `br scan --local` on it.
