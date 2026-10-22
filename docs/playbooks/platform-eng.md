# Platform / DevOps

## The incident

AppSec has named `GHSA-q7vr-4xhc-m2jw`. You own the self-hosted runners, the Actions caches, the container images and the build hosts. You want exact commands: which caches and artifacts to delete, which runners to clean, which images to rebuild and in what order. You also want a gate that fails a pipeline if the bad version comes back.

## Commands

**1. See which runner ran what, and which caches and images hold it.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --only caches
FOUND  2 of 3 indicators (GHSA-q7vr-4xhc-m2jw)
2 caches to clean.
...
  REPO            KEY               CREATED      LAST USED    SIZE    INDICATORS
  acme/dashboard  pnpm-linux-a41c   05-11 15:40  05-12 06:10  340 MB  npm:@tanstack/react-router@1.120.3, npm:@tanstack/router-core@1.120.3
  acme/web        npm-linux-9f3a1c  05-11 15:12  05-12 06:50  212 MB  npm:@tanstack/react-router@1.120.3, npm:@tanstack/router-core@1.120.3
...
[exit 10]
```

`--only` takes `repos`, `ci`, `caches`, `artifacts`, `images`, `hosts` and `releases`. The output says how much of the whole answer it hides: "`--only caches` shows 4 of the whole answer's 45 findings".

**2. Get the purge plan.**

```
$ br demo purge --advisory GHSA-q7vr-4xhc-m2jw
Each deletion below is preceded by a '# preserve first:' line: run it, keep the hash, then delete.
...
ACTIONS CACHES, AFTER THE MERGE (a run on the unfixed code would save them again)
...
  gh cache delete pnpm-linux-a41c -R acme/dashboard
...
ARTIFACTS
...
  gh api -X DELETE repos/acme/marketing-site/actions/artifacts/88120031
...
IMAGES TO REBUILD
  fix the source repos first: acme/embed-widget, acme/web; then rebuild
  rebuild order: no dependency between these images; any order
...
[exit 0]
```

Run `br purge --advisory ID --commands > purge.sh` to get a script. It has two parts. Part 1 can run now. Part 2 runs after the fixes are merged, because a CI run on the old code would put the bad version back into a cache or an image. Each step has a guard that runs `br hunt` for its own repo first. br never runs any of it.

**3. Read the runner lines.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --only hosts
...
  ci-runner-04 possible: run acme/dashboard#7701 on ci-runner-04 resolved the affected package on 05-11 15:38; host last indexed 05-11 01:00
...
  ci-runner-03  runner  /home/runner/.npm/_cacache  05-11 15:31  05-12 02:00  present  @acme/platform  the install ran here (CI run acme/status-page#4112)  npm:@tanstack/react-router@1.120.3, npm:@tanstack/router-core@1.120.3
...
...
[exit 10]
```

`ci-runner-03` is a finding: the install ran there. `ci-runner-04` is only possible, because its last scan is older than the run. Scan it (`br scan --host ci-runner-04`) before you decide.

**4. Put a gate in CI.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --repo acme/web --fail-if found --quiet
FOUND  2 of 3 indicators (GHSA-q7vr-4xhc-m2jw)  10 findings in 3 places and 2 CI runs (present now: 1 repo, 1 image and 1 cache)  1 possible  index 05-12 06:30Z
[exit 10]
```

Exit 10 fails the job. In a pipeline on your own org, the checkout gate needs no index and no network:

```sh
br hunt npm:@tanstack/react-router@1.120.3 --path . --fail-if found --strict
```

`--strict` also fails (exit 3) when br could not read a lockfile under the path. If both apply, found wins and you get 10.

## Beyond this advisory

- **In the pipeline.** The GitHub Action, `--format sarif` and the pre-commit hook run the checkout gate with no index and no token ([docs/action.md](../action.md)). `br claimcheck --path . --fail-if exposed` adds a check on your own internal names ([claimcheck.md](claimcheck.md)); pinning each scope and index to your registry is the platform team's fix for what it finds.

## Reading the output

- "preserve first" lines save evidence before a delete: cache metadata, the artifact zip, a tarball of a host cache. They are there so you can still answer the auditor afterwards.
- "wider than the finding" means the command removes more than the bad entry. `npm cache clean --force` empties the whole cache. It downloads again on the next install.
- A runner where a CI job installed the package is treated as possibly holding its secrets. br says to isolate it, keep a copy of the cache, rotate what the user could read, and reimage. Clearing the cache is not enough.
- An image can hold the file in a deleted layer. The old digest stays downloadable until it is deleted, so the plan is rebuild first, then delete the old digest.

## What br does not tell you

- It does not read container layer caches on a runner host.
- A host scan hashes only the files that match its filter (`br status --config` shows it). An odd filename in an odd place can be missed.
- It does not run anything. You review `purge.sh` before you run it.
