# Startup CTO

## The incident

Fifteen engineers, no security team, six repos. Your MDR vendor sent you a package name and a hash, and you have fifteen minutes before your next meeting. You have a GitHub token in your shell. You want "yes, here, here and here", or "no, and here is what I could not check", and then a message you can paste into the team channel. If setup takes more than two commands, you will not do it.

## Commands

**0. See what it does first, with no token.**

```sh
br demo
```

It prints a six-step tour and touches nothing of yours.

**1. Install and index.** Two commands.

```sh
curl -fsSL https://raw.githubusercontent.com/jondot/blastradius/main/install.sh | sh
br init --org initech
```

A read-only token is enough. `init` reads the repos, CI runs, caches and images the token can see. It also reads container registries you are logged into with `docker login`, and says so. It lists self-hosted runners it can see but cannot read, with the command to add them. In testing, a 6-repo org took about 8 seconds.

**2. Ask.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --format summary
Yes. 7 repos, 2 images, 2 machines, 2 caches and 2 build artifacts contain or contained the affected packages (GHSA-q7vr-4xhc-m2jw).
...
Data as of 05-08 10:00Z–05-12 06:30Z (oldest: laptop-priya). Not checked: 4 sources (acme/mobile-web; ci-runner-04; laptop-priya; laptops: 11 of 12 members visible to this token in GitHub have no laptop scan here). The number can still change.
[exit 10]
```

`--format summary` is the screen to read first. The default table is long and wide. Use it when you need the rows.

**3. Get the message for the channel.**

```
$ br demo notify --advisory GHSA-q7vr-4xhc-m2jw --format slack
...
To #team-frontend (@acme/frontend, lead Dana Okafor)
...
```

Each team gets a short post: what to change, which runs could read which secrets, what to rebuild. Set channels once with `br teams set @org/team --slack '#channel'`.

**4. Fix it.**

```
$ br demo fix --advisory GHSA-q7vr-4xhc-m2jw --repo acme/web
acme/web  (owner @acme/frontend)
...
  package.json line 23  @tanstack/react-router 1.120.3 -> 1.120.4
...
[exit 0]
```

## Beyond this advisory

- **Make it automatic.** The GitHub Action ([docs/action.md](../action.md)) fails a build that holds a listed package, with no token for the checkout gate. `br claimcheck --path .` tells you whether anyone could register one of your internal package names ([claimcheck.md](claimcheck.md)).
- **Ask your assistant.** `br mcp` serves the read-only commands to an AI agent ([docs/mcp.md](../mcp.md)).

## Reading the output

- "Yes" with a list means the package is, or was, in those places. It does not mean anything was stolen.
- "Not checked" is the part to act on if you have time. For a laptop the answer is `br scan --local --export NAME.brx --seal` on that laptop, then `br import NAME.brx` on yours.
- `--fail-if found` makes a CI step fail when the bad version appears. In a repo, `br hunt npm:name@1.2.3 --path . --fail-if found --strict` needs no index and no token.

## What br does not tell you

- It does not know your SaaS tools, your cloud accounts or machines nobody scanned.
- It does not rotate anything. It lists the secret names to rotate and who owns them.
- The answer includes packages that were in a lockfile during the exposure window and have since been removed. Those rows are marked removed, with the date.
