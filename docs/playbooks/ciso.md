# CISO

## The incident

An advisory is in the news. By noon the CEO wants a yes or no and a number, said in one sentence. Customer success wants a text they can send to customers who ask "were you affected?". You have been burned by a number that was wrong by three o'clock, so you want to know how sure the number is and what would change it.

## Commands

**1. The sentence for the CEO.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --format summary
Yes. 7 repos, 2 images, 2 machines, 2 caches and 2 build artifacts contain or contained the affected packages (GHSA-q7vr-4xhc-m2jw).
4 people and 2 machines may also be affected but could not be confirmed.
Still present: 5 repos, 2 images, 2 machines, 2 caches and 2 build artifacts.
...
Data as of 05-08 10:00Z–05-12 06:30Z (oldest: laptop-priya). Not checked: 4 sources (acme/mobile-web; ci-runner-04; laptop-priya; laptops: 11 of 12 members visible to this token in GitHub have no laptop scan here). The number can still change.
[exit 10]
```

Say the first line. Then say the last one. The count of confirmed places, the count of possible ones, and the list of what was not checked are three different things, and the summary keeps them apart.

**2. How much of the company did the answer cover?**

```
$ br demo status
45 sources: 42 fresh, 3 stale (threshold 24h)
hosts: 4 indexed (2 runners, 2 laptops); acme has 12 members visible to this token in GitHub, 11 with no laptop scan here: run br hosts to list them
...
[exit 0]
```

This is the coverage line. In the sample org, 1 of 12 people has a current laptop scan in the index. Any laptop-borne exposure for the other 11 is unknown, not absent.

**3. The text for customers.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --format summary --audience customers
Yes. Some of our internal systems contained or ran the affected packages (GHSA-q7vr-4xhc-m2jw), starting on 2026-05-11.
Recommended next steps are to remove them and to rotate any credentials that those systems could read.
We have not established whether any customer data was involved.
Our findings are as of 2026-05-12 06:30 UTC (the oldest source was checked at 2026-05-08 10:00 UTC). Some systems have not been fully checked yet, so this statement can still change.
[exit 10]
```

No repo, team or person is named. The statement says it can still change, and it says it does not know whether customer data was involved. For a sealed version with a case number, see [auditor.md](auditor.md).

**4. Track the cleanup.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --progress
GHSA-q7vr-4xhc-m2jw: 22 open, 0 fixed, 0 new since no earlier baseline (this is the first --progress for this scope: it is now the baseline)
...
[exit 10]
```

The first `--progress` on your own org sets the baseline. Later runs show, per owner, what is still open, what was fixed and when, and what is new. In the demo the baseline is thrown away when the command ends.

## Beyond this advisory

- **"Are we exposed to dependency confusion?"** `br claimcheck --format summary` gives one verdict word, the count behind it and what was not checked; `--format md` pastes into a risk register. It says "owner not shown" where a registry does not say. The total is in the first line, every gap is counted in names, a result that rests only on a publisher's own claim is never a bare CLEAR, and `br evidence --claimcheck` seals the answer for a customer. See [claimcheck.md](claimcheck.md); `br demo claimcheck` runs it on a sample.
- **A standing gate.** The GitHub Action and SARIF output ([docs/action.md](../action.md)) put the same checks in the pipeline your teams already use.

## Reading the output

- "9 secret names, 11 secrets" can both be right. The same name, such as `NPM_TOKEN`, can be stored separately in several repos. Each copy is a credential to rotate. The hunt output says which. Say "11 credentials", not "9", if you mean the work to be done.
- **POSSIBLE** is not counted in the headline. It is shown so that you do not hear about it first from someone else.
- When a re-scan changes the number, the summary says what changed and where.

## What br does not tell you

- It cannot say that nothing happened. It says what it found in what it could read, and what it could not read.
- It does not know about machines nobody scanned, SaaS tools that are not GitHub or a registry, or developers' personal accounts.
- "Not established" in the customer text is a statement about br's coverage, not a finding that no customer data was touched. A person has to answer that.
