# IR consultant

## The incident

A client's EDR flagged a file, or an advisory names a package. You have a read-only GitHub token and perhaps one laptop on the table. You bill by the day, you work from your own machine, and nothing may phone home. Within about an hour you want to know every place the package landed, a sealed record to hand to counsel, and a clear list of what you could not see.

## Commands

**1. One index per client.** Keep each client's index, notes and custody log in their own directory.

```sh
br --home ~/clients/acme init --org acme       # a read-only token is enough; also reads registries you are logged into
br --home ~/clients/acme hunt --advisory GHSA-q7vr-4xhc-m2jw
```

`--home DIR` is the same as `BR_HOME=DIR`. `init` says what it read and what it could not, for example a runner it saw but has no way into.

**2. See who is not covered.** Before you write anything down, list the machines.

```
$ br demo hosts
hosts: 4 indexed (2 runners, 2 laptops); acme has 12 members visible to this token in GitHub, 11 with no laptop scan here
...
NO LAPTOP SCAN HERE (11 of 12 members)
...
to add one: on their laptop run  br scan --local --export NAME.brx --seal ; here run  br import NAME.brx --owner @login
[exit 0]
```

A laptop with no network path to the index scans itself and exports a sealed `.brx`. Nothing leaves the machine except that file.

**3. Scan the laptop on the table.** On your own org:

```sh
br scan --local --export laptop-mira.brx --seal --case ACME-2026-07
br --home ~/clients/acme import laptop-mira.brx --requested-by "Yusuf Haddad" --case ACME-2026-07
```

`--local` reads the home directory and the package and tool caches br knows. `--local --path /` reads the whole disk. It hashes the files that match its filter; `br status --config` shows the filter.

**4. See how much of the answer is machines.**

```
$ br demo hunt --advisory GHSA-q7vr-4xhc-m2jw --only hosts
FOUND  3 indicators (GHSA-q7vr-4xhc-m2jw)
2 hosts to clean.
...
  ci-runner-04 possible: run acme/dashboard#7701 on ci-runner-04 resolved the affected package on 05-11 15:38; host last indexed 05-11 01:00
...
[exit 10]
```

**5. Write the record and sign it.** On your own org:

```sh
br --home ~/clients/acme evidence --advisory GHSA-q7vr-4xhc-m2jw --out evidence.json --case ACME-2026-07 --sign ~/.ssh/id_ed25519
br verify evidence.json --allowed-signers signers
```

`signers` has one line per signer, from the signer's `.pub` file: `NAME ssh-ed25519 AAAA...`. The seal covers `evidence.json` and its `.md` files; the signature says who made them.

## Reading the output

- **FOUND on a host** says the package or file was seen on that machine. **possible** says there is evidence, such as a CI run that used the runner, but the scan is older than the run.
- Every row has a first and last time seen, so you can say when it arrived and whether it was still there at the last look.
- An image row says whether the file is in the final image or in a layer that a later layer deleted. A deleted layer can still be downloaded by digest.
- The custody log inside the index records who ran what and when. `evidence` includes it.

## What br does not tell you

- It is not an EDR. It does not watch processes or network traffic, and it does not tell you whether a file ran.
- It finds the bytes you name (by package version or sha256), and files that look similar with `--similar`. A changed or repacked file with a new hash is found only by similarity.
- A laptop scan is as complete as the paths it was given. A sealed export proves the file was not edited after export. It does not prove the laptop was not tampered with before.
- If a machine was already compromised, what it reports is only as good as that machine.
