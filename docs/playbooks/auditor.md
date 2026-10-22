# Auditor / customer assurance

## The incident

An enterprise customer asked in writing: "Between 2026-05-01 and 2026-05-12, did any of your systems contain package X?" You are not an engineer. You can run a command someone gives you and read a table. You need a record that has the question, the period, what was scanned and when, what was not covered, the result and the limits. It has to stand up when an auditor reads it, and you need a text to attach to the reply.

## Commands

**1. Write the evidence file.** Ask an engineer for the case number, or use your own.

```
$ br demo evidence --advisory GHSA-q7vr-4xhc-m2jw --out evidence.json --audience customers --case INC-42
FOUND  npm:@tanstack/react-router@1.120.3, npm:@tanstack/router-core@1.120.3, npm:@tanstack/start-client@1.120.3  window 05-11 14:00Z..18:00Z
3 stale + 1 laptop gap = 4 gaps; the file lists them under PARTIAL COVERAGE and NOT COVERED
wrote evidence.json
wrote evidence.md
wrote evidence.customers.md
wrote evidence.json.sha256
sealed evidence.json and evidence.md and evidence.customers.md together
the seal is an integrity check (the files are unchanged), not proof of who made them; add --sign KEY for that
[exit 0]
```

`evidence.json` is the record. `evidence.md` is the same record for a person to read. `evidence.customers.md` is the statement for the customer, with no internal names. Exit 0 means the file was written. The finding is inside the file, so the exit code is not 10.

**2. Check the seal.** Anyone who holds the files can do this. Run it in the same directory, after step 1:

```
# br demo verify evidence.json
OK: evidence.json unmodified (sha256 <first 16 hex digits>...; sealed (unsigned): the sha256 seal is integrity only, it detects edits but does not say who made the file; anyone with the files can re-seal; use --sign for a signature; covers evidence.json, evidence.md, evidence.customers.md)
```

The checksum is that of the file's contents, so yours will differ from any quoted here.

**3. Read the customer statement.**

```
# Statement for customers

Yes. Some of our internal systems contained or ran @tanstack/react-router 1.120.3 (npm), @tanstack/router-core 1.120.3 (npm), @tanstack/start-client 1.120.3 (npm), starting on 2026-05-11.
We have not established whether any customer data was involved.
```

This is an excerpt of `evidence.customers.md`. The rest of the file gives the period examined, how many systems were checked and how many were not, and the case number and checksum.

## Reading the output

The `.md` file has fixed sections: **QUESTION** (what was asked, the period, where the window came from), **RESULT** (the verdict and how fresh the data is), **POPULATION** (what the index holds and what it does not), **METHOD** (how each source type was read), **FINDINGS**, and the gaps.

- **Verdict** is FOUND, CLEAR or CLEAR WITH GAPS. CLEAR WITH GAPS is a real answer: nothing was found, and here is what was not looked at.
- **Population** is the number auditors ask for: 40 repos, 1 registry and 4 hosts, and "1 of 12 members checked" for laptops.
- The seal covers every file written. If someone edits one, `br verify` fails.
- `--sign KEY` signs with `ssh-keygen -Y sign`. `br verify FILE --allowed-signers FILE` then checks who signed.

## What br does not tell you

- The seal says the files were not changed. Without `--sign` it does not say who made them. Anyone who has the files can seal new ones.
- The record is about the indexed sources. Anything outside them is not in it, and the POPULATION section says so.
- br does not say whether customer data was involved. The statement says that it has not established this.
