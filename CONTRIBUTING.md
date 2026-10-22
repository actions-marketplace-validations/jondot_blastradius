# Contributing

Bug reports with the command you ran and the output you got are the most useful thing you can send. If br said something was clear and it was not, or a count disagreed between two commands, say so: those are the bugs that matter most.

Pull requests are welcome. Before you open one:

    cargo fmt
    cargo clippy --all-targets -- -D warnings
    cargo test

New behaviour needs a test. br has three hard rules, and a change that breaks one will not be merged:
1. Read-only. No call that writes to GitHub, a registry or a host.
2. Never a silent clear. Anything br could not check is listed as a gap.
3. Nothing tuned to one org. Rules come from file formats, ecosystems and APIs, not from example data.
