# Security

`br` is read-only by design: it makes GET and HEAD calls to GitHub, your registries and (for `br claimcheck`) the public package registries, and it never writes to them. If you find a way to make it write, leak a secret value, or report a place as clear when it is not, that is a security bug.

Report it privately through GitHub's "Report a vulnerability" button on this repository (Security tab). Please do not open a public issue. We aim to reply within three working days.
