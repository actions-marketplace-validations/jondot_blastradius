# A static br image. Build:   docker build -t blastradius .
# Run:                        docker run --rm blastradius demo
#                             docker run --rm -v "$PWD:/work" -w /work blastradius hunt npm:name@1.2.3 --path . --fail-if found
#
# The final image holds the br binary and an empty /tmp. br carries its own TLS root certificates (rustls with webpki-roots). There is no shell, no git, no ssh and no gh:
# hunts over a mounted checkout (--path) and `br demo` work; scanning ssh hosts or using a `gh` login does not.
# To scan a GitHub org, pass a token:  docker run --rm -e GITHUB_TOKEN -v br-home:/data blastradius init --org ORG
# For a release build, pin the builder image by digest.

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --locked \
 && strip target/release/br \
 && mkdir -p /out/tmp /out/data \
 && chmod 1777 /out/tmp \
 && chown 65532:65532 /out/data \
 && cp target/release/br /out/br

FROM scratch
COPY --from=build /out/br /br
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/tmp /tmp
ENV BR_HOME=/data \
    TMPDIR=/tmp \
    NO_COLOR=1
USER 65532:65532
VOLUME ["/data"]
ENTRYPOINT ["/br"]
CMD ["--help"]
