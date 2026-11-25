# The Pubky Dispatch service.
#
#   docker build -t pubky-dispatch .
#   docker run -e PUBKY_DISPATCH_DATABASE_URL=postgres://... \
#     -v dispatch-keys:/var/lib/pubky-dispatch/keys pubky-dispatch
#
# See docs/configuration.md.

FROM rust:1.91.1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pubky-dispatch \
    && cp target/release/pubky-dispatch /pubky-dispatch \
    && mkdir -p /state/keys

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /pubky-dispatch /usr/local/bin/pubky-dispatch
COPY docker/config.toml /etc/pubky-dispatch/config.toml
# The key store. Mount a volume here that database backups don't cover.
COPY --from=build --chown=65532:65532 /state /var/lib/pubky-dispatch
VOLUME ["/var/lib/pubky-dispatch/keys"]
ENV PUBKY_DISPATCH_CONFIG=/etc/pubky-dispatch/config.toml
# The API listener, once server.origin is set, and the operator listener: health and
# metrics.
EXPOSE 8080 9090
USER nonroot
ENTRYPOINT ["/usr/local/bin/pubky-dispatch"]
CMD ["run"]
