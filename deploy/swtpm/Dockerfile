# Development-only software TPM for Attest integration tests.
# A swtpm instance is NOT a hardware root of trust: its EK is issued by a
# throwaway local CA generated inside this container. See
# docs/platform-limitations.md.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends swtpm swtpm-tools \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
EXPOSE 2321 2322
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
