# One static arm64 musl binary, nothing else. Built by docker/build.sh (a throwaway
# rust:alpine container — no toolchain ever lands in this image). Used for every node
# in compose.yaml: honest peer, hostile peer, witness — only the command differs.
FROM scratch
COPY out/nas /nas
ENTRYPOINT ["/nas"]
