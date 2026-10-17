FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY . .

# Pure Go and vendored: no C toolchain or network access needed.
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath \
	-ldflags "-s -w \
	  -X github.com/genuinetools/amicontained/version.VERSION=$(cat VERSION.txt) \
	  -X github.com/genuinetools/amicontained/version.GITCOMMIT=docker" \
	-o /amicontained .

# The binary is static and re-executes itself via /proc/self/exe, so it
# needs nothing from a base image.
FROM scratch

COPY --from=builder /amicontained /amicontained

ENTRYPOINT ["/amicontained"]
