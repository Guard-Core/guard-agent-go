# Build context is the repository root:
#   docker build -f examples/demo_app/Dockerfile .
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY examples/demo_app/ examples/demo_app/

RUN CGO_ENABLED=0 go build -trimpath -o /out/guard-agent-demo ./examples/demo_app

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && \
    addgroup -S guard && adduser -S -G guard guard

COPY --from=build /out/guard-agent-demo /usr/local/bin/guard-agent-demo

LABEL org.opencontainers.image.title="guard-agent-go demo" \
    org.opencontainers.image.description="Containerized Guard Agent demo: a small Go service streaming security telemetry to a Guard Core ingestion endpoint" \
    org.opencontainers.image.source="https://github.com/Guard-Core/guard-agent-go" \
    org.opencontainers.image.licenses="MIT"

ENV GUARD_AGENT_ENDPOINT=https://api.guard-core.com \
    GUARD_AGENT_PROJECT_ID=demo-project \
    PORT=8080

USER guard

EXPOSE 8080

ENTRYPOINT ["guard-agent-demo"]
