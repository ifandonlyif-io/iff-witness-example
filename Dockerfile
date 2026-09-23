# Build from repository root: docker build -f Dockerfile .
FROM node:22-alpine AS browser
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY client ./client
COPY scripts/build.mjs scripts/check-apostille-source.mjs ./scripts/
COPY examples/agentic-demo-bundle.json ./examples/agentic-demo-bundle.json
COPY web/service-receipt.mjs ./web/service-receipt.mjs
RUN npm run build

FROM golang:1.26.6-alpine AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=browser /src/web/app.js /src/web/settings.js /src/web/apostille-demo.js ./web/
RUN CGO_ENABLED=0 go build -trimpath -o /witness ./cmd/witness

FROM alpine:3.24.1
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 witness
WORKDIR /app
COPY --from=build /witness /app/witness
COPY examples/iff-fixture.json /app/examples/iff-fixture.json
USER witness
ENV WITNESS_LISTEN_ADDR=0.0.0.0:8094
ENV WITNESS_EXAMPLE_FILE=/app/examples/iff-fixture.json
EXPOSE 8094
ENTRYPOINT ["/app/witness"]
