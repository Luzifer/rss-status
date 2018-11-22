FROM golang:alpine as builder

COPY . /go/src/github.com/Luzifer/rss-status
WORKDIR /go/src/github.com/Luzifer/rss-status

RUN set -ex \
 && apk add --update git \
 && go install -ldflags "-X main.version=$(git describe --tags || git rev-parse --short HEAD || echo dev)"

FROM alpine:latest

LABEL maintainer "Knut Ahlers <knut@ahlers.me>"

RUN set -ex \
 && apk --no-cache add ca-certificates

COPY --from=builder /go/bin/rss-status /usr/local/bin/rss-status

EXPOSE 3000
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/rss-status"]
CMD ["--"]

# vim: set ft=Dockerfile:
