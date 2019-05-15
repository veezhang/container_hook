ARG TAG=latest
FROM ubuntu:${TAG} AS builder
LABEL MAINTAINER "Vee Zhang <veezhang@126.com>"

RUN apt-get update && apt-get install -y gcc make

WORKDIR /src

COPY . .

RUN make

FROM ubuntu:${TAG}
LABEL maintainer "Vee Zhang <veezhang@126.com>"

COPY --from=builder /src/container_hook.so /usr/lib/container_hook.so
COPY --from=builder /src/container_hook_test /usr/bin/container_hook_test