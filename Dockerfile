# syntax=docker/dockerfile:1
FROM debian:9

RUN export DEBIAN_FRONTEND=noninteractive ; apt update && apt install -y make     curl   wget    git    coreutils    autoconf    libtool    pkg-config    libsodium-dev     nano    vim
