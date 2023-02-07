# syntax=docker/dockerfile:1
FROM debian:9

RUN export DEBIAN_FRONTEND=noninteractive ; apt update && apt install -y make     curl   wget    git    coreutils    autoconf    libtool    pkg-config    libsodium-dev     nano    vim
RUN mkdir -p /workspace2/build/ ; cd /workspace2/build/ ; rm -Rf ./c-toxcore/
RUN git clone https://github.com/zoff99/c-toxcore
RUN cd c-toxcore/ && \
export _INST_="/workspace2/build/inst_ct" && \
export CFLAGS=" -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_INFO -D_GNU_SOURCE -g -O2 -I$_INST_/include/ -fPIC -Wall -Wextra -fstack-protector-all -Wno-unused-function -fno-omit-frame-pointer -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable " && \
export LDFLAGS=" -O2 -L$_INST_/lib -fPIC " && \
./autogen.sh && \
./configure \
  --prefix=$_INST_ \
  --disable-soname-versions --disable-testing --enable-logging --disable-shared && \
make clean && \
make -j $(nproc) && \
make install
RUN export DEBIAN_FRONTEND=noninteractive ; apt install -y libcurl4-gnutls-dev
