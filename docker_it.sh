#! /bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

echo $_HOME_
cd $_HOME_


if [ "$1""x" == "buildx" ]; then
    docker build -t toxcore_ready_deb9_003 .
    exit 0
fi

build_for='
debian:9
'

for system_to_build_for in $build_for ; do

    system_to_build_for_orig="$system_to_build_for"
    system_to_build_for=$(echo "$system_to_build_for_orig" 2>/dev/null|tr ':' '_' 2>/dev/null)

    cd $_HOME_/
    mkdir -p $_HOME_/"$system_to_build_for"/

    mkdir -p $_HOME_/"$system_to_build_for"/artefacts
    mkdir -p $_HOME_/"$system_to_build_for"/script
    mkdir -p $_HOME_/"$system_to_build_for"/workspace/build/

    ls -al $_HOME_/"$system_to_build_for"/

    rsync -a ./pubjoin_group_ngc_test.c --exclude=.localrun $_HOME_/"$system_to_build_for"/workspace/build/
    chmod a+rwx -R $_HOME_/"$system_to_build_for"/workspace/build >/dev/null 2>/dev/null

    echo '#! /bin/bash

export DEBIAN_FRONTEND=noninteractive


os_release=$(cat /etc/os-release 2>/dev/null|grep "PRETTY_NAME=" 2>/dev/null|cut -d"=" -f2)
echo "# using /etc/os-release"
system__=$(cat /etc/os-release 2>/dev/null|grep "^NAME=" 2>/dev/null|cut -d"=" -f2|tr -d "\""|sed -e "s#\s##g")
version__=$(cat /etc/os-release 2>/dev/null|grep "^VERSION_ID=" 2>/dev/null|cut -d"=" -f2|tr -d "\""|sed -e "s#\s##g")

echo "# compiling on: $system__ $version__"

#------------------------

cd /workspace/build/
mkdir -p /workspace/build/inst_ct

rm -Rf ./c-toxcore/
git clone https://github.com/zoff99/c-toxcore
cd c-toxcore/

# git checkout "zoff99/zoxcore_local_fork"

echo "*** toxcore ***"

export _INST_="/workspace/build/inst_ct"

export CFLAGS=" -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_INFO -D_GNU_SOURCE -g -O2 \
 -I$_INST_/include/ -fPIC -Wall -Wextra -Wno-unused-function \
 -fno-omit-frame-pointer \
 -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable "
export LDFLAGS=" -O2 -L$_INST_/lib -fPIC "
./autogen.sh
./configure \
  --prefix=$_INST_ \
  --disable-soname-versions --disable-testing --enable-logging --disable-shared

make clean
make -j $(nproc) || exit 1
make install

export PKG_CONFIG_PATH=/workspace/build/inst_ct/lib/pkgconfig/

echo "*** toxirc ***"

cd /workspace/build/
set -x
ls -al /workspace/build/inst_ct/lib/
gcc -O2 -g -fPIC -I/workspace/build/inst_ct/include \
    -L/workspace/build/inst_ct/lib \
    tox_send_msgv3_bot_on_command_output.c \
    /workspace/build/inst_ct/lib/libtoxcore.a \
    /workspace/build/inst_ct/lib/libtoxencryptsave.a \
    -l:libsodium.a \
    -lpthread \
    -o tox_send_msgv3_bot_on_command_output

cd /workspace/build/

cp -av tox_send_msgv3_bot_on_command_output /artefacts/

' > $_HOME_/"$system_to_build_for"/script/run.sh

    mkdir -p $_HOME_/"$system_to_build_for"/workspace/build/c-toxcore/

    docker run -ti --rm \
      -v $_HOME_/"$system_to_build_for"/artefacts:/artefacts \
      -v $_HOME_/"$system_to_build_for"/script:/script \
      -v $_HOME_/"$system_to_build_for"/workspace:/workspace \
      --net=host \
     "toxcore_ready_deb9_003" \
     /bin/sh -c "apk add bash >/dev/null 2>/dev/null; /bin/bash /script/run.sh"
     if [ $? -ne 0 ]; then
        echo "** ERROR **:$system_to_build_for_orig"
        exit 1
     else
        echo "--SUCCESS--:$system_to_build_for_orig"
     fi

done


