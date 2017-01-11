#!/bin/bash -x

export SDK_PATH=

echo "make_lib.sh version 20150923"
echo ""

if [ $SDK_PATH ]; then
    echo "SDK_PATH:"
    echo "$SDK_PATH"
    echo ""
else
    echo "ERROR: Please export SDK_PATH in gen_misc.sh firstly, exit!!!"
    exit
fi

if [ ! -d "lib" ]; then
    mkdir lib
fi
cd $1
make
cp .output/eagle/debug/lib/lib$1.a ../lib/lib$1.a
xtensa-lx106-elf-strip --strip-unneeded ../lib/lib$1.a
cd ..
