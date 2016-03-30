#!/bin/sh

chmod 777 *

export PATH=/opt/cross_tools/sysroot-ppc_e500mc-glibc_small/x86_64-wrlinuxsdk-linux/usr/bin/powerpc-wrs-linux:$PATH
export SYSROOT=/opt/cross_tools/sysroot-ppc_e500mc-glibc_small/ppce500mc-wrs-linux
export NETCONFLIB=$PWD/../netconf_depend_so

./configure CC=powerpc-wrs-linux-gcc CXX=powerpc-wrs-linux-g++ LDFLAGS="-L$SYSROOT/lib -L$NETCONFLIB --sysroot=$SYSROOT -lpthread" CFLAGS="-I$SYSROOT/usr/include -DHAVE_OPENSSL" --host=i686-linux

core_num=`cat /proc/cpuinfo | grep processor | wc -l`
job_num=$((core_num * 2 + 2))

make -j${job_num}

# Package all
mkdir openflow
cp secchan/ofprotocol                                       openflow/
cp netconfiglib/libxslt.so.1                                openflow/
cp netconfiglib/libssh2.so.1                                openflow/
cp netconfiglib/libidn.so.11                                openflow/
cp netconfiglib/libcurl.so.4                                openflow/
cp netconfiglib/libssl3.so                                  openflow/
cp netconfiglib/libnssutil3.so                              openflow/
cp netconfiglib/libsmime3.so                                openflow/
cp netconfiglib/libnss3.so                                  openflow/
cp netconfiglib/libplc4.so                                  openflow/
cp netconfiglib/libplds4.so                                 openflow/
cp netconfiglib/libnspr4.so                                 openflow/
cp .libs/libnetconf.so.0                                    openflow/
cp udatapath/ofdatapath                                     openflow/
cp ../../../code/bin/release/ppc_e500mc_6800/lib/libdpal.so openflow/

cd openflow
tar zcf ../openflow.tar.gz *
cd - 1>/dev/null 2>&1
rm -rf openflow
echo "*******************************************"
echo "* Final openflow package: openflow.tar.gz *"
echo "*******************************************"
echo -e "Upload the package to CE device and then decompress it whith \"tar zxvf openflow.tar.gz\"."
