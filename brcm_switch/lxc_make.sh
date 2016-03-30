#!/bin/sh

chmod 777 *

cd ofprotocol_status
powerpc-linux-gnu-gcc ofprotocol_status.c -I"../lib/" -I"../secchan/" -g3 -o ofprotocol_status
cd -

export NETCONFLIB=$PWD/../netconf_depend_so

./configure CC=powerpc-linux-gnu-gcc CXX=powerpc-linux-gnu-g++ LDFLAGS="-L$NETCONFLIB -lpthread -llzma -lssl -lcrypto" CFLAGS="-DHAVE_OPENSSL" --host=i686-linux

core_num=`cat /proc/cpuinfo | grep processor | wc -l`
job_num=$((core_num * 2 + 2))

make -j${job_num}

# Package all
mkdir openflow
cp secchan/ofprotocol                                       openflow/
cp udatapath/ofdatapath                                     openflow/
cp utilities/dpctl                                          openflow/
cp ofprotocol_status/ofprotocol_status                      openflow/
cp ./../netconf_depend_so/libdpal.so                        openflow/
cp ./../netconf_depend_so/libsecurec.so                     openflow/
cp ./../netconf_depend_so/libnetconf.so.0                   openflow/
cp ofdatapath.cfg                                           openflow/

# Make the base directory
cd openflow
mkdir ./mydeb
mkdir -p ./mydeb/DEBIAN
touch ./mydeb/DEBIAN/control
touch ./mydeb/DEBIAN/postinst
touch ./mydeb/DEBIAN/postrm

# Change the file's authority
chmod 775 ./mydeb/DEBIAN/postinst
chmod 775 ./mydeb/DEBIAN/postrm
chmod 775 ./mydeb/DEBIAN/control

# Make the lib&bin directory
mkdir -p ./mydeb/home
mkdir -p ./mydeb/usr/bin
mkdir -p ./mydeb/usr/lib/powerpc-linux-gnu

# Copy files
cp ofdatapath.cfg ./mydeb/home
cp ofprotocol ./mydeb/usr/bin
cp ofdatapath ./mydeb/usr/bin
cp ofprotocol_status ./mydeb/usr/bin
cp dpctl ./mydeb/usr/bin
cp libdpal.so ./mydeb/usr/lib/powerpc-linux-gnu
cp libsecurec.so ./mydeb/usr/lib/powerpc-linux-gnu
cp libnetconf.so.0 ./mydeb/usr/lib/powerpc-linux-gnu

# Write files
echo Package: openflow-1.3.4 >> ./mydeb/DEBIAN/control
echo Version: 1.3.4 >> ./mydeb/DEBIAN/control
echo Section: utils >> ./mydeb/DEBIAN/control
echo Priority: optional >> ./mydeb/DEBIAN/control
echo Architecture: powerpc >> ./mydeb/DEBIAN/control
echo Maintainer: huawei >> ./mydeb/DEBIAN/control
echo Description: openflow 1.3.4 >> ./mydeb/DEBIAN/control

echo '#!/bin/bash' >> ./mydeb/DEBIAN/postinst
echo 'touch /var/log/openflow_install.log' >> ./mydeb/DEBIAN/postinst
echo '#!/bin/bash' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /home/ofdatapath.cfg' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ofprotocol' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ofdatapath' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/dpctl' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ofprotocol_status' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/lib/powerpc-linux-gnu/libdpal.so' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/lib/powerpc-linux-gnu/libsecurec.so' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/lib/powerpc-linux-gnu/libnetconf.so.0' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /var/log/openflow_install.log' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /home/pipe_file_m' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /home/pipe_file_s' >> ./mydeb/DEBIAN/postrm

# Make the dpkg file
PACKAGE_NAME=openflow-1.3.4.deb
dpkg -b mydeb ${PACKAGE_NAME}

mv ${PACKAGE_NAME} ./../
rm -rf mydeb
cd ..
rm -rf openflow
chmod 777 ${PACKAGE_NAME}
echo "****************************************************************************************************************"
echo "* Finish building openflow package: ${PACKAGE_NAME} (Install it with command \"dpkg -i ${PACKAGE_NAME}\"). *"
echo "****************************************************************************************************************"
