#!/bin/sh

export OPENFLOW_PATH=$PWD

echo -n "Building secure_c ... "
make -C ${OPENFLOW_PATH}/secure_c/src -f makefile_lxc &>${OPENFLOW_PATH}/log.log
if [ $? != 0 ];then
        echo ">>>>>>>>>>ERROR: build secure_c error!"
        exit
else
        echo "done"
fi

echo -n "Building dpal ... "
make -C ${OPENFLOW_PATH}/dpal/source -f makefile_lxc &>>${OPENFLOW_PATH}/log.log
if [ $? != 0 ];then
        echo ">>>>>>>>>>ERROR: build dpal error!"
        exit
else
        echo "done"
fi

echo -n "Building openflow ... "
cd ${OPENFLOW_PATH}/brcm_switch
./lxc_make.sh &>>${OPENFLOW_PATH}/log.log
echo "done"

PACKAGE_NAME=openflow-1.3.4.deb
mv ${OPENFLOW_PATH}/brcm_switch/${PACKAGE_NAME} ${OPENFLOW_PATH}/${PACKAGE_NAME}
echo "****************************************************************************************************************"
echo "* Finish building openflow package: ${PACKAGE_NAME} (Install it with command \"dpkg -i ${PACKAGE_NAME}\"). *"
echo "****************************************************************************************************************"
