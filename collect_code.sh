#!/bin/sh

export V8_ROOT=$PWD/../../

rm -rf openflow.tar.gz

if [ ! -d ${V8_ROOT}/code/dcswitch/dpal ]; then
	echo "code path error, pls check!"
	exit
else
	echo -n "Copy dpal to current directory ... "
	cp -r ${V8_ROOT}/code/dcswitch/dpal ./
	find ./dpal -name *.o | xargs rm 1>/dev/null 2>&1
	find ./dpal -name *.d | xargs rm 1>/dev/null 2>&1
	echo "done"
fi

if [ ! -d ${V8_ROOT}/code/dcswitch/secure_c ]; then
	echo "code path error, pls check!"
	exit
else
	echo -n "Copy secure_c to current directory ... "
	cp -r ${V8_ROOT}/code/dcswitch/secure_c ./
	find ./secure_c -name *.o | xargs rm 1>/dev/null 2>&1
	find ./secure_c -name *.d | xargs rm 1>/dev/null 2>&1
	echo "done"
fi

cd ..

echo -n "Compress openflow directory ... "
tar zcf openflow.tar.gz openflow/
mv openflow.tar.gz openflow/
echo "done"

echo "Final output source file package: openflow.tar.gz"
