#!/bin/bash

#Attach to a running process if TestPoint or ControlPoint is running
if [ "${FM_API_SHM_KEY+set}" != set ]; then
    # Look for the names of processes that might be sharing the
    # FocalPoint API library. 
    #   l2d/bin/ama0        ControlPoint
    #   progressChildPid    TestPoint
    #
    # Custom applications may be added to this list,
    # separated with pipe (|) characters.
    CLIENTS='l2d/bin/ama0|progressChildPid|ofdatapath'
    
    PS=`pgrep -f $CLIENTS`
    if [ "$PS" == "" ]; then
        export FM_API_SHM_KEY=501,restart
    else
        export FM_API_SHM_KEY=501
    fi
    if [ -e /sbin/sysctl ]; then
        sysctl -w kernel.shmmax=536870912
    fi
    echo "Setting up multi-process key=$FM_API_SHM_KEY"
fi

./ofdatapath $@
