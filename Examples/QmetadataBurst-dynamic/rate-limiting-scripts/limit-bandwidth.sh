#!/bin/bash

if [ $# -ne 1 ];then
    echo "Please specify the rate in kbps as a parameter"
    exit 1
fi

CONF_FILE="./fireqos.conf"
RATE=$1
DEVICE=enp5s0f1

cat << EOM > $CONF_FILE
interface $DEVICE world-out output rate $RATE
EOM

sudo fireqos start fireqos.conf






