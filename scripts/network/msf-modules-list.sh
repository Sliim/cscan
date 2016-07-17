#!/bin/bash

modules_file=msf.modules
if ! test -f $modules_file; then
    echo no modules file found
    exit 1
fi

while read h; do
    NAME="msf_modules_list_$(date +%s).xml"
    echo "Run msfrpc plugin.."
    ./plugin/msfrpc.py --output $(realpath $2$NAME) --modules $(sed ':a;N;$!ba;s/\n/,/g' $modules_file) --options RHOSTS=$h,RHOST=$h --command=run
done <$1

