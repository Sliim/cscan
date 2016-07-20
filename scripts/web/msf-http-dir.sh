#!/bin/bash

while read h; do
    NAME="msf_http_dir_$(date +%s).xml"
    HOST=$(echo $h | cut -d/ -f3 | cut -d: -f1)
    PORT=$(echo $h | cut -d/ -f3 | cut -d: -f2)
    echo "Run msfrpc plugin.."
    ./plugin/msfrpc.py --output $(realpath $2$NAME) \
                       --log $(realpath log/$NAME.log) \
                       --modules auxiliary/scanner/http/dir_scanner \
                       --options RHOSTS=$HOST,RPORT=$PORT \
                       --command=run
done <$1
