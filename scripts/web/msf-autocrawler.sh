#!/bin/bash

xml=nmap.xml
if ! test -f $xml; then
    echo XML file $xml not found
    exit 1
fi

NAME="msf_autocrawler_$(date +%s).xml"
echo "Run msfrpc plugin.."
./plugin/msfrpc.py --output $(realpath $2$NAME) \
                   --log $(realpath log/$NAME.log) \
                   --xml $xml \
                   --resource autocrawler.rc \
                   --options THREADS=100
