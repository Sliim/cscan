#!/bin/bash
NAME="msf_autocrawler_$(date +%s).xml"
echo "Run msfrpc plugin.."
./plugin/msfrpc.py --output $(realpath $2$NAME) --resource autocrawler.rc --xml lab.xml

