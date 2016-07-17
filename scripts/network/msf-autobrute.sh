#!/bin/bash
NAME="msf_autobrute_$(date +%s).xml"
echo "Run msfrpc plugin.."
./plugin/msfrpc.py --output $(realpath $2$NAME) --resource auto_brute.rc --xml lab.xml --options THREADS=100

