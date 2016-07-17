#!/bin/bash
NAME="msf_autobrute_$(date +%s).xml"
echo ./plugin/msfrpc.py --output $(realpath $2$NAME) --resource auto_brute.rc --xml lab.xml
./plugin/msfrpc.py --output $(realpath $2$NAME) --resource auto_brute.rc --xml lab.xml --options THREADS=100

