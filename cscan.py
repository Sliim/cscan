#!/usr/bin/env python
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

import subprocess
import os
import argparse
import time
from pprint import pprint
from config import config

def lockFile(lockfile):
    if os.path.isfile(lockfile):
        return False
    else:
        f = open(lockfile, 'w')
        f.close()
        return True

def target_list(script):
    dictionary = {
        "network": "ips.txt",
        "web": "websites.txt",
        "extra": "ips.txt"
    }

    category = 'network'
    for path in os.environ["PATH"].split(os.pathsep):
        if os.path.exists(os.path.join(path, script)):
            category = os.path.join(path)[1]

    return dictionary[category]

def mattermost_message(url, msg, username=None, icon_url=None):
    if url and msg:
        import json
        import requests
        payload = { "text": msg }
        if username:
            payload["username"] = username
        if icon_url:
            payload["icon_url"] = icon_url

        requests.post(url,
                      data={"payload": json.dumps(payload)})

def main():
    lockf = ".lock.pod"
    if not lockFile(lockf):
        print "You can run only one instance of cscan (%s)" % lockf
        exit(0)

    for d in ["log", "output"]:
        if not os.path.isdir(d):
            os.makedirs(d)

    my_env = os.environ
    env = config.copy()
    env.update(my_env)

    parser = argparse.ArgumentParser(description='continues scanning on Faraday')
    parser.add_argument('-s','--script', help='Scan only the following script ej: ./cscan.py -p nmap.sh', required=False)
    parser.add_argument('-S','--scripts', help='Scan the following scripts list ej: ./cscan.py -p nmap.sh,nikto.sh', required=False)
    parser.add_argument('-c','--category', help='Scan only for given category ej: ./cscan.py -c network', required=False)
    parser.add_argument('-t','--targets', help='Choose a custom target list ej: ./cscan.py -t custom-list.txt', required=False)
    args = parser.parse_args()

    mm_url = False
    if env["CS_MATTERMOST"]:
        mm_url = env["CS_MATTERMOST"]
        mm_username = env["CS_MATTERMOST_USERNAME"] if "CS_MATTERMOST_USERNAME" in env else None
        mm_icon_url = env["CS_MATTERMOST_ICON_URL"] if "CS_MATTERMOST_ICON_URL" in env else None
        mattermost_message(mm_url, "Starting CScan..", mm_username, mm_icon_url)

    if args.script:
        scripts = [args.script]
    elif args.scripts:
        scripts = args.scripts.split(",")
    else:
        scripts = env["CS_SCRIPTS"].split(",")

    for category in env["CS_CATEGORIES"].split(","):
        env["PATH"] += ":%s" % os.path.abspath("./scripts/" + category)

    for script in scripts:
        if args.targets:
            targets = args.targets
        else:
            targets = target_list(script)

        cmd = "%s %s output/ log/" % (script, targets)
        print "Running: %s" % cmd
        if mm_url:
            mattermost_message(mm_url, "Run script: %s\nTargets:\n```\n%s\n```\n" % (f, open(targets).read()), mm_username, mm_icon_url)
        proc = subprocess.call(cmd, shell=True, stdin=None, env=dict(env))

    if mm_url:
        mattermost_message(mm_url, "CScan finished.", mm_username, mm_icon_url)

    #Remove lockfile
    os.remove(lockf)

if __name__ == "__main__":
    main()
