#!/usr/bin/env python

import os
import time
import string
import random
import argparse
import msgpack
import httplib

class Msfrpc:
    """ Msfrpc class from https://github.com/SpiderLabs/msfrpc """
    class MsfError(Exception):
        def __init__(self,msg):
            self.msg = msg
        def __str__(self):
            return repr(self.msg)

    class MsfAuthError(MsfError):
        def __init__(self,msg):
            self.msg = msg
    
    def __init__(self,opts=[]):
        self.host = opts.get('host') or "127.0.0.1"
        self.port = opts.get('port') or 55552
        self.uri = opts.get('uri') or "/api/"
        self.ssl = opts.get('ssl') or False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type" : "binary/message-pack" }
        if self.ssl:
            self.client = httplib.HTTPSConnection(self.host,self.port)
        else:
            self.client = httplib.HTTPConnection(self.host,self.port)
 

    def encode(self,data):
        return msgpack.packb(data)
    def decode(self,data):
        return msgpack.unpackb(data)

    def call(self,meth,opts = []):
        if meth != "auth.login":
            if not self.authenticated:
                raise self.MsfAuthError("MsfRPC: Not Authenticated")

        if meth != "auth.login":
            opts.insert(0,self.token)

        opts.insert(0,meth)
        params = self.encode(opts)
        self.client.request("POST",self.uri,params,self.headers)
        resp = self.client.getresponse()
        return self.decode(resp.read()) 
  
    def login(self,user,password):
        ret = self.call('auth.login',[user,password])
        if ret.get('result') == 'success':
	    self.authenticated = True
            self.token = ret.get('token')
            return True
        else:
            raise self.MsfAuthError("MsfRPC: Authentication failed")


def main():
    parser = argparse.ArgumentParser(description='msfrpc cscan plugin, for automated security testing')
    parser.add_argument('-o','--output', help='Output file', required=False)
    parser.add_argument('-m','--modules', help='Modules to use', required=False)
    parser.add_argument('-r','--resource', help='Resource to execute', required=False)
    parser.add_argument('-O','--options', help='Modules options', required=False)
    parser.add_argument('-c','--command', help='Command to execute (check, run, exploit)', required=False, default="check")
    args = parser.parse_args()    
    
    client = Msfrpc({"host": os.environ.get('CS_MSF_HOST'), "port": os.environ.get('CS_MSF_PORT')})
    client.login(os.environ.get('CS_MSF_USER'), os.environ.get('CS_MSF_PASS'))
    current_ws = client.call('db.current_workspace')['workspace']
    tmp_ws = "cscan_" + ''.join(random.sample(string.lowercase,6))

    print "Current workspace: " + current_ws
    print "Create %s workspace.. %s" % (tmp_ws, client.call('db.add_workspace',
                                                            [tmp_ws])['result'])
    print "Switch to new workspace.. %s" % client.call('db.set_workspace',
                                                       [tmp_ws])['result']
    if args.options:
        print "Options: \n" + args.options.replace(",", "\n")
    if args.modules:
        print "Modules: \n" + args.modules.replace(",", "\n")
    if args.resource:
        print "Resource: " + args.resource 
    print "Command: " + args.command
    print "Output: " + args.output

    commands = []
    console_id = client.call('console.create', [{}])['id']
    client.call('console.read', [console_id])
    print "Created console ID " + str(console_id)

    if args.options:
        for option in args.options.split(','):
            commands.append("setg " + option.replace('=', ' '))

    if args.modules:
        for module in args.modules.split(','):
            commands.append("use " + module)
            commands.append("show options")
            commands.append(args.command)
    elif args.resource:
        commands.append("resource " + args.resource)

    commands.append("\r\n")
    print "Run command: %s" % "\n".join(commands)
    client.call('console.write', [console_id, "\n".join(commands)])
    client.call('console.write', [console_id, "set PROMPT command_deployed\r\n"])

    while True:
        time.sleep(2)
        res = client.call('console.read', [console_id])
        print "%s %s" % (res["prompt"], res['data'])
        if 'command_deployed' in res['prompt'] and not res['busy']:
            client.call('console.write', [console_id, "set PROMPT 'exporting>>'\r\n"])
            break

    print "Exporting workspace.."
    client.call('console.write', [console_id, "db_export " + args.output + "\nset PROMPT msf\r\n"])

    while True:
        time.sleep(5)
        res = client.call('console.read', [console_id])
        print "%s %s" % (res["prompt"], res['data'])
        if 'Finished export' in res['data']:
            break

    print "Destroy console ID %s.. %s" % (console_id,
                                          client.call('console.destroy',
                                                      [console_id])['result'])
    print "Switch to %s workspace.. %s" % (current_ws,
                                           client.call('db.set_workspace',
                                                       [current_ws])['result'])
    print "Delete %s workspace.. %s" % (tmp_ws, client.call('db.del_workspace', [tmp_ws])['result'])

if __name__ == "__main__":
    main()

