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
        self.host = opts.get("host") or "127.0.0.1"
        self.port = opts.get("port") or 55552
        self.uri = opts.get("uri") or "/api/"
        self.ssl = opts.get("ssl") or False
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
        ret = self.call("auth.login",[user,password])
        if ret.get("result") == "success":
	    self.authenticated = True
            self.token = ret.get("token")
            return True
        else: 
            raise self.MsfAuthError("MsfRPC: Authentication failed")

client = Msfrpc({"host": os.environ.get("CS_MSF_HOST"), "port": os.environ.get("CS_MSF_PORT")})

def create_tmp_workspace():
    ws = "cscan_" + "".join(random.sample(string.lowercase,6))
    print "Create %s workspace.. %s" % (ws, client.call("db.add_workspace",
                                                        [ws])["result"])
    print "Switch to new workspace.. %s" % client.call("db.set_workspace",
                                                       [ws])["result"]
    return ws

def import_xml_data(ws, xml):
    content = open(xml, "r").read()
    print "Importing data from %s.. %s" % (xml, client.call("db.import_data",
                                                            [{"workspace": ws,
                                                              "data": content}])["result"])

def export_workspace(cid, out):
    print "Exporting workspace.."
    client.call("console.write", [cid, "db_export %s\r\n" % out])
    
    while True:
        time.sleep(5)
        res = client.call("console.read", [cid])
        print "%s %s" % (res["prompt"], res["data"])
        if "Finished export" in res["data"]:
            return True

def destroy_tmp_workspace(ws, new_ws):
    print "Switch to %s workspace.. %s" % (new_ws,
                                           client.call("db.set_workspace",
                                                       [new_ws])["result"])
    print "Delete %s workspace.. %s" % (ws, client.call("db.del_workspace", [ws])["result"])

def wait_for_jobs():
    while True:
        job_list = client.call("job.list", [])
        print "Current jobs: %s (Total: %d)" % (",".join(job_list), len(job_list))
        if len(job_list) > 0:
            for j in job_list:
                jinfo = client.call("job.info", [j])
                print "%s - %s" % (jinfo["jid"], jinfo["name"])
        else:
            return True
        time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description="msfrpc cscan plugin, for automated security testing")
    parser.add_argument("-o","--output", help="Output file", required=False)
    parser.add_argument("-m","--modules", help="Modules to use", required=False)
    parser.add_argument("-r","--resource", help="Resource to execute", required=False)
    parser.add_argument("-O","--options", help="Modules options", required=False)
    parser.add_argument("-c","--command", help="Command to execute (check, run, exploit)", required=False, default="check")
    parser.add_argument("-x","--xml", help="XML to import in temp workspace", required=False)
    args = parser.parse_args()    
    
    client.login(os.environ.get("CS_MSF_USER"), os.environ.get("CS_MSF_PASS"))
    current_ws = client.call("db.current_workspace")["workspace"]
    tmp_ws = None

    print "Current workspace: " + current_ws

    if os.environ.get("CS_MSF_TMP_WS") == "enabled":
        tmp_ws = create_tmp_workspace()
        if args.xml:
            import_xml_data(tmp_ws, args.xml)
            
    if args.options:
        print "Options: \n" + args.options.replace(",", "\n")
    if args.modules:
        print "Modules: \n" + args.modules.replace(",", "\n")
    if args.resource:
        print "Resource: " + args.resource 
    print "Command: " + args.command
    print "Output: " + args.output

    commands = []
    console_id = client.call("console.create", [{}])["id"]
    client.call("console.read", [console_id])
    print "Created console ID " + str(console_id)

    if args.options:
        for option in args.options.split(","):
            commands.append("setg " + option.replace("=", " "))

    if args.modules:
        for module in args.modules.split(","):
            commands.append("use " + module)
            commands.append("show options")
            commands.append(args.command)
    elif args.resource:
        commands.append("resource " + args.resource)

    commands.append("\r\n")
    print "Run command: %s" % "\n".join(commands)
    client.call("console.write", [console_id, "\n".join(commands)])
    client.call("console.write", [console_id, "set PROMPT command_deployed\r\n"])

    while True:
        time.sleep(2)
        res = client.call("console.read", [console_id])
        print "%s %s" % (res["prompt"], res["data"])
        if "command_deployed" in res["prompt"] and not res["busy"]:
            client.call("console.write", [console_id, "set PROMPT 'exporting>>'\r\n"])
            break

    wait_for_jobs()

    if os.environ.get("CS_MSF_EXPORT") == "enabled" and args.output:
        export_workspace(console_id, args.output)

    client.call("console.write", [console_id, "set PROMPT msf\r\n"])
    time.sleep(1)

    print "Destroy console ID %s.. %s" % (console_id,
                                          client.call("console.destroy",
                                                      [console_id])["result"])
    if tmp_ws:
        destroy_tmp_workspace(tmp_ws, current_ws)

if __name__ == "__main__":
    main()

