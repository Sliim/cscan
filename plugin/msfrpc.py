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

class CscanMsf:
    """ msfrpc plugin for cscan """
    def __init__(self):
        self.logfile = None
        self.cid = None
        try:
            self.client = Msfrpc({"host": os.environ.get("CS_MSF_HOST"), "port": os.environ.get("CS_MSF_PORT")})
            self.client.login(os.environ.get("CS_MSF_USER"), os.environ.get("CS_MSF_PASS"))
            print "Logged in to msfrpc server. Token: %s" % self.client.token
        except:
            print "Cannot connect to server.."

    def check_auth(self):
        if not self.client or not self.client.authenticated:
            print "You are not authenticated.."
            return False
        return True

    def rpc_call(self, meth, opts, key=""):
        if self.check_auth():
            res = self.client.call(meth, opts)
            return res if not key else res.get(key)

    def create_console(self):
        self.cid = self.rpc_call("console.create", [{}], "id")
        self.rpc_call("console.read", [self.cid])

    def destroy_console(self):
        print "Destroy console ID %s.. %s" % (self.cid, self.rpc_call("console.destroy",
                                                                      [self.cid], "result"))

    def set_logfile(self, f):
        self.logfile = open(f, "a+")

    def create_tmp_workspace(self):
        ws = "cscan_" + "".join(random.sample(string.lowercase,6))
        print "Create %s workspace.. %s" % (ws, self.rpc_call("db.add_workspace", [ws], "result"))
        print "Switch to new workspace.. %s" % self.rpc_call("db.set_workspace", [ws], "result")
        return ws

    def import_xml_data(self, ws, xml):
        content = open(xml, "r").read()
        print "Importing data from %s.. %s" % (xml, self.rpc_call("db.import_data", [{"workspace": ws,
                                                                                      "data": content}], "result"))

    def export_workspace(self, out):
        print "Exporting workspace.."
        self.rpc_call("console.write", [self.cid, "db_export %s\r\n" % out])
    
        while True:
            time.sleep(5)
            res = self.rpc_call("console.read", [self.cid])
            if res.get("data"):
                print "%s %s" % (res.get("prompt"), res.get("data"))
            if "Finished export" in res.get("data"):
                return True

    def destroy_tmp_workspace(self, ws, new_ws):
        print "Switch to %s workspace.. %s" % (new_ws, self.rpc_call("db.set_workspace",
                                                                      [new_ws], "result"))
        print "Delete %s workspace.. %s" % (ws, self.rpc_call("db.del_workspace", [ws], "result"))

    def wait_for_jobs(self):
        while True:
            job_list = self.rpc_call("job.list", [])
            print "Current jobs: %s (Total: %d)" % (",".join(job_list), len(job_list))
            if len(job_list) > 0:
                for j in job_list:
                    jinfo = self.rpc_call("job.info", [j])
                    print "%s - %s" % (jinfo.get("jid"), jinfo.get("name"))
            else:
                return True
            time.sleep(10)

    def run_commands(self, commands, quiet=False):
            print "Run command: %s" % "\n".join(commands)
            self.rpc_call("console.write", [self.cid, "\n".join(commands)])
            self.rpc_call("console.write", [self.cid, "set PROMPT commands_deployed\r\n"])

            while True:
                time.sleep(2)
                res = self.rpc_call("console.read", [self.cid])
                if self.logfile:
                    self.logfile.write(str(res) + "\n")
                if not quiet and res.get("data"):
                    print "%s %s" % (res.get("prompt"), res.get("data")) 
                if "commands_deployed" in res["prompt"] and not res["busy"]:
                    self.rpc_call("console.write", [self.cid, "set PROMPT cscan\r\n"])
                    break

    def clean(self):
        if self.logfile:
            self.logfile.close()
        self.wait_for_jobs()
        self.rpc_call("console.write", [self.cid, "set PROMPT msf\r\n"])
        time.sleep(1)

def main():
    cscan = CscanMsf()
    parser = argparse.ArgumentParser(description="msfrpc cscan plugin, for automated security testing")
    parser.add_argument("-o","--output", help="Output file", required=False)
    parser.add_argument("-l","--log", help="Log file", required=False)
    parser.add_argument("-m","--modules", help="Modules to use", required=False)
    parser.add_argument("-r","--resource", help="Resource to execute", required=False)
    parser.add_argument("-O","--options", help="Modules options", required=False)
    parser.add_argument("-c","--command", help="Command to execute (check, run, exploit)", default="check")
    parser.add_argument("-x","--xml", help="XML to import in temp workspace", required=False)
    parser.add_argument("-T","--disable-tmp-ws", help="Do not create temp workspace and use current", required=False)
    parser.add_argument("-q","--quiet", help="Quiet mode, set -l options to have log in a file", required=False, action="store_true")
    args = parser.parse_args()    
    
    current_ws = cscan.rpc_call("db.current_workspace", [], "workspace")
    tmp_ws = None

    print "Current workspace: " + current_ws
    if not args.disable_tmp_ws:
        if os.environ.get("CS_MSF_TMP_WS") == "enabled":
            tmp_ws = cscan.create_tmp_workspace()
            if args.xml:
                cscan.import_xml_data(tmp_ws, args.xml)

    if args.disable_tmp_ws:
        print "Temporary workspace disabled."
    if args.options:
        print "Options: \n" + args.options.replace(",", "\n")
    if args.modules:
        print "Modules: \n" + args.modules.replace(",", "\n")
    if args.resource:
        print "Resource: " + args.resource 
    print "Command: " + args.command
    if args.output:
        print "Output: " + args.output
    if args.log:
        cscan.set_logfile(args.log)
        print "Log file: " + args.log

    commands = []
    console_id = cscan.create_console()
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
    cscan.run_commands(commands, args.quiet if args.quiet else False)
    cscan.clean()

    if os.environ.get("CS_MSF_EXPORT") == "enabled" and args.output:
        cscan.export_workspace(args.output)

    cscan.destroy_console()

    if tmp_ws:
        cscan.destroy_tmp_workspace(tmp_ws, current_ws)

if __name__ == "__main__":
    main()

