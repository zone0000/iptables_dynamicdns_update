#!/usr/bin/python

import sys
import os
import re
import random
import string
import json

class IptablesDynamicDnsUpdate(object):
    def __init__(self, localport_foreignips):
        self.localport_foreignips = localport_foreignips
        self.chain_name = 'AUTH_CHAIN'

    def get_static_ip_address(self, address):
        hostname = self.get_text_output("host %s" % address)
        ipaddress = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)
        if len(ipaddress) == 0:
            return address
        else:
            return ipaddress[len(ipaddress) - 1]

    def get_text_output(self, cmd):
        pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
        pipe = os.popen(cmd + ' 2>&1', 'r')
        text = pipe.read()
        if text[-1:] == '\n':
            text = text[:-1]
            return text
        return

    def make_chain(self, chain_name):
        cmd = "iptables -N %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    def delete_chain(self, chain_name):
        cmd = "iptables -F %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)

        cmd = "iptables -X %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    def rename_chain(self, from_chain_name, to_chain_name):
        cmd = "iptables -E %s %s" % (from_chain_name, to_chain_name)
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    def regist_chain(self, chain_name):
        cmd = "iptables -I INPUT -j %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    def unregist_chain(self, chain_name):
        cmd = "iptables -D INPUT -j %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    def add_rules_to_chain(self, chain_name):
        for localport_foreignip in self.localport_foreignips:
            (localport, foreignip) = localport_foreignip
            static_ip = self.get_static_ip_address(foreignip)

            cmd = "iptables -A %s -p tcp -s %s --dport %s -j ACCEPT" % (
                chain_name, static_ip, localport)
            print "cmd : %s" % cmd
            os.system(cmd)
        return

    def run(self):
        chain_name = "%s_%s" % (self.chain_name,
                                ''.join(random.sample(string.lowercase,10)))
        self.make_chain(chain_name)
        self.add_rules_to_chain(chain_name)
        self.regist_chain(chain_name)
        self.unregist_chain(self.chain_name)
        self.delete_chain(self.chain_name)
        self.rename_chain(chain_name, self.chain_name)
        return

class IptableLoader(object):
    def __init__(self):
        self.localport_foreignip = {}

    def load(self, filename):
        f = open(filename, 'r')
        self.localport_foreignip = json.loads(f.read())
        f.close()
        return

    def prints(self):
        for localport_foreignip in self.localport_foreignip["localport_foreignip"]:
            print "localPort: %s, foreignIp: %s" % (localport_foreignip["localport"],
                                                    localport_foreignip["foreignip"])

    def get_localport_forignip(self):
        localport_foreignips = []
        for v in self.localport_foreignip["localport_foreignip"]:
            localport_foreignips.append((v["localport"], v["foreignip"]))
        return localport_foreignips

def main(argv):
    iptable_loader = IptableLoader();
    iptable_loader.load("localport_foreignip.json")
    localport_foreignip = iptable_loader.get_localport_forignip()

    ip_update = IptablesDynamicDnsUpdate(localport_foreignip)
    ip_update.run()
    return

if __name__ == "__main__":
    try:
        main(argv=sys.argv)
    except os.error, err:
        print str(err)