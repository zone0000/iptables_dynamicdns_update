#!/usr/bin/python
''' This script add rules into iptables '''

import os
import re
import random
import string
import json
import dns.resolver # from dnspython

class IptablesDynamicDnsUpdate(object):
    ''' Update iptables '''
    def __init__(self, localport_foreignips):
        ''' init '''
        self.localport_foreignips = localport_foreignips
        self.chain_name = 'AUTH_CHAIN'
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8']
        return

    def get_static_ip_address(self, address):
        ''' get static ip address '''
        compiled_regex_ip = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}($|\/\d{1,2}$)")

        matched = compiled_regex_ip.match(address)
        if matched:
            return matched.group()

        results = self.resolver.query(address, 'A')
        for result in results:
            matched = compiled_regex_ip.match(result.address)
            if matched:
                return matched.group()
        return

    @staticmethod
    def make_chain(chain_name):
        ''' make chain '''
        cmd = "iptables -N %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    @staticmethod
    def delete_chain(chain_name):
        ''' delete chain '''
        cmd = "iptables -F %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)

        cmd = "iptables -X %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    @staticmethod
    def rename_chain(from_chain_name, to_chain_name):
        ''' rename chain '''
        cmd = "iptables -E %s %s" % (from_chain_name, to_chain_name)
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    @staticmethod
    def regist_chain(chain_name):
        ''' regist chain '''
        cmd = "iptables -I INPUT -j %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    @staticmethod
    def unregist_chain(chain_name):
        ''' unregist chain '''
        cmd = "iptables -D INPUT -j %s" % chain_name
        print "cmd : %s" % cmd
        os.system(cmd)
        return

    def add_rules_to_chain(self, chain_name):
        ''' add rules to chain '''
        for localport_foreignip in self.localport_foreignips:
            (localport, foreignip) = localport_foreignip
            static_ip = self.get_static_ip_address(foreignip)

            if len(static_ip) != 0:
                cmd = "iptables -A %s -p tcp -s %s --dport %s -j ACCEPT" % (
                    chain_name, static_ip, localport)
                print "cmd : %s" % cmd
                os.system(cmd)
        return

    def run(self):
        ''' run '''
        chain_name = "%s_%s" % (self.chain_name,
                                ''.join(random.sample(string.lowercase, 10)))
        self.make_chain(chain_name)
        self.add_rules_to_chain(chain_name)
        self.regist_chain(chain_name)
        self.unregist_chain(self.chain_name)
        self.delete_chain(self.chain_name)
        self.rename_chain(chain_name, self.chain_name)
        return

class IptableLoader(object):
    ''' Load iptable rules from json file '''
    def __init__(self):
        ''' init '''
        self.localport_foreignip = {}
        return

    def load(self, filename):
        ''' load '''
        rule_file = open(filename, 'r')
        self.localport_foreignip = json.loads(rule_file.read())
        rule_file.close()
        return

    def prints(self):
        ''' print rules '''
        for localport_foreignip in self.localport_foreignip["localport_foreignip"]:
            print "localPort: %s, foreignIp: %s" % (localport_foreignip["localport"],
                                                    localport_foreignip["foreignip"])
        return

    def get_localport_foreignip(self):
        ''' get localport and foreignip '''
        localport_foreignips = []
        for port_ip in self.localport_foreignip["localport_foreignip"]:
            localport_foreignips.append((port_ip["localport"], port_ip["foreignip"]))
        return localport_foreignips

def main():
    ''' main '''
    iptable_loader = IptableLoader()
    iptable_loader.load("localport_foreignip.json")
    localport_foreignip = iptable_loader.get_localport_foreignip()

    ip_update = IptablesDynamicDnsUpdate(localport_foreignip)
    ip_update.run()
    return

if __name__ == "__main__":
    try:
        main()
    except os.error, err:
        print str(err)
