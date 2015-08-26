#!/usr/bin/python

import os
import re
import random
import string

class iptables_dynamicdns_update(object):
    def __init__(self, ip_ports):
        self.ip_ports = ip_ports
        self.chain_name = 'AUTH_CHAIN'

    def get_ip_address(self, address):
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
        cmd = "iptables -F %s" % self.chain_name
        print "cmd : %s" % cmd
        os.system(cmd)

        cmd = "iptables -X %s" % self.chain_name
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
        for ip_port in self.ip_ports:
            (ip, port) = ip_port
            static_ip = self.get_ip_address(ip)

            cmd = "iptables -A %s -p tcp -s %s --dport %s -j ACCEPT" % (
                chain_name, static_ip, port)
            print "cmd : %s" % cmd
            os.system(cmd)
        return

    def run(self):
        chain_name = "%s_%s" % (self.chain_name,
                                ''.join(random.sample(string.lowercase,10)))
        self.make_chain(chain_name)
        self.add_rules_to_chain(chain_name)
        self.regist_chain(chain_name)
        self.delete_chain(self.chain_name)
        self.unregist_chain(self.chain_name)
        self.rename_chain(chain_name, self.chain_name)
        return

def main():
    ip_ports = [
        ("192.168.0.0/24", "80"),
        ("github.com", "80")]

    ip_update = iptables_dynamicdns_update(ip_ports)
    ip_update.run()
    return

main()
