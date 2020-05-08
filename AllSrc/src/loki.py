#!/usr/bin/env python

#       loki.py
#       
#       Copyright 2009 Daniel Mende <dmende@ernw.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import base64
import copy
import hashlib
import sys
import os
import platform
import threading
import time
import traceback
import string
import struct

import ConfigParser

import dpkt
import dnet
import IPy
pcap = None

DEBUG = True

VERSION = "0.3.0"
PLATFORM = platform.system()

MODULE_PATH="/modules"
CONFIG_PATH=os.path.expanduser("~/.loki")
DATA_DIR="."
#~ For OSX Bundeling
#~ DATA_DIR=os.path.expandvars("$bundle_data/loki")

class pcap_thread(threading.Thread):
    def __init__(self, parent, interface):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True
        self.interface = interface

    def run(self):
        p = pcap.pcapObject()
        #check to_ms = 100 for non linux
        p.open_live(self.interface, 1600, 1, 100)
        if not PLATFORM == "Darwin":
            p.setnonblock(1)
        while self.running:
            try:
                p.dispatch(1, self.dispatch_packet)
            except Exception, e:
                self.parent._print(e)
                if DEBUG:
                    self.parent._print('-'*60)
                    self.parent._print(traceback.format_exc())
                    self.parent._print('-'*60)

            time.sleep(0.001)
        self.parent.log("Listen thread terminated")

    def quit(self):
        self.running = False

    def dispatch_packet(self, pktlen, data, timestamp):
        got_tag = False
        if not data:
            return
        #parse and build dpkt.eth on myself, as dpkt parsing method strips dot1q, mpls, etc...
        (dst, src, type) = struct.unpack("!6s6sH", data[:14])
        eth = dpkt.ethernet.Ethernet(dst=dst, src=src, type=type, data=data[14:])
        for (check, call, name) in self.parent.eth_checks:
            (ret, stop) = check(eth)
            if ret:
                call(copy.copy(eth), timestamp)
                if stop:
                    return
        if eth.type == dpkt.ethernet.ETH_TYPE_8021Q or eth.type == dpkt.ethernet.ETH_TYPE_MPLS:
            got_tag = True
            eth_new = dpkt.ethernet.Ethernet(data)
            #dpkt only removes first dot1q tag
            while eth_new.type == dpkt.ethernet.ETH_TYPE_8021Q:
                eth_new = dpkt.ethernet.Ethernet(eth_new.data)
            for (check, call, name) in self.parent.eth_checks:
                (ret, stop) = check(eth_new)
                if ret:
                    call(copy.copy(eth_new), timestamp)
                    if stop:
                        return
            #why here and not waiting for later?
            if eth_new.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = dpkt.ip.IP(str(eth_new.data))
                for (check, call, name) in self.parent.ip_checks:
                    (ret, stop) = check(ip)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip), timestamp)
                        if stop:
                            return
            eth = eth_new
        
        #strip pppoe and ppp headers
        if eth.type == dpkt.ethernet.ETH_TYPE_PPPoE:
            pppoe = dpkt.pppoe.PPPoE(str(eth.data))
            ppp = dpkt.ppp.PPP(str(pppoe.data))
            eth.data = ppp.data
            if ppp.p == dpkt.ppp.PPP_IP:
                eth.type = dpkt.ethernet.ETH_TYPE_IP
            elif ppp.p == dpkt.ppp.PPP_IP6:
                eth.type = dpkt.ethernet.ETH_TYPE_IP6
            else:
                return

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = dpkt.ip.IP(str(eth.data))
            for (check, call, name) in self.parent.ip_checks:
                if name == "arp" and got_tag:
                    continue
                (ret, stop) = check(ip)
                if ret:
                    call(copy.copy(eth), copy.copy(ip), timestamp)
                    if stop:
                        return
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.tcp.TCP(str(ip.data))
                for (check, call, name) in self.parent.tcp_checks:
                    (ret, stop) = check(tcp)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip), copy.copy(tcp), timestamp)
                        if stop:
                            return
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = dpkt.udp.UDP(str(ip.data))
                for (check, call, name) in self.parent.udp_checks:
                    (ret, stop) = check(udp)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip), copy.copy(udp), timestamp)
                        if stop:
                            return
            elif ip.p == dpkt.ip.IP_PROTO_SCTP:
                sctp = dpkt.sctp.SCTP(str(ip.data))
                for (check, call, name) in self.parent.sctp_checks:
                    (ret, stop) = check(sctp)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip), copy.copy(sctp), timestamp)
                        if stop:
                            return
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip6 = dpkt.ip6.IP6(str(eth.data))
            for (check, call, name) in self.parent.ip6_checks:
                (ret, stop) = check(ip6)
                if ret:
                    call(copy.copy(eth), copy.copy(ip6), timestamp)
                    if stop:
                        return
            if ip6.nxt == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.tcp.TCP(str(ip6.data))
                for (check, call, name) in self.parent.tcp_checks:
                    (ret, stop) = check(tcp)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip6), copy.copy(tcp), timestamp)
                        if stop:
                            return
            elif ip6.nxt == dpkt.ip.IP_PROTO_UDP:
                udp = dpkt.udp.UDP(str(ip6.data))
                for (check, call, name) in self.parent.udp_checks:
                    (ret, stop) = check(udp)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip6), copy.copy(udp), timestamp)
                        if stop:
                            return
            elif ip6.nxt == dpkt.ip.IP_PROTO_SCTP:
                sctp = dpkt.sctp.SCTP(str(ip6.data))
                for (check, call, name) in self.parent.sctp_checks:
                    (ret, stop) = check(sctp)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip6), copy.copy(sctp), timestamp)
                        if stop:
                            return

class pcap_thread_offline(pcap_thread):
    def __init__(self, parent, filename):
        self.filename = filename
        pcap_thread.__init__(self, parent, "null")

    def run(self):
        p = pcap.pcapObject()
        p.open_offline(self.filename)
        while self.running:
            try:
                if not p.dispatch(1, self.dispatch_packet):
                    self.running = False
            except Exception, e:
                self.parent._print(e)
                if DEBUG:
                    self.parent._print('-'*60)
                    self.parent._print(traceback.format_exc())
                    self.parent._print('-'*60)
        self.parent.log("Read thread terminated")

class dnet_thread(threading.Thread):
    def __init__(self, interface):
        threading.Thread.__init__(self)
        self.interface = interface
        self.sem = threading.Semaphore()
        self.running = True
        self.eth = dnet.eth(interface)
        self.out = None

    def run(self):
        while self.running:
            self.sem.acquire()
            if self.out:
                self.eth.send(self.out)
                self.out = None
            self.sem.release()
            time.sleep(0.001)

    def quit(self):
        self.running = False

    def send(self, out):
        self.sem.acquire()
        self.out = out
        self.sem.release()
        time.sleep(0.001)

class fake_eth(object):
    def get(self):
        return "\x00\x00\x00\x00\x00\x00"
        
class dnet_thread_offline(object):
    def __init__(self):
        self.eth = fake_eth()
    def send(self, data):
        pass

class codename_loki(object):
    def __init__(self):
        self.modules = {}
        self.groups = {}
        self.msg_id = 0
        self.configured = False
        self.filename = None
        self.netcfg_configured = False
        self.pcap_thread = None
        self.dnet_thread = None
        self.fw = None
        self.data_dir = DATA_DIR
        self.devices = {}
        self.ui = None
        self.wordlist = None
        self.bruteforce = True
        self.bruteforce_full = False
        self.bruteforce_threads = 4
        self.dot_prog = 'dot'
        self.dot_prog_choices = [ 'circo', 'dot', 'fdp', 'neato', 'osage', 'sfdp', 'twopi' ]

        self.eth_checks = []
        self.ip_checks = []
        self.ip6_checks = []
        self.tcp_checks = []
        self.udp_checks = []
        self.sctp_checks = []

        self.module_active = []

    def main(self):
        self._print("This is %s version %s by Daniel Mende - dmende@ernw.de" % (self.__class__.__name__, VERSION))
        self._print("Running on %s" % (PLATFORM))

        self.load_all_modules()
        self.init_all_modules()

    def load_all_modules(self, path=DATA_DIR + MODULE_PATH):
        #import the modules
        if DEBUG:
            self._print("Loading modules...")
        sys.path.append(path)
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)):
                (name, ext) = os.path.splitext(i)
                if ext == ".py":
                    self.load_module(name, True)
            elif os.path.isdir(os.path.join(path, i)):
                pass

    def init_all_modules(self):
        if DEBUG:
            self._print("Initialising modules...")
        for i in self.modules:
            self.init_module(i)
    
    def load_module(self, module, enabled=True):
        if DEBUG:
            self._print("load %s, enabled %i" % (module, enabled))
        try:
            mod = __import__(module)
            if DEBUG:
                self._print(mod)
            #XXX hack, remove when all modules are ported
            import inspect
            argspec = inspect.getargspec(mod.mod_class.__init__)
            if len(argspec.args) == 4:
                self.modules[module] = (mod.mod_class(self, PLATFORM, self.ui), enabled)
            else:
                self.modules[module] = (mod.mod_class(self, PLATFORM), enabled)
        except Exception, e:
            self._print(e)
            if DEBUG:
                self._print('-'*60)
                self._print(traceback.format_exc())
                self._print('-'*60)

    def init_module(self, module):
        if DEBUG:
            self._print("init %s" % module)
        (mod, enabled) = self.modules[module]
        mod.set_log(self.log)
        self.init_module_ui(mod)
        try:
            if "get_eth_checks" in dir(mod):
                (check, call) = mod.get_eth_checks()
                self.eth_checks.append((check, call, mod.name))
            if "get_ip_checks" in dir(mod):
                (check, call) = mod.get_ip_checks()
                self.ip_checks.append((check, call, mod.name))
            if "get_ip6_checks" in dir(mod):
                (check, call) = mod.get_ip6_checks()
                self.ip6_checks.append((check, call, mod.name))
            if "get_tcp_checks" in dir(mod):
                (check, call) = mod.get_tcp_checks()
                self.tcp_checks.append((check, call, mod.name))
            if "get_udp_checks" in dir(mod):
                (check, call) = mod.get_udp_checks()
                self.udp_checks.append((check, call, mod.name))
            if "get_sctp_checks" in dir(mod):
                (check, call) = mod.get_sctp_checks()
                self.sctp_checks.append((check, call, mod.name))
            if "set_config_dict" in dir(mod):
                cdict = self.load_mod_config(module)
                if cdict:
                    mod.set_config_dict(cdict)
        except Exception, e:
            self._print(e)
            if DEBUG:
                self._print('-'*60)
                self._print(traceback.format_exc())
                self._print('-'*60)
            self._print("failed to start module %s" % mod)
        else:
            self.modules[module] = (mod, True)
    
    def init_module_ui(self, mod):
		pass

    def load_mod_config(self, module):
        def str_(config, section, name, cdict):
            try:
                val = base64.b64decode(config.get(section, name))
                assert(len(val) >= cdict[name]["min"])
                assert(len(val) <= cdict[name]["max"])
            except:
                pass
            else:
                cdict[name]["value"] = val

        def int_(config, section, name, cdict):
            try:
                val = config.getint(section, name)
                assert(val >= cdict[name]["min"])
                assert(val <= cdict[name]["max"])
            except:
                pass
            else:
                cdict[name]["value"] = val

        def float_(config, section, name, cdict):
            try:
                val = config.getfloat(section, name)
                assert(val >= cdict[name]["min"])
                assert(val <= cdict[name]["max"])
            except:
                pass
            else:
                cdict[name]["value"] = val

        (mod, en) = self.modules[module]
        try:
            if "get_config_dict" in dir(mod):
                cdict = mod.get_config_dict()
                file = CONFIG_PATH + "/" + module +".cfg"
                if os.path.exists(file):
                    config = ConfigParser.RawConfigParser()
                    config.read(file)
                    for i in cdict:
                        {   "str" : str_,
                            "int" : int_,
                            "float" : float_    }[cdict[i]["type"]](config, module, i, cdict)
                    if DEBUG:
                        self._print("conf %i from %s" % (len(cdict), file))
                    return cdict
        except Exception, e:
            self._print(e)
            if DEBUG:
                self._print('-'*60)
                self._print(traceback.format_exc())
                self._print('-'*60)
        return None

    def start_module(self, module):
        (mod, en) = self.modules[module]
        if en:
            try:
                if "set_ip" in dir(mod):
                    mod.set_ip(self.ip, self.mask)
            except Exception, e:
                self._print(e)
                if DEBUG:
                    self._print('-'*60)
                    self._print(traceback.format_exc())
                    self._print('-'*60)
            try:
                if "set_ip6" in dir(mod):
                    mod.set_ip6(self.ip6, self.mask6, self.ip6_ll, self.mask6_ll)
            except Exception, e:
                self._print(e)
                if DEBUG:
                    self._print('-'*60)
                    self._print(traceback.format_exc())
                    self._print('-'*60)
            try:
                if "set_dnet" in dir(mod):
                    if self.dnet_thread:
                        mod.set_dnet(self.dnet_thread)
                    else:
                        mod.set_dnet(dnet_thread_offline())
                    
            except Exception, e:
                self._print(e)
                if DEBUG:
                    self._print('-'*60)
                    self._print(traceback.format_exc())
                    self._print('-'*60)
            try:
                if "set_fw" in dir(mod):
                    mod.set_fw(self.fw)
            except Exception, e:
                self._print(e)
                if DEBUG:
                    self._print('-'*60)
                    self._print(traceback.format_exc())
                    self._print('-'*60)
            try:
                if "set_int" in dir(mod):
                    mod.set_int(self.interface)
            except Exception, e:
                self._print(e)
                if DEBUG:
                    self._print('-'*60)
                    self._print(traceback.format_exc())
                    self._print('-'*60)
            try:
                mod.start_mod()
            except Exception, e:
                self._print(e)
                if DEBUG:
                    self._print('-'*60)
                    self._print(traceback.format_exc())
                    self._print('-'*60)

    def shut_module(self, module, delete=False):
        if DEBUG:
            self._print("shut %s" % module)
        (mod, enabled) = self.modules[module]
        mod.shut_mod()
        self.shut_module_ui(mod)
        if "get_eth_checks" in dir(mod):
            for i in self.eth_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.eth_checks.remove(i)
        if "get_ip_checks" in dir(mod):
            for i in self.ip_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.ip_checks.remove(i)
        if "get_ip6_checks" in dir(mod):
            for i in self.ip6_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.ip6_checks.remove(i)
        if "get_tcp_checks" in dir(mod):
            for i in self.tcp_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.tcp_checks.remove(i)
        if "get_udp_checks" in dir(mod):
            for i in self.udp_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.udp_checks.remove(i)
        if "get_sctp_checks" in dir(mod):
            for i in self.sctp_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.sctp_checks.remove(i)
        self.modules[module] = (mod, False)
        if delete:
            del self.modules[modules]
    
    def shut_module_ui(self, mod):
		pass
        
    def update_devices(self):
        self.devices = {}
        devs = pcap.findalldevs()
        for (name, descr, addr, flags) in devs:
            try:
                test = dnet.eth(name)
                mac = test.get()
                self.devices[name] = { 'mac' : mac, 'ip4' : [], 'ip6' : [], 'descr' : descr, 'flags' : flags }
            except:
                pass
            else:
                if len(addr) > 1:
                    for (ip, mask, net, gw) in addr:
                        try:
                            dnet.ip_aton(ip)
                            addr_dict = {}
                            addr_dict['ip'] = ip
                            addr_dict['mask'] = mask
                            addr_dict['net'] = net
                            addr_dict['gw'] = gw
                            self.devices[name]['ip4'].append(addr_dict)
                        except:
                            pass                            
                        try:
                            dnet.ip6_aton(ip)
                            addr_dict = {}
                            addr_dict['ip'] = ip
                            if PLATFORM == "Windows" and mask is None:
                                addr_dict['mask'] = "ffff:ffff:ffff:ffff::"
                            else:
                                addr_dict['mask'] = mask
                            addr_dict['net'] = net
                            addr_dict['gw'] = gw
                            if ip.startswith("fe80:"):
                                addr_dict['linklocal'] = True
                            else:
                                addr_dict['linklocal'] = False
                            self.devices[name]['ip6'].append(addr_dict)
                        except:
                            pass
                else:
                    #????
                    pass
    
    def shutdown(self):
        try:
            for i in self.modules.keys():
                (module, enabled) = self.modules[i]
                module.shut_mod()
            if self.pcap_thread:
                self.pcap_thread.quit()
            if self.dnet_thread:
                self.dnet_thread.quit()
            if PLATFORM == "Linux" and self.netcfg_configured:
                self.netcfg.unexecute_l3()
                self.netcfg.unexecute_l2()
                self.netcfg.unexecute_br()
        except Exception, e:
            self._print(e)
            if DEBUG:
                self._print('-'*60)
                self._print(traceback.format_exc())
                self._print('-'*60)

	def quit(self, data):
		sys.exit(1)
    
    def error(self, msg):
        print(msg)
        sys.exit(1)
    
    def log(self, msg):
        self._print(msg)
    
    def _print(self, msg):
        print(msg)

    def check(self):
        if PLATFORM == "Linux" or PLATFORM == "FreeBSD" or PLATFORM == "Darwin":
            if os.geteuid() != 0:
                self.error("You must be root to run this script.")
                sys.exit(1)
            try:
                import imp
                fp, pathname, (suffix, _, _) = imp.find_module('pcap')
                if suffix == '.so':     # this is pypcap
                    fp.close()
                    filename = os.path.dirname(pathname)+"/pcap.py"
                    if os.path.exists(filename):
                        with open(filename) as fp:
                            pcap = imp.load_module("pcap", fp, filename, ('.py', 'U', 1))
                else:
                    import pcap
                    if 'pcapObject' not in dir(pcap):
                        self.error("Be sure you have pylibpcap and not pypcap installed")
                        sys.exit(1)
            except:
                self.error("Please install pylibpcap to run Loki.")
                sys.exit(1)
        elif PLATFORM == "Windows":
            try:
                import pcap
            except:
                self.error("Please install WinPcap to run Loki.")
        else:
            self.error("%s is not supported yet." % (PLATFORM))
            sys.exit(1)
        return pcap
