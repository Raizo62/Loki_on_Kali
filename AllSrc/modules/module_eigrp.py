#       module_eigrp.py
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

import os
import sys
import signal
import threading
import socket
import struct
import time
import cmd
#import md5

import dnet
import dpkt
import pcap

import gobject
import gtk
import gtk.glade

EIGRP_PROTOCOL_NUMBER = 0x58
EIGRP_MULTICAST_ADDRESS = "224.0.0.10"
EIGRP_MULTICAST_MAC = "01:00:5e:00:00:0a"

DEFAULT_HOLD_TIME = 5

SO_BINDTODEVICE	= 25

### HELPER_FUNKTIONS ###

def ichecksum_func(data, sum=0):
    ''' Compute the Internet Checksum of the supplied data.  The checksum is
    initialized to zero.  Place the return value in the checksum field of a
    packet.  When the packet is received, check the checksum, by passing
    in the checksum field of the packet and the data.  If the result is zero,
    then the checksum has not detected an error.
    '''
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in xrange(0,len(data),2):
        if i + 1 >= len(data):
            sum += ord(data[i]) & 0xFF
        else:
            w = ((ord(data[i]) << 8) & 0xFF00) + (ord(data[i+1]) & 0xFF)
            sum += w

    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # one's complement the result
    sum = ~sum

    return sum & 0xFFFF

### EIGRP_PACKET_STRUCTURES ###

class eigrp_address:
    def __init__(self, addr, len=4):
        self.addr = dnet.ip_aton(addr)
        self.len = len

    def render(self):
        return self.addr + struct.pack("!B", self.len)

class eigrp_packet:
    EIGRP_VERSION = 2
    EIGRP_OPTCODE_UPDATE = 1
    EIGRP_OPTCODE_RESERVED = 2
    EIGRP_OPTCODE_QUERY = 3
    EIGRP_OPTCODE_REPLY = 4
    EIGRP_OPTCODE_HELLO = 5
    EIGRP_FLAGS_INIT = 0x00000001
    EIGRP_FLAGS_COND_RECV = 0x00000008
        
    def __init__(self, optcode = None, flags = None, seq_num = None, ack_num = None, as_num = None, data = None):
        self.optcode = optcode
        self.checksum = 0
        self.flags = flags
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.as_num = as_num
        self.data = data

    def parse(self, data):
        payload = data[20:]
        self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num = struct.unpack("!xBHIIII", data[:20])
        return payload

    def render(self):
        data = ""
        auth = None
        auth_pos = None
        if self.data:
            for i in self.data:
                if i.__class__ == eigrp_authentication:
                    auth = i
                    auth_pos = len(data)
                else:
                    data += i.render()
            if auth:
                #data = data[0:auth_pos] + auth.render(struct.pack("!BBHIIII", self.EIGRP_VERSION, self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num) + data) + data[auth_pos:]
                data = data[0:auth_pos] + auth.render(struct.pack("!BBIIII", self.EIGRP_VERSION, self.optcode, self.flags, self.seq_num, self.ack_num, self.as_num)) + data[auth_pos:]
                #data = data[0:auth_pos] + auth.render(struct.pack("!BIII", self.optcode, self.as_num, self.flags, self.seq_num) ) + data[auth_pos:]
        ret = struct.pack("!BBHIIII", self.EIGRP_VERSION, self.optcode, 0, self.flags, self.seq_num, self.ack_num, self.as_num)
        self.checksum = ichecksum_func(ret + data)
        return struct.pack("!BBHIIII", self.EIGRP_VERSION, self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num) + data

class eigrp_tlv:
    EIGRP_TYPE_PARAM = 0x0001
    EIGRP_TYPE_AUTH = 0x0002
    EIGRP_TYPE_SEQENCE = 0x0003
    EIGRP_TYPE_VERSION = 0x0004
    EIGRP_TYPE_NEXT_MULTICAST_SEQ = 0x0005
    EIGRP_TYPE_INTERNAL_ROUTE = 0x0102
    EIGRP_TYPE_EXTERNAL_ROUTE = 0x0103
    
    def __init__(self, type=None):
        self.type = type
        self.len = None
        self.data = None

    def parse(self, data):
        self.type, self.len = struct.unpack("!HH", data[:4])
        self.data = data[4:self.len]
        if self.len >= len(data):
            return False
        else:
            return data[self.len:]

    def render(self, data=None):
        if data and not self.data:
            return struct.pack("!HH", self.type, len(data) + 4) + data
        if not data and self.data:
            return struct.pack("!HH", self.type, self.len) + self.data

class eigrp_param(eigrp_tlv):
    def __init__(self, k1, k2, k3, k4, k5, hold_time):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_PARAM)
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.k4 = k4
        self.k5 = k5
        self.hold_time = hold_time

    def render(self):
        return eigrp_tlv.render(self, struct.pack("!BBBBBxH", self.k1, self.k2, self.k3, self.k4, self.k5, self.hold_time))

class eigrp_authentication(eigrp_tlv):
    def __init__(self, key, hash="md5", key_id = 1):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_AUTH)
        self.key = key
        self.hash = hash
        self.key_id = key_id

    def render(self, data):
        #if self.hash == "md5":
            #m = md5.new()
            #m.update(self.key)
            #m.update(data)
            ##m.update(self.key)
            #return eigrp_tlv.render(self, struct.pack("!4BI12B", 0x00, 0x02, 0x00, 0x10, self.key_id, 0x00, 0x00, 0x00, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + m.digest())
        #else:
            return ""

class eigrp_sequence(eigrp_tlv):
    def __init__(self, addr):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_SEQENCE)
        self.addr = addr

    def render(self):
        return eigrp_tlv.render(self, addr.render())

class eigrp_next_multicast_seq(eigrp_tlv):
    def __init__(self, seq):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_NEXT_MULTICAST_SEQ)
        self.seq = seq

    def render(self):
        return eigrp_tlv.render(self, struct.pack("!I", self.seq))

class eigrp_version(eigrp_tlv):
    def __init__(self, ios_ver=0xc04, eigrp_ver=0x102):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_VERSION)
        self.ios_ver = ios_ver
        self.eigrp_ver = eigrp_ver

    def render(self):
        return eigrp_tlv.render(self, struct.pack("!HH", self.ios_ver, self.eigrp_ver))

class eigrp_internal_route(eigrp_tlv):
    def __init__(self, next_hop = None, delay = None, bandwidth = None, mtu = None, hop_count = None, reliability = None, load = None, prefix = None, dest = None):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_INTERNAL_ROUTE)
        if next_hop:
            self.next_hop = dnet.ip_aton(next_hop)
        else:
            self.next_hop = next_hop
        self.delay = delay
        self.bandwidth = bandwidth
        self.mtu = mtu
        self.hop_count = hop_count
        self.reliability = reliability
        self.load = load
        self.prefix = prefix
        if dest:
            self.dest = dnet.ip_aton(dest)
        else:
            self.dest = dest

    def render(self):
        mtu_and_hop = (self.mtu << 8) + self.hop_count
        dest = ""
        for x in xrange(0, self.prefix / 8):
            dest += self.dest[x:x+1]
        return eigrp_tlv.render(self, self.next_hop + struct.pack("!IIIBBxxB", self.delay, self.bandwidth, mtu_and_hop, self.reliability, self.load, self.prefix) + dest)

    def parse(self, data):
        self.next_hop = dnet.ip_ntoa(data[:4])
        (self.delay, self.bandwidth, mtu_and_hop, self.reliability, self.load, self.prefix) = struct.unpack("!IIIBBxxB", data[4:21])
        self.mtu = mtu_and_hop >> 8
        self.hop_count = mtu_and_hop & 0x000000ff
        self.dest = dnet.ip_ntoa(data[21:] + '\0' * (25 - len(data)))

class eigrp_external_route(eigrp_tlv):
    EIGRP_EXTERNAL_PROTO_OSPF = 6
    
    def __init__(self, next_hop = None, originating_router = None, originating_as = None, arbitrary_tag = None, external_metric = None, external_proto = None, flags = None, delay = None, bandwidth = None, mtu = None, hop_count = None, reliability = None, load = None, prefix = None, dest = None):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_EXTERNAL_ROUTE)
        if next_hop:
            self.next_hop = dnet.ip_aton(next_hop)
        else:
            self.next_hop = next_hop
        if originating_router:
            self.originating_router = dnet.ip_aton(originating_router)
        else:
            self.originating_router = originating_router
        self.originating_as = originating_as
        self.arbitrary_tag = arbitrary_tag
        self.external_metric = external_metric
        self.external_proto = external_proto
        self.flags = flags
        self.delay = delay
        self.bandwidth = bandwidth
        self.mtu = mtu
        self.hop_count = hop_count
        self.reliability = reliability
        self.load = load
        self.prefix = prefix
        if dest:
            self.dest = dnet.ip_aton(dest)
        else:
            self.dest = dest

    def render(self):
        mtu_and_hop = (self.mtu << 8) + self.hop_count
        dest = ""
        for x in xrange(0, self.prefix / 8):
            dest += self.dest[x:x+1]
        return eigrp_tlv.render(self, self.next_hop + self.originating_router + struct.pack("!IIIxxBBIIIBBxxB", self.originating_as, self.arbitrary_tag, self.external_metric, self.external_proto, self.flags, self.delay, self.bandwidth, mtu_and_hop, self.reliability, self.load, self.prefix) + dest)

    def parse(self, data):
        self.next_hop = dnet.ip_ntoa(data[:4])
        self.originating_router = dnet.ip_ntoa(data[4:8])
        (self.originating_as, self.arbitrary_tag, self.external_metric, self.external_proto, self.flags, self.delay, self.bandwidth, mtu_and_hop, self.reliability, self.load, self.prefix) = struct.unpack("!IIIxxBBIIIBBxxB", data[8:41])
        self.mtu = mtu_and_hop >> 8
        self.hop_count = mtu_and_hop & 0x000000ff
        self.dest = dnet.ip_ntoa(data[41:] + '\0' * (45 - len(data)))

### THREAD_CLASSES ###

class eigrp_hello_thread(threading.Thread):
    def __init__(self, parent, interface, as_num, auth=None):
        threading.Thread.__init__(self)
        self.parent = parent
        self.interface = interface
        self.running = True
        self.as_num = as_num
        self.auth = auth

    def send_multicast(self, data):
        ip_hdr = dpkt.ip.IP(    ttl=2,
                                p=dpkt.ip.IP_PROTO_EIGRP,
                                src=self.parent.address,
                                dst=dnet.ip_aton(EIGRP_MULTICAST_ADDRESS),
                                data=data
                                )
        ip_hdr.len += len(ip_hdr.data)
        eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(EIGRP_MULTICAST_MAC),
                                            src=self.parent.mac,
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=str(ip_hdr)
                                            )
        self.parent.dnet.send(str(eth_hdr))

    def hello(self):
        timer = DEFAULT_HOLD_TIME
        while self.running:
            if timer == DEFAULT_HOLD_TIME:
                timer = 0
                params = eigrp_param(1, 0, 1, 0, 0, 15)
                version = eigrp_version(self.parent.ios_ver, self.parent.eigrp_ver) #(0xc02, 0x300)
                args = [params, version]
                if self.auth:
                    args.insert(0, self.auth)
                msg = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_HELLO, 0, 0, 0, self.as_num, args)
                data = msg.render()
                if not self.parent.spoof:
                    self.send_multicast(data)
                else:
                    ip_hdr = dpkt.ip.IP(    ttl=2,
                                            p=dpkt.ip.IP_PROTO_EIGRP,
                                            src=self.parent.spoof,
                                            dst=dnet.ip_aton(EIGRP_MULTICAST_ADDRESS),
                                            data=data
                                            )
                    ip_hdr.len += len(ip_hdr.data)
                    eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(EIGRP_MULTICAST_MAC),
                                                        src=self.parent.mac,
                                                        type=dpkt.ethernet.ETH_TYPE_IP,
                                                        data=str(ip_hdr)
                                                        )
                    self.parent.dnet.send(str(eth_hdr))
            timer += 1
            time.sleep(1)

    def run(self):
        self.hello()
        self.parent.log("EIGRP: Hello thread on %s terminated" % (self.interface))

    def quit(self):
        self.running = False

class eigrp_peer(threading.Thread):
    def __init__(self, parent, mac, peer, as_num, auth=None):
        threading.Thread.__init__(self)
        self.parent = parent
        self.sem = threading.Semaphore()
        self.mac = mac
        self.peer = peer
        self.as_num = as_num
        self.sock = None
        self.msg = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_UPDATE, eigrp_packet.EIGRP_FLAGS_INIT, 0, 0, self.as_num, None)
        self.running = True
        self.seq_num = 0
        self.auth = auth

    def send_unicast(self, mac, ip, data):
        ip_hdr = dpkt.ip.IP(    ttl=2,
                                p=dpkt.ip.IP_PROTO_EIGRP,
                                src=self.parent.address,
                                dst=ip,
                                data=data
                                )
        ip_hdr.len += len(ip_hdr.data)
        eth_hdr = dpkt.ethernet.Ethernet(   dst=mac,
                                            src=self.parent.mac,
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=str(ip_hdr)
                                            )
        self.parent.dnet.send(str(eth_hdr))

    def send(self):
        while self.running:
            if self.parent.hello_thread and self.parent.hello_thread.is_alive() or self.parent.goodbye_thread and self.parent.goodbye_thread.is_alive():
                self.sem.acquire()
                if self.msg:
                    if self.auth:
                        self.msg.data.insert(0, self.auth)
                    if not self.msg.optcode == eigrp_packet.EIGRP_OPTCODE_HELLO:
                        self.msg.seq_num = self.seq_num
                        self.seq_num += 1
                    data = self.msg.render()
                    if not self.parent.spoof:
                        self.send_unicast(self.mac, self.peer, data)
                    else:
                        ip_hdr = dpkt.ip.IP(    ttl=2,
                                                p=dpkt.ip.IP_PROTO_EIGRP,
                                                src=self.parent.spoof,
                                                dst=self.peer,
                                                data=data
                                                )
                        ip_hdr.len += len(ip_hdr.data)
                        eth_hdr = dpkt.ethernet.Ethernet(   dst=self.mac,
                                                            src=self.parent.mac,
                                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                                            data=str(ip_hdr)
                                                            )
                        self.parent.dnet.send(str(eth_hdr))
                    self.msg = None
                self.sem.release()
                time.sleep(0.1)
            else:
                time.sleep(1)

    def input(self, data):
        packet = eigrp_packet()
        payload = packet.parse(data)
        if not packet.optcode == eigrp_packet.EIGRP_OPTCODE_HELLO:
            reply = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_HELLO, 0, 0, packet.seq_num, self.as_num)
            self.seq_num = packet.seq_num + 1
            self.sem.acquire()
            self.msg = reply
            self.sem.release()
            if packet.optcode == eigrp_packet.EIGRP_OPTCODE_UPDATE and len(payload) > 4:
                tlv = eigrp_tlv()
                while payload:
                    payload = tlv.parse(payload)
                    if tlv.type == eigrp_tlv.EIGRP_TYPE_INTERNAL_ROUTE:
                        route = eigrp_internal_route()
                        route.parse(tlv.data)
                        if route.next_hop == "0.0.0.0":
                            route.next_hop = dnet.ip_ntoa(self.peer)
                        route_str = route.dest + "/" + str(route.prefix) + " via " + route.next_hop
                        for i in xrange(self.parent.treestore.iter_n_children(self.iter)):
                            (test_str,) = self.parent.treestore.get(self.parent.treestore.iter_nth_child(self.iter, i), self.parent.TREE_AS_ROW)
                            if test_str == route_str:
                                return
                        self.parent.treestore.append(self.iter, ["INTERNAL_ROUTE", route_str])
                    if tlv.type == eigrp_tlv.EIGRP_TYPE_EXTERNAL_ROUTE:
                        route = eigrp_external_route()
                        route.parse(tlv.data)
                        if route.next_hop == "0.0.0.0":
                            route.next_hop = dnet.ip_ntoa(self.peer)
                        route_str = route.dest + "/" + str(route.prefix) + " via " + route.next_hop + " on AS# " + str(route.originating_as) + ", type " + str(route.external_proto)
                        for i in xrange(self.parent.treestore.iter_n_children(self.iter)):
                            (test_str,) = self.parent.treestore.get(self.parent.treestore.iter_nth_child(self.iter, i), self.parent.TREE_AS_ROW)
                            if test_str == route_str:
                                return
                        self.parent.treestore.append(self.iter, ["EXTERNAL_ROUTE", route_str])

    def update(self, msg):
        self.sem.acquire()
        self.msg = msg
        self.sem.release()
        
    def run(self):
        self.iter = self.parent.treestore.append(None, [dnet.ip_ntoa(self.peer), str(self.as_num)])
        self.send()
        self.parent.log("EIGRP: Peer " + socket.inet_ntoa(self.peer) + " terminated")
        if self.parent.treestore:
            if self.parent.treestore.iter_is_valid(self.iter):
                self.parent.treestore.remove(self.iter)
        del self.parent.peers[self.peer]

    def quit(self):
        self.running = False

class eigrp_goodbye(threading.Thread):
    def __init__(self, parent, peer, as_num):
        threading.Thread.__init__(self)
        self.parent = parent
        self.peer = peer
        self.as_num = as_num
        self.running = True

    def run(self):
        params = eigrp_param(255, 255, 255, 255, 255, 15)
        version = eigrp_version() #(0xc02, 0x300)
        args = [params, version]
        msg = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_HELLO, 0, 0, 0, self.as_num, args)
        while self.running:
            self.parent.peers[self.peer].update(msg)
            self.parent.goodbye_progressbar.pulse()
            time.sleep(1)
        self.parent.log("EIGRP: Goodbye thread terminated")

    def quit(self):
        self.running = False
        
### MODULE_CLASS ###

class mod_class(object):
    TREE_HOST_ROW = 0
    TREE_AS_ROW = 1
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "eigrp"
        self.group = "ROUTING"
        self.gladefile = "/modules/module_eigrp.glade"
        self.treestore = gtk.TreeStore(str, str)
        self.filter = False
        self.hello_thread = None
        self.goodbye_thread = None
        self.peers = None
        #(0xc02, 0x300)
        self.ios_ver = 0xc04
        self.eigrp_ver = 0x102

    def start_mod(self):
        self.hello_thread = None
        self.goodbye_thread = None
        self.spoof = False
        self.auth = None
        self.as_num = None
        self.peers = {}
        self.listen_for_auth = False

    def shut_mod(self):
        if self.hello_thread:
            if self.hello_thread.running:
                self.hello_thread.quit()
        if self.goodbye_thread:
            if self.goodbye_thread.running:
                self.goodbye_thread.quit()
        if self.peers:
            for i in self.peers:
                self.peers[i].quit()
        if self.filter:
                self.log("EIGRP: Removing lokal packet filter for EIGRP")
                if self.platform == "Linux":
                    os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_EIGRP))
                elif self.platform == "Darwin":
                    os.system("ipfw -q delete 31335")
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall del rule name=eigrp")
                else:
                    self.fw.delete(self.ospf_filter)
                self.filter = False
        self.treestore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_hello_togglebutton_toggled" : self.on_hello_togglebutton_toggled,
                "on_spoof_togglebutton_toggled" : self.on_spoof_togglebutton_toggled,
                "on_goodbye_button_clicked" : self.on_goodbye_button_clicked,
                "on_add_button_clicked" : self.on_add_button_clicked,
                "on_del_button_clicked" : self.on_del_button_clicked,
                "on_clear_button_clicked" : self.on_clear_button_clicked,
                "on_update_button_clicked" : self.on_update_button_clicked,
                "on_stop_button_clicked" : self.on_stop_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.hello_togglebutton = self.glade_xml.get_widget("hello_togglebutton")
        self.spoof_togglebutton = self.glade_xml.get_widget("spoof_togglebutton")

        self.interface_entry = self.glade_xml.get_widget("interface_entry")
        self.as_spinbutton = self.glade_xml.get_widget("as_spinbutton")
        self.spoof_entry = self.glade_xml.get_widget("spoof_entry")

        self.update_textview = self.glade_xml.get_widget("update_textview")
        
        self.treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.treeview.set_model(self.treestore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Host")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.TREE_HOST_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("AS")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.TREE_AS_ROW)
        self.treeview.append_column(column)
        self.treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)

        self.goodbye_window = self.glade_xml.get_widget("goodbye_window")
        #self.goodbye_window.set_parent(self.parent.window)
        self.goodbye_label = self.glade_xml.get_widget("goodbye_label")
        self.goodbye_progressbar = self.glade_xml.get_widget("goodbye_progressbar")

        self.notebook = self.glade_xml.get_widget("notebook")

        self.next_hop_entry = self.glade_xml.get_widget("next_hop_entry")
        self.delay_spinbutton = self.glade_xml.get_widget("delay_spinbutton")
        self.bandwidth_spinbutton = self.glade_xml.get_widget("bandwidth_spinbutton")
        self.mtu_spinbutton = self.glade_xml.get_widget("mtu_spinbutton")
        self.hop_count_spinbutton = self.glade_xml.get_widget("hop_count_spinbutton")
        self.reliability_spinbutton = self.glade_xml.get_widget("reliability_spinbutton")
        self.load_spinbutton = self.glade_xml.get_widget("load_spinbutton")
        self.prefix_spinbutton = self.glade_xml.get_widget("prefix_spinbutton")
        self.destination_entry = self.glade_xml.get_widget("destination_entry")

        self.next_hop_entry1 = self.glade_xml.get_widget("next_hop_entry1")
        self.delay_spinbutton1 = self.glade_xml.get_widget("delay_spinbutton1")
        self.bandwidth_spinbutton1 = self.glade_xml.get_widget("bandwidth_spinbutton1")
        self.mtu_spinbutton1 = self.glade_xml.get_widget("mtu_spinbutton1")
        self.hop_count_spinbutton1 = self.glade_xml.get_widget("hop_count_spinbutton1")
        self.reliability_spinbutton1 = self.glade_xml.get_widget("reliability_spinbutton1")
        self.load_spinbutton1 = self.glade_xml.get_widget("load_spinbutton1")
        self.prefix_spinbutton1 = self.glade_xml.get_widget("prefix_spinbutton1")
        self.destination_entry1 = self.glade_xml.get_widget("destination_entry1")

        self.orig_router_entry = self.glade_xml.get_widget("orig_router_entry")
        self.orig_as_spinbutton = self.glade_xml.get_widget("orig_as_spinbutton")
        self.external_metric_spinbutton = self.glade_xml.get_widget("external_metric_spinbutton")
        self.external_id_spinbutton = self.glade_xml.get_widget("external_id_spinbutton")
        
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_ip_checks(self):
        return (self.check_ip, self.input_ip)

    def check_ip(self, ip):
        if ip.p == dpkt.ip.IP_PROTO_EIGRP:
            return (True, False)
        return (False, False)

    def set_ip(self, ip, mask):
        self.address = dnet.ip_aton(ip)
        self.mask = dnet.ip_aton(mask)

    def set_fw(self, fw):
        self.fw = fw

    def set_int(self, interface):
        self.interface = interface
        self.eigrp_filter = {    "device"    : self.interface,
                                 "op"        : dnet.FW_OP_BLOCK,
                                 "dir"       : dnet.FW_DIR_IN,
                                 "proto"     : dpkt.ip.IP_PROTO_EIGRP,
                                 "src"       : dnet.addr("0.0.0.0/0", dnet.ADDR_TYPE_IP),
                                 "dst"       : dnet.addr("0.0.0.0/0", dnet.ADDR_TYPE_IP),
                                 "sport"     : [0, 0],
                                 "dport"     : [0, 0]
                                 }

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    # LISTENING #

    def input_ip(self, eth, ip, timestamp):
        if ip.dst == dnet.ip_aton("224.0.0.10"):
            if ip.src != self.address and ip.src != self.spoof:
                self.disp_multicast(str(ip.data), eth.src, ip.src)
            if self.listen_for_auth and ip.src == self.address:
                self.disp_auth(str(ip.data))
        elif ip.dst == self.address or ip.dst == self.spoof:
            self.disp_unicast(str(ip.data), eth.src, ip.src)

    def disp_auth(self, data):
        packet = eigrp_packet()
        payload = packet.parse(data)
        if packet.optcode == eigrp_packet.EIGRP_OPTCODE_HELLO:
            tlv = eigrp_tlv()
            while True:
                payload = tlv.parse(payload)
                if tlv.type == eigrp_tlv.EIGRP_TYPE_AUTH:
                    self.auth = tlv
                    self.log("EIGRP: Got authentication data from " + socket.inet_ntoa(self.address))
                    self.running = False
                    break
                if not payload:
                    break

    def disp_multicast(self, data, mac, src):
        #print "disp_multicast from " + socket.inet_ntoa(src)
        if src not in self.peers:
            packet = eigrp_packet()
            packet.parse(data)
            #if self.hello_thread and self.hello_thread.is_alive():
            self.add_peer(mac, src, packet.as_num)
        else:
            self.peers[src].input(data)
        
    def disp_unicast(self, data, mac, src):
        #print "disp_unicast from " + socket.inet_ntoa(src)
        if src not in self.peers:
            packet = eigrp_packet()
            packet.parse(data)
            #if self.hello_thread and self.hello_thread.is_alive():
            self.add_peer(mac, src, packet.as_num)
        else:
            self.peers[src].input(data)
        
    # PEER HANDLING #

    def add_peer(self, mac, src, as_num, data=None):
        self.log("EIGRP: Got new peer " + socket.inet_ntoa(src))
        self.peers[src] = eigrp_peer(self, mac, src, as_num, self.auth)
        self.peers[src].start()
        if data:
            self.peers[src].input(data)
            
    # SIGNALS #

    def on_hello_togglebutton_toggled(self, btn):
        if btn.get_property("active"):
            self.as_num = int(self.as_spinbutton.get_value())
            self.as_spinbutton.set_property("sensitive", False)
            if not self.filter:
                self.log("EIGRP: Setting lokal packet filter for EIGRP")
                if self.platform == "Linux":
                    os.system("iptables -A INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_EIGRP))
                elif self.platform == "Darwin":
                    os.system("ipfw -q add 31335 deny eigrp from any to any")
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall add rule name=eigrp dir=in protocol=%i action=block" % dpkt.ip.IP_PROTO_EIGRP)
                else:
                    self.fw.add(self.eigrp_filter)
                self.filter = True
            try:
                self.spoof_togglebutton.set_property("sensitive", False)
                if self.spoof_togglebutton.get_property("active"):
                    self.hello_thread = eigrp_hello_thread(self, self.interface, self.as_num, self.auth)
                else:
                    self.hello_thread = eigrp_hello_thread(self, self.interface, self.as_num, self.auth)
            except Exception, e:
                    self.log("EIGRP: Cant start hello thread on %s: %s" % (self.interface, e))
                    if not self.listen_togglebutton.get_property("active"):
                        self.spoof_togglebutton.set_property("sensitive", True)
                        self.as_entry.set_property("sensitive", True)
                    return
        
            self.hello_thread.start()
            self.log("EIGRP: Hello thread on %s started" % (self.interface))
        else:
            if self.filter:
                self.log("EIGRP: Removing lokal packet filter for EIGRP")
                if self.platform =="Linux":
                    os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_EIGRP))
                elif self.platform == "Darwin":
                    os.system("ipfw -q delete 31335")
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall del rule name=eigrp")
                else:
                    self.fw.delete(self.eigrp_filter)
                self.filter = False
            self.hello_thread.quit()
            self.spoof_togglebutton.set_property("sensitive", True)
            self.as_spinbutton.set_property("sensitive", True)

    def on_spoof_togglebutton_toggled(self, btn):
        if btn.get_property("active"):
            self.spoof = dnet.ip_aton(self.spoof_entry.get_text())
            self.spoof_entry.set_property("sensitive", False)
        else:
            self.spoof_entry.set_property("sensitive", True)
            self.spoof = False

    def on_goodbye_button_clicked(self, data):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) == 1:
            parent = model.iter_parent(model.get_iter(paths[0]))
            if not parent:
                parent = model.get_iter(paths[0])
            host = model.get_value(parent, self.TREE_HOST_ROW)
            peer = dnet.ip_aton(host)
            self.peers[peer].msg = None
            self.goodbye_thread = eigrp_goodbye(self, peer, self.peers[peer].as_num)
            self.goodbye_label.set_label("Sending Goodbye Messages to %s..." % (host))
            self.goodbye_window.show_all()
            self.goodbye_thread.start()
            self.log("EIGRP: Goodbye thread started for %s" % (host)) 

    def on_add_button_clicked(self, data):
        dialog = gtk.MessageDialog(self.parent.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Enter IP Address to add:")
        entry = gtk.Entry(0)
        dialog.vbox.pack_start(entry)
        entry.show()
        ret = dialog.run()
        dialog.destroy()
        if ret == gtk.RESPONSE_OK:
            try:
                peer = entry.get_text()
                arp = dnet.arp()
                mac = arp.get(dnet.addr(peer))
                if not mac:
                    raise Exception("Unable to get mac address")
                self.add_peer(mac.data, dnet.ip_aton(peer), int(self.as_spinbutton.get_value()))
            except Exception, e:
                self.log("EIGRP: Cant add peer %s: %s" % (peer, e))

    def on_del_button_clicked(self, data):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            host = model.get_value(parent, self.TREE_HOST_ROW)
            peer = dnet.ip_aton(host)
            self.peers[peer].quit()

    def on_clear_button_clicked(self, data):
        #self.treestore.clear()
        for i in self.peers:
            self.peers[i].quit()

    def on_update_button_clicked(self, data):
        page = self.notebook.get_current_page()
        if page == 0:
            msg = eigrp_packet( eigrp_packet.EIGRP_OPTCODE_UPDATE,
                                eigrp_packet.EIGRP_FLAGS_COND_RECV,
                                0,
                                0,
                                int(self.as_spinbutton.get_value()),
                                [   eigrp_internal_route(
                                        self.next_hop_entry.get_text(),
                                        int(self.delay_spinbutton.get_value()),
                                        int(self.bandwidth_spinbutton.get_value()),
                                        int(self.mtu_spinbutton.get_value()),
                                        int(self.hop_count_spinbutton.get_value()),
                                        int(self.reliability_spinbutton.get_value()),
                                        int(self.load_spinbutton.get_value()),
                                        int(self.prefix_spinbutton.get_value()),
                                        self.destination_entry.get_text()
                                        )
                                    ]
                                )
        elif page == 1:
            msg = eigrp_packet( eigrp_packet.EIGRP_OPTCODE_UPDATE,
                                eigrp_packet.EIGRP_FLAGS_COND_RECV,
                                0,
                                0,
                                int(self.as_spinbutton.get_value()),
                                [   eigrp_external_route(
                                        self.next_hop_entry1.get_text(),
                                        self.orig_router_entry.get_text(),
                                        int(self.orig_as_spinbutton.get_value()),
                                        0,
                                        int(self.external_metric_spinbutton.get_value()),
                                        int(self.external_id_spinbutton.get_value()),
                                        0,
                                        int(self.delay_spinbutton1.get_value()),
                                        int(self.bandwidth_spinbutton1.get_value()),
                                        int(self.mtu_spinbutton1.get_value()),
                                        int(self.hop_count_spinbutton1.get_value()),
                                        int(self.reliability_spinbutton1.get_value()),
                                        int(self.load_spinbutton1.get_value()),
                                        int(self.prefix_spinbutton1.get_value()),
                                        self.destination_entry1.get_text()
                                        )
                                    ]
                                )
        elif page == 2:
            buffer = self.update_textview.get_buffer()
            text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter())
            if text == "":
                return
            exec("msg = " + text)

        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            host = model.get_value(parent, self.TREE_HOST_ROW)
            self.log("EIGRP: Sending update to %s" % (host))
            peer = dnet.ip_aton(host)
            self.peers[peer].update(msg)
        #~ #bcast
        #~ ip_hdr = dpkt.ip.IP(    ttl=2,
                                #~ p=dpkt.ip.IP_PROTO_EIGRP,
                                #~ src=self.address,
                                #~ dst=dnet.ip_aton(EIGRP_MULTICAST_ADDRESS),
                                #~ data=msg.render()
                                #~ )
        #~ ip_hdr.len += len(ip_hdr.data)
        #~ eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(EIGRP_MULTICAST_MAC),
                                            #~ src=self.mac,
                                            #~ type=dpkt.ethernet.ETH_TYPE_IP,
                                            #~ data=str(ip_hdr)
                                            #~ )
        #~ self.dnet.send(str(eth_hdr))
        
    def on_stop_button_clicked(self, data):
        self.goodbye_thread.quit()
        self.goodbye_window.hide_all()

    def get_config_dict(self):
        return {    "ios_ver" : {   "value" : "0x%x" % self.ios_ver,
                                    "type" : "str",
                                    "min" : 3,
                                    "max" : 6
                                    },
                    "eigrp_ver" : {   "value" : "0x%x" % self.eigrp_ver,
                                      "type" : "str",
                                      "min" : 3,
                                      "max" : 6
                                      }
                    }

    def set_config_dict(self, dict):
        if dict:
            self.ios_ver = int(dict["ios_ver"]["value"], 0)
            self.eigrp_ver = int(dict["eigrp_ver"]["value"], 0)
