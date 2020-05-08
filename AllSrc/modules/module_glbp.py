#       module_glbp.py
#       
#       Copyright 2013 Daniel Mende <dmende@ernw.de>
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

import struct
import threading
import time

import dnet
import dpkt

import gobject
import gtk
import gtk.glade

GLBP_VERSION = 1
GLBP_PORT = 3222
GLBP_MULTICAST_ADDRESS = "224.0.0.102"
GLBP_MULTICAST_MAC = "01:00:5e:00:00:66"

class glbp_packet(object):
    #~                     1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |   Version     |   Unknown1    |             Group             |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |            Unknown2           |           Owner MAC           |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                           Owner MAC                           |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    def __init__(self, group=None, owner_mac=None, tlvs=[]):
        self.group = group
        self.owner_mac = owner_mac
        self.tlvs = tlvs
    
    def render(self):
        tlv_data = ""
        for t in self.tlvs:
            tlv_data += t.render()
        return struct.pack("!BxHxx6s", GLBP_VERSION, self.group, self.owner_mac) + tlv_data 
    
    def parse(self, data):
        (self.group, self.owner_mac) = struct.unpack("!xxHxx6s", data[:12])
        return data[12:]

class glbp_tlv(object):
    #~                     1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |     Type      |     Length    |           Value ...           |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    TYPE_HELLO = 1
    TYPE_REQ_RESP = 2
    TYPE_AUTH = 3
    TYPE_NONCE = 4
    
    def __init__(self, tlv_type=None):
        self.tlv_type = tlv_type
        
    def render(self, data):
        return struct.pack("!BB", self.tlv_type, len(data)+2) + data
    
    def parse(self, data):
        (self.tlv_type, self.tlv_length) = struct.unpack("!BB", data[:2])
        return data[2:]
        
class glbp_tlv_hello(glbp_tlv):
    #~                     1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |   Unknown1    |     State     |   Unknown2    |    Priority   |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |            Unknown3           |        Hello Intervall        |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |        Hello Intervall        |         Hold Intervall        |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |         Hold Intervall        |           Redirect            |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |            Timeout            |           Unknown4            |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |  Address Type | Address Length|          Address ...          |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    STATE_LISTEN = 4
    STATE_SPEAK = 8
    STATE_STANDBY = 16
    STATE_ACTIVE = 32
    
    def __init__(self, state=None, prio=None, hello_int=None, hold_int=None,
                 redirect=None, timeout=None, addr_type=None, addr_len=None,
                 addr=None):
        self.state = state
        self.prio = prio
        self.hello_int = hello_int
        self.hold_int = hold_int
        self.redirect = redirect
        self.timeout = timeout
        self.addr_type = addr_type
        self.addr_len = addr_len
        self.addr = addr
        glbp_tlv.__init__(self, glbp_tlv.TYPE_HELLO)
    
    def render(self):
        return glbp_tlv.render(self, struct.pack("!xBxBxxIIHHxxBB", self.state, self.prio, self.hello_int, self.hold_int,
                                                 self.redirect, self.timeout, self.addr_type, self.addr_len) + self.addr)
    
    def parse(self, data):
        data = glbp_tlv.parse(self, data)
        (self.state, self.prio, self.hello_int, self.hold_int, self.redirect, self.timeout, self.addr_type, self.addr_len) = \
            struct.unpack("!xBxBxxIIHHxxBB", data[:22])
        self.addr = data[22:22+self.addr_len]
        return data[22+self.addr_len:]

class glbp_tlv_req_resp(glbp_tlv):
    #~                     1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |   Forwarder   |   VF State    |    Unknown    |    Priority   |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |    Weight     |                   Unknown2                    |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                           Unknown2                            |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                         Virtual MAC                           |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |         Virtual MAC           |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    def __init__(self, forwarder=None, state=None, prio=None, weight=None, vmac=None):
        self.forwarder = forwarder
        self.state = state
        self.prio = prio
        self.weight = weight
        self.vmac = vmac
        self.unknown = None
        self.unknown2 = None
        glbp_tlv.__init__(self, glbp_tlv.TYPE_REQ_RESP)
    
    def __eq__(self, other):
        return self.vmac == other.vmac

    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __hash__(self):
        return hash(self.vmac)
    
    def render(self):
        if not self.unknown is None:
            return glbp_tlv.render(self, struct.pack("!BBBBB7s6s", self.forwarder, self.state, self.unknown, self.prio, self.weight, self.unknown2, self.vmac))
        return glbp_tlv.render(self, struct.pack("!BBxBB7x6s", self.forwarder, self.state, self.prio, self.weight, self.vmac))
        
    def parse(self, data):
        data = glbp_tlv.parse(self, data)
        (self.forwarder, self.state, self.unknown, self.prio, self.weight, self.unknown2, self.vmac) = struct.unpack("!BBBBB7s6s", data[:18])
        return data[18:]
        
class glbp_tlv_auth(glbp_tlv):
    #~                     1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |     Type      |     Length    |           Secret ...          |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    TYPE_PLAIN = 1
    TYPE_MD5_STRING = 2
    TYPE_MD5_CHAIN = 3
    
    def __init__(self, auth_type=None, secret=None):
        self.auth_type = auth_type
        self.secret = secret
        glbp_tlv.__init__(self, glbp_tlv.TYPE_AUTH)
        
    def render(self):
        return glbp_tlv.render(self, struct.pack("!BB", self.auth_type, len(self.secret)) + self.secret)
        
    def parse(self, data):
        data = glbp_tlv.parse(self, data)
        (self.auth_type, length) = struct.unpack("!BB", data[:2])
        self.secret = data[2:2+length]
        return data[self.tlv_length-2:]

class glbp_tlv_nonce(glbp_tlv):
    def __init__(self):
        glbp_tlv.__init__(self, glbp_tlv.TYPE_NONCE)

class glbp_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True

    def run(self):
        self.parent.log("GLBP: Thread started")
        while self.running:
            for i in self.parent.peers:
                (iter, pkg, hello, req_resp, auth, state, arp) = self.parent.peers[i]
                if state:
                    glbp = glbp_packet(pkg.group, self.parent.mac)
                    glbp_hello = glbp_tlv_hello(glbp_tlv_hello.STATE_ACTIVE, 255, hello.hello_int, hello.hold_int,
                                        hello.redirect, hello.timeout, hello.addr_type, hello.addr_len, hello.addr)
                    reqs = ""
                    for req in req_resp:
                        req.prio = 255
                        req.weight = 255
                        reqs += req.render()
                    
                    if not auth is None:
                        if auth.auth_type == glbp_tlv_auth.TYPE_PLAIN:
                            data = glbp.render() + auth.render() + glbp_hello.render() + reqs
                        elif auth.auth_type == glbp_tlv_auth.TYPE_MD5_STRING:
                            nonce = "\x00\x01\x02\x03\x04\x05\x06\x07"
                            data = glbp_tlv_nonce().render(nonce) + glbp_hello.render() + reqs
                            import hashlib
                            m = hashlib.md5()
                            m.update(data)
                            auth.secret = m.digest()
                            data = glbp.render() + auth.render() + data
                    else:
                        data = glbp.render() + glbp_hello.render() + reqs
                    udp_hdr = dpkt.udp.UDP( sport=GLBP_PORT,
                                            dport=GLBP_PORT,
                                            data=data
                                            )
                    udp_hdr.ulen += len(udp_hdr.data)
                    ip_hdr = dpkt.ip.IP(    ttl=255,
                                            p=dpkt.ip.IP_PROTO_UDP,
                                            src=self.parent.ip,
                                            dst=dnet.ip_aton(GLBP_MULTICAST_ADDRESS),
                                            data=str(udp_hdr)
                                            )
                    ip_hdr.len += len(ip_hdr.data)
                    eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(GLBP_MULTICAST_MAC),
                                                        src=self.parent.mac,
                                                        type=dpkt.ethernet.ETH_TYPE_IP,
                                                        data=str(ip_hdr)
                                                        )
                    self.parent.dnet.send(str(eth_hdr))
                    if arp:
                        if arp < 4:
                            src_mac = self.parent.mac
                            brdc_mac = dnet.eth_aton("ff:ff:ff:ff:ff:ff")
                            stp_uplf_mac = dnet.eth_aton("01:00:0c:cd:cd:cd")
                            ip = hello.addr #struct.pack("!I", hello.addr)
                            arp_hdr = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                                pro=dpkt.arp.ARP_PRO_IP,
                                                op=dpkt.arp.ARP_OP_REPLY,
                                                sha=src_mac,
                                                spa=ip,
                                                tha=brdc_mac,
                                                tpa=ip
                                                )
                            eth_hdr = dpkt.ethernet.Ethernet(   dst=brdc_mac,
                                                                src=src_mac,
                                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                                data=str(arp_hdr)
                                                                )
                            self.parent.dnet.send(str(eth_hdr))

                            arp_hdr = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                                pro=dpkt.arp.ARP_PRO_IP,
                                                op=dpkt.arp.ARP_OP_REPLY,
                                                sha=src_mac,
                                                spa=ip,
                                                tha=stp_uplf_mac,
                                                tpa=ip
                                                )
                            eth_hdr = dpkt.ethernet.Ethernet(   dst=stp_uplf_mac,
                                                                src=src_mac,
                                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                                data=str(arp_hdr)
                                                                )
                            self.parent.dnet.send(str(eth_hdr))
                        self.parent.peers[i] = (iter, pkg, hello, req_resp, auth, state, arp - 1)
            time.sleep(1)
        self.parent.log("GLBP: Thread terminated")

    def shutdown(self):
        self.running = False

class mod_class(object):
    STORE_SRC_ROW = 0
    STORE_IP_ROW = 1
    STORE_PRIO_ROW = 2
    STORE_STATE_ROW = 3
    STORE_AUTH_ROW = 4
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "glbp"
        self.group = "HOT-STANDBY"
        self.gladefile = "/modules/module_glbp.glade"
        self.treestore = gtk.TreeStore(str, str, int, str, str)
        self.thread = None

    def start_mod(self):
        self.peers = {}
        self.thread = glbp_thread(self)

    def shut_mod(self):
        if self.thread:
            if self.thread.is_alive():
                self.thread.shutdown()
        self.treestore.clear()
        
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_get_button_clicked" : self.on_get_button_clicked,
                "on_release_button_clicked" : self.on_release_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.treeview = self.glade_xml.get_widget("treeview")
        self.treeview.set_model(self.treestore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Source")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_SRC_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_IP_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Priority")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_PRIO_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Status")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_STATE_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Auth")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_AUTH_ROW)
        self.treeview.append_column(column)

        self.arp_checkbutton = self.glade_xml.get_widget("arp_checkbutton")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.dport == GLBP_PORT:
            return (True, True)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        if ip.src != self.ip:
            pkg = glbp_packet()
            data = pkg.parse(str(udp.data))
            req_resp = []
            auth = None
            nonce = None
            auth_str = "Unauthenticated"
            while len(data) > 0:
                #~ print "len: %d data: %s" % (len(data), data.encode("hex"))
                tlv = glbp_tlv()
                tlv.parse(data)
                if tlv.tlv_type == glbp_tlv.TYPE_HELLO:                    
                    hello = glbp_tlv_hello()
                    data = hello.parse(data)
                elif tlv.tlv_type == glbp_tlv.TYPE_REQ_RESP:
                    tmp = glbp_tlv_req_resp()
                    data = tmp.parse(data)
                    if not tmp.vmac == "\x00\x00\x00\x00\x00\x00":
                        req_resp.append(tmp)
                elif tlv.tlv_type == glbp_tlv.TYPE_AUTH:
                    auth = glbp_tlv_auth()
                    data = auth.parse(data)
                    if auth.auth_type == glbp_tlv_auth.TYPE_PLAIN:
                        auth_str = "Plaintext: '%s'" % auth.secret[:-1]
                    elif auth.auth_type == glbp_tlv_auth.TYPE_MD5_STRING:
                        auth_str = "MD5 String: '%s'" % auth.secret.encode("hex")
                    elif auth.auth_type == glbp_tlv_auth.TYPE_MD5_CHAIN:
                        auth_str = "MD5 Chain: '%s'" % auth.secret.encode("hex")
                    else:
                        auth_str = "Unknown"
                else:
                    #~ print "type: %d len: %d" % (tlv.tlv_type, tlv.tlv_length)
                    data = data[tlv.tlv_length:]
            try:
                src = dnet.ip_ntoa(ip.src)
            except:
                pass
            
            if ip.src in self.peers:
                (iter, _, _, req_resp_old, _, _, _) = self.peers[ip.src]
                for i in req_resp:
                    if not i in req_resp_old:
                        req_resp_old.append(i)
                        self.treestore.append(iter, ["", "", i.weight, dnet.eth_ntoa(i.vmac), ""])
            else:
                iter = self.treestore.append(None, [src, dnet.ip_ntoa(hello.addr), hello.prio, "Seen", auth_str])
                for req in req_resp:
                    self.treestore.append(iter, ["", "", req.weight, dnet.eth_ntoa(req.vmac), ""])
                self.peers[ip.src] = (iter, pkg, hello, req_resp, auth, False, False)
                self.log("GLBP: Got new peer %s" % (src))

    # SIGNALS #

    def on_get_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            peer = dnet.ip_aton(model.get_value(iter, self.STORE_SRC_ROW))
            (iter, pkg, hello, req_resp, auth, run, arp) = self.peers[peer]
            if self.arp_checkbutton.get_active():
                arp = 13
            else:
                arp = 0
            self.peers[peer] = (iter, pkg, hello, req_resp, auth, True, arp)
            model.set_value(iter, self.STORE_STATE_ROW, "Taken")
        if not self.thread.is_alive():
            self.thread.start()

    def on_release_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            peer = dnet.ip_aton(model.get_value(iter, self.STORE_SRC_ROW))
            (iter, pkg, hello, req_resp, auth, run, arp) = self.peers[peer]
            self.peers[peer] = (iter, pkg, hello, req_resp, auth, False, arp)
            model.set_value(iter, self.STORE_STATE_ROW, "Released")


