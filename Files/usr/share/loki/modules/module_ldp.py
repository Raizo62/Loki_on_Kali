#       module_ldp.py
#       
#       Copyright 2010 Daniel Mende <dmende@ernw.de>
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


import sys
import signal
import threading
import socket
import struct
import time

import dpkt

import gobject
import gtk
import gtk.glade

LDP_PORT = 646
LDP_MULTICAST_ADDRESS = "224.0.0.2"
LDP_VERSION = 1

DEFAULT_HOLD_TIME = 15  #like cisco
DEFAULT_KEEP_ALIVE = 60 #cisco got 180

SO_BINDTODEVICE	= 25

class ldp_msg(object):
    MSG_TYPE_HELLO = 0x0100
    MSG_TYPE_INIT = 0x0200
    MSG_TYPE_KEEPALIVE = 0x0201
    #MSG_TYPE_ADDRESS = 0x0300
    MSG_TYPE_LABEL_MAPPING = 0x0400

    def __init__(self, lsr_id, label_space, msgs):
        self.lsr_id = lsr_id
        self.label_space = label_space
        self.msgs = msgs

    def render(self):
        data = ""
        for x in self.msgs:
            data += x.render()
        return struct.pack("!HH", LDP_VERSION, len(data) + 6) + self.lsr_id + struct.pack("!H", self.label_space) + data;

class ldp_hello_msg(object):
    def __init__(self, id=None, tlvs=None):
        self.id = 0
        self.tlvs = tlvs

    def render(self):
        data = ""
        for x in self.tlvs:
            data += x.render()
        return struct.pack("!HHI", ldp_msg.MSG_TYPE_HELLO, len(data) + 4, self.id) + data

    def parse(self, data):
        (self.id, ) = struct.unpack("!2x2xI", data[:8])
        return data[8:]

class ldp_init_msg(object):
    def __init__(self, id, tlvs):
        self.id = id
        self.tlvs = tlvs

    def render(self):
        data = ""
        for x in self.tlvs:
            data += x.render()
        return struct.pack("!HHI", ldp_msg.MSG_TYPE_INIT, len(data) + 4, self.id) + data

class ldp_keepalive_msg(object):
    def __init__(self, id):
        self.id = id

    def render(self):
        return struct.pack("!HHI", ldp_msg.MSG_TYPE_KEEPALIVE, 4, self.id)

class ldp_label_mapping_msg(object):
    def __init__(self, id, tlvs):
        self.id = id
        self.tlvs = tlvs

    def render(self):
        data = ""
        for x in self.tlvs:
            data += x.render()
        return struct.pack("!HHI", ldp_msg.MSG_TYPE_LABEL_MAPPING, len(data) + 4, self.id) + data

class ldp_tlv(object):
    TLV_TYPE_FORWARDING_EQUIVALENCE_CLASSES = 0x0100
    TLV_TYPE_GENERIC_LABEL = 0x0200
    TLV_TYPE_COMMON_HELLO = 0x0400
    TLV_TYPE_IPV4_TRANSPORT = 0x0401
    TLV_TYPE_COMMON_SESSION = 0x0500
    
    def __init__(self, type):
        self.type = type

    def render(self, data):
        return struct.pack("!HH", self.type, len(data)) + data

class ldp_forwarding_equivalence_classes_tlv(ldp_tlv):
    def __init__(self, fec_elements):
        ldp_tlv.__init__(self, ldp_tlv.TLV_TYPE_FORWARDING_EQUIVALENCE_CLASSES)
        self.fec_elements = fec_elements

    def render(self):
        data = ""
        for x in self.fec_elements:
            data += x.render()
        return ldp_tlv.render(self, data)

class ldp_generic_label_tlv(ldp_tlv):
    def __init__(self, label):
        ldp_tlv.__init__(self, ldp_tlv.TLV_TYPE_GENERIC_LABEL)
        self.label = label

    def render(self):
        return ldp_tlv.render(self, struct.pack("!I", self.label))

class ldp_common_hello_tlv(ldp_tlv):
    def __init__(self, hold_time, targeted = False, request = False):
        ldp_tlv.__init__(self, ldp_tlv.TLV_TYPE_COMMON_HELLO)
        self.hold_time = hold_time
        self.targeted = targeted
        self.request = request

    def render(self):
        data = 0
        if self.targeted:
            data |= 0x8000
        if self.request:
            data |= 0x4000
        return ldp_tlv.render(self, struct.pack("!HH", self.hold_time, data))

class ldp_ipv4_transport_tlv(ldp_tlv):
    def __init__(self, addr):
        ldp_tlv.__init__(self, ldp_tlv.TLV_TYPE_IPV4_TRANSPORT)
        self.addr = addr

    def render(self):
        return ldp_tlv.render(self, socket.inet_aton(self.addr))

class ldp_common_session_tlv(ldp_tlv):
    def __init__(self, keep_alive, rcv_lsr_id, rcv_label_space):
        ldp_tlv.__init__(self, ldp_tlv.TLV_TYPE_COMMON_SESSION)
        self.keep_alive = keep_alive
        self.rcv_lsr_id = rcv_lsr_id
        self.rcv_label_space = rcv_label_space

    def render(self):
        return ldp_tlv.render(self, struct.pack("!HHBBH", LDP_VERSION, self.keep_alive, 0, 0, 0) + self.rcv_lsr_id + struct.pack("!H", self.rcv_label_space))

class ldp_virtual_circuit_fec(object):
    VC_TYPE_ETHERNET = 0x0005
    
    def __init__(self, group_id, vc_id, iface_tlvs, c_bit = False, vc_type = None):
        self.group_id = group_id
        self.vc_id = vc_id
        self.iface_tlvs = iface_tlvs
        self.c_bit = c_bit
        self.vc_type = vc_type

    def render(self):
        data = ""
        for x in self.iface_tlvs:
            data += x.render()
        if not self.vc_type:
            self.vc_type = self.VC_TYPE_ETHERNET
        if self.c_bit:
            self.vc_type &= 0x80
        return struct.pack("!BHBII", 0x80, self.vc_type, len(data) + 4, self.group_id, self.vc_id) + data

class ldp_vc_interface_param_mtu(object):
    VC_INTERFACE_PARAM_MTU = 0x01

    def __init__(self, mtu):
        self.mtu = mtu

    def render(self):
        return struct.pack("!BBH", self.VC_INTERFACE_PARAM_MTU, 4, self.mtu)
    
class ldp_vc_interface_param_vccv(object):
    VC_INTERFACE_PARAM_VCCV = 0x0c

    def __init__(self, cc_type = 0x02, cv_type = 0x02):
        self.cc_type = cc_type
        self.cv_type = cv_type

    def render(self):
        return struct.pack("!BBBB", self.VC_INTERFACE_PARAM_VCCV, 4, self.cc_type, self.cv_type)

class ldp_hello_thread(threading.Thread):
    def __init__(self, parent, addr, interface, dst_addr, hold_time = DEFAULT_HOLD_TIME):
        threading.Thread.__init__(self)
        self.parent = parent
        self.addr = addr
        self.hold_time = hold_time
        self.sock = None
        self.running = True
        self.interface = interface
        self.dst_addr = dst_addr

    def hello(self):
        msg = ldp_msg(socket.inet_aton(self.addr), 0, [ ldp_hello_msg(0, [ ldp_common_hello_tlv(self.hold_time), ldp_ipv4_transport_tlv(self.addr) ] ) ] )
        t_msg = ldp_msg(socket.inet_aton(self.addr), 0, [ ldp_hello_msg(0, [ ldp_common_hello_tlv(self.hold_time, True, True), ldp_ipv4_transport_tlv(self.addr) ] ) ] )
        data = msg.render()
        t_data = t_msg.render()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.interface)
        self.sock.settimeout(1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', LDP_PORT))
        while self.running:
            if self.dst_addr == "224.0.0.2":
                self.sock.sendto(data, (self.dst_addr, LDP_PORT))
            else:
                self.sock.sendto(t_data, (self.dst_addr, LDP_PORT))
            for x in self.parent.peers:
                self.sock.sendto(t_data, (x, LDP_PORT))
            time.sleep(self.hold_time / 3)

    def run(self):
        self.parent.log("LDP: Hello thread started")
        self.hello()
        self.parent.log("LDP: Hello thread terminated")

    def quit(self):
        self.running = False

class ldp_listener(threading.Thread):
    def __init__(self, parent, interface):
        threading.Thread.__init__(self)
        self.parent = parent
        self.interface = interface
        self.running = True
        self.listen_sock = None

    def run(self):
        self.parent.log("LDP: Listen thread started")
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.interface)
        self.listen_sock.settimeout(1)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind(("0.0.0.0", LDP_PORT))
        self.listen_sock.listen(1)
        while(self.running):
            try:
                (csock, addr) = self.listen_sock.accept()
            except:
                continue
            csock.settimeout(1)
            self.parent.add_peer(csock, addr)
        self.listen_sock.close()
        self.parent.log("LDP: Listen thread terminated")
    
    def quit(self):
        self.running = False
        self.join()

class ldp_peer(threading.Thread):
    def __init__(self, peer, sock, addr, label_space = 0, keep_alive = DEFAULT_KEEP_ALIVE, timeout = 3):
        threading.Thread.__init__(self)
        self.sem = threading.Semaphore()
        self.peer = peer
        self.timeout = timeout
        self.running = True
        self.sock = sock
        self.listen_sock = None
        self.keepalive_msg = None
        self.lsr_id = socket.inet_aton(addr)
        self.id = 1
        self.label_space = label_space
        self.msg = ldp_msg(self.lsr_id, label_space, [ldp_init_msg(self.id, [ldp_common_session_tlv(keep_alive, socket.inet_aton(peer), label_space)])])
        self.keep_alive = keep_alive

    def send(self):
        if not self.sock:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)    
            self.sock.connect((self.peer, LDP_PORT))
        
        while(self.running):
            self.sem.acquire()
            try:
                if self.msg:
                    self.sock.send(self.msg.render())
                    self.msg = None
                self.id += 1
                self.keepalive_msg = ldp_msg(self.lsr_id, self.label_space, [ldp_keepalive_msg(self.id)])
                self.sock.send(self.keepalive_msg.render())
            except socket.error:
                self.running = False
            self.sem.release()
            if self.running:
                time.sleep(self.keep_alive / 3)
        self.sock.close()

    def update(self, msg):
        self.sem.acquire()
        self.msg = msg
        self.sem.release()

    def run(self):
        self.send()
        print "LDP peer " + self.peer + " terminated"

    def quit(self):
        self.running = False
        self.join()

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "ldp"
        self.group = "MPLS"
        self.gladefile = "/modules/module_ldp.glade"
        self.liststore = gtk.ListStore(str, str)
        self.hello_thread = None
        self.listener = None
        self.peers = None

    def start_mod(self):
        self.hello_thread = None
        self.peers = {}
        self.listener = None

    def shut_mod(self):
        if self.listener:
            self.listener.quit()
        if self.hello_thread:
            self.hello_thread.quit()
        if self.peers:
            for x in self.peers:
                (iter, peer) = self.peers[x]
                if peer:
                    peer.quit()
        self.liststore.clear()
        
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_hello_togglebutton_toggled" : self.on_hello_togglebutton_toggled,
                "on_listen_togglebutton_toggled" : self.on_listen_togglebutton_toggled,
                "on_update_button_clicked" : self.on_update_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.treeview = self.glade_xml.get_widget("treeview")
        self.treeview.set_model(self.liststore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Source")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Ident")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.treeview.append_column(column)

        self.msg_textview = self.glade_xml.get_widget("msg_textview")
        self.hello_dst_entry = self.glade_xml.get_widget("hello_dst_entry")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_int(self, int):
        self.interface = int

    def set_ip(self, ip, mask):
        self.ip = ip

    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.dport == LDP_PORT:
            return (True, False)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        src = socket.inet_ntoa(ip.src)
        if src != self.ip:
            if ip.dst == socket.inet_aton(LDP_MULTICAST_ADDRESS):
                if src not in self.peers:
                    hello = ldp_hello_msg()
                    hello.parse(udp.data)
                    id = socket.inet_ntoa(struct.pack("!I", hello.id))
                    iter = self.liststore.append([src, id])
                    self.peers[src] = (iter, None)
                    self.log("LDP: Got new peer %s" % (src))
    
    def add_peer(self, sock, (addr, port)):
        self.log("LDP: Got new connection from peer %s" % (addr))
        if addr not in self.peers:
            iter = self.liststore.append([addr, addr])
            self.peers[addr] = (iter, None)
            self.log("LDP: Got new peer %s" % (addr))
        (iter, peer) = self.peers[addr]
        peer = ldp_peer(addr, sock, self.ip)
        self.peers[addr] = (iter, peer)
        peer.start()

    # SIGNALS #

    def on_hello_togglebutton_toggled(self, btn):
        active = btn.get_active()
        if active:
            self.hello_thread = ldp_hello_thread(self, self.ip, self.interface, self.hello_dst_entry.get_text())
            self.hello_thread.start()
        else:
            if self.hello_thread:
                self.hello_thread.quit()

    def on_listen_togglebutton_toggled(self, btn):
        active = btn.get_active()
        if active:
            self.listener = ldp_listener(self, self.interface)
            self.listener.start()
        else:
            if self.listener:
                self.listener.quit()
        
    def on_update_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        buffer = self.msg_textview.get_buffer()
        text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter())
        try:
            exec("msg = " + text)
        except Exception, e:
            self.log("LDP: Can't compile update statement: %s" % (e))
            return
        for i in paths:
            iter = model.get_iter(i)
            peer = model.get_value(iter, 0)
            (i, p) = self.peers[peer]
            if p:
                p.update(msg)

