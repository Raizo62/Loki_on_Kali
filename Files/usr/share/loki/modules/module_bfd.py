#       module_bfd.py
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

import os
import random
import struct

import dumbnet
import dpkt

import gobject
import gtk
import gtk.glade

BFD_VERSION = 1
BFD_PORT = 3784

class bfd_control_packet(object):

    DIAG_NO = 0             #No Diagnostic
    DIAG_TIME_EXP = 1       #Control Detection Time Expired
    DIAG_ECHO_FAIL = 2      #Echo Function Failed
    DIAG_NEIGH_DOWN = 3     #Neighbor Signaled Session Down
    DIAG_FORW_RST = 4       #Forwarding Plane Reset
    DIAG_PATH_DOWN = 5      #Path Down
    DIAG_CONC_PATH_DOWN = 6 #Concatenated Path Down
    DIAG_ADMIN_DOWN = 7     #Administratively Down
    DIAG_REV_PATH_DOWN = 8  #Reverse Concatenated Path Down

    diag_to_str = { DIAG_NO : "DIAG_NO",
                    DIAG_TIME_EXP : "DIAG_TIME_EXP",
                    DIAG_ECHO_FAIL : "DIAG_ECHO_FAIL",
                    DIAG_NEIGH_DOWN : "DIAG_NEIGH_DOWN",
                    DIAG_FORW_RST : "DIAG_FORW_RST",
                    DIAG_PATH_DOWN : "DIAG_PATH_DOWN",
                    DIAG_CONC_PATH_DOWN : "DIAG_CONC_PATH_DOWN",
                    DIAG_ADMIN_DOWN : "DIAG_ADMIN_DOWN",
                    DIAG_REV_PATH_DOWN : "DIAG_REV_PATH_DOWN"
                    }

    STATE_ADMIN_DOWN = 0
    STATE_DOWN = 1
    STATE_INIT = 2
    STATE_UP = 3

    state_to_str = {    STATE_ADMIN_DOWN : "STATE_ADMIN_DOWN",
                        STATE_DOWN : "STATE_DOWN",
                        STATE_INIT : "STATE_INIT",
                        STATE_UP : "STATE_UP"
                        }

    FLAG_POLL = 0x20
    FLAG_FINAL = 0x10
    FLAG_INDEPEND = 0x8
    FLAG_AUTH = 0x4
    FLAG_DEMAN = 0x2
    FLAG_MULTIPOINT = 0x1

    #~ 0                   1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                       My Discriminator                        |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                      Your Discriminator                       |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                    Desired Min TX Interval                    |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                   Required Min RX Interval                    |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                 Required Min Echo RX Interval                 |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def __init__(self, diag=None, state=None, flags=None, multiplier=None, my_discrim=None, your_discrim=None, des_min_tx=None, req_min_rx=None, req_min_echo=None, auth=None):
        self.diag = diag
        self.state = state
        self.flags = flags
        self.multiplier = multiplier
        self.my_discrim = my_discrim
        self.your_discrim = your_discrim
        self.des_min_tx = des_min_tx
        self.req_min_rx = req_min_rx
        self.req_min_echo = req_min_echo
        self.auth = auth

    def render(self):
        vers_diag = (BFD_VERSION << 5) + (self.diag & 0x1F)
        state_flags = (self.state << 6) + (self.flags & 0x3F)
        auth = ""
        if self.flags and self.flags & self.FLAG_AUTH and self.auth:
            auth = self.auth.render()
        length = 24 + len(auth)
        return struct.pack("!BBBBLLLLL", vers_diag, state_flags, self.multiplier, length, self.my_discrim, self.your_discrim, self.des_min_tx, self.req_min_rx, self.req_min_echo) + auth
        
    def parse(self, data):
        (vers_diag, state_flags, self.multiplier, length, self.my_discrim, self.your_discrim, self.des_min_tx, self.req_min_rx, self.req_min_echo) = struct.unpack("!BBBBLLLLL", data[:24])
        self.version = vers_diag >> 5
        self.diag = vers_diag & 0x1F
        self.state = state_flags >> 6
        self.flags = state_flags & 0x3F
        if self.flags & self.FLAG_AUTH:
            self.auth = bfd_auth()
            self.auth.parse(data[24:])

class bfd_auth(object):

    TYPE_RESERVED = 0
    TYPE_SIMPLE = 1
    TYPE_KEYED_MD5 = 2
    TYPE_METRIC_MD5 = 3
    TYPE_KEYED_SHA1 = 4
    TYPE_METRIC_SHA1 = 5
    
    #~  0                   1                   2                   3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |   Auth Type   |   Auth Len    |    Authentication Data...     |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def __init__(self, type=None, data=None):
        self.type = type
        self.data = data

    def render(self):
        return struct.pack("!BB", self.type, 2 + len(self.data)) + self.data

    def parse(self, data):
        pass

class mod_class(object):
    NEIGH_SRC_ROW = 0
    NEIGH_DST_ROW = 1
    NEIGH_STATE_ROW = 2
    NEIGH_DIAG_ROW = 3
    NEIGH_ANSWER_ROW = 4
    NEIGH_DOS_ROW = 5
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "bfd"
        self.group = "HOT-STANDBY"
        self.gladefile = "/modules/module_bfd.glade"
        self.neighbor_treestore = gtk.TreeStore(str, str, str, str, bool, bool)
        self.neighbors = {}
        self.filter = False

    def start_mod(self):
        self.neighbors = {}
        self.auto_answer = False
        self.auto_answer_checkbutton.set_active(False)
        
    def shut_mod(self):
        self.neighbor_treestore.clear()
        if self.filter:
            self.log("BFD: Removing lokal packet filter for BFD")
            if self.platform == "Linux":
                os.system("iptables -D INPUT -i %s -p udp --dport %d -j DROP" % (self.interface, BFD_PORT))
            elif self.platform == "Darwin":
                os.system("ipfw -q delete 31336")
            elif self.platform == "Windows":
                os.system("netsh advfirewall firewall del rule name=bfd")
            else:
                self.fw.delete(self.bfd_filter)
            self.filter = False
            self.filter_checkbutton.set_active(False)

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_auto_answer_checkbutton_toggled" : self.on_auto_answer_checkbutton_toggled,
                "on_filter_checkbutton_toggled" : self.on_filter_checkbutton_toggled
                }
        self.glade_xml.signal_autoconnect(dic)

        self.neighbor_treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.neighbor_treeview.set_model(self.neighbor_treestore)
        self.neighbor_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("SRC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_SRC_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DST")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_DST_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("STATE")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_STATE_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DIAG")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_DIAG_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("ANSWER")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.connect('toggled', self.answer_toggle_callback, self.neighbor_treestore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, "active", self.NEIGH_ANSWER_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DOS")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.connect('toggled', self.dos_toggle_callback, self.neighbor_treestore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, "active", self.NEIGH_DOS_ROW)
        self.neighbor_treeview.append_column(column)

        self.auto_answer_checkbutton = self.glade_xml.get_widget("auto_answer_checkbutton")
        self.filter_checkbutton = self.glade_xml.get_widget("filter_checkbutton")

        return self.glade_xml.get_widget("root")

    def answer_toggle_callback(self, cell, path, model):            
        model[path][self.NEIGH_ANSWER_ROW] = not model[path][self.NEIGH_ANSWER_ROW]
        id = "%s:%s" % (model[path][self.NEIGH_SRC_ROW], model[path][self.NEIGH_DST_ROW])
        (iter, discrim, answer, dos) = self.neighbors[id]
        if model[path][self.NEIGH_ANSWER_ROW] and model[path][self.NEIGH_DOS_ROW]:
            model[path][self.NEIGH_DOS_ROW] = False
            dos = False
        self.neighbors[id] = (iter, discrim, model[path][self.NEIGH_ANSWER_ROW], dos)
        
    def dos_toggle_callback(self, cell, path, model):
        model[path][self.NEIGH_DOS_ROW] = not model[path][self.NEIGH_DOS_ROW]
        id = "%s:%s" % (model[path][self.NEIGH_SRC_ROW], model[path][self.NEIGH_DST_ROW])
        (iter, discrim, answer, dos) = self.neighbors[id]
        if model[path][self.NEIGH_DOS_ROW] and model[path][self.NEIGH_ANSWER_ROW]:
            model[path][self.NEIGH_ANSWER_ROW] = False
            answer = False
        self.neighbors[id] = (iter, discrim, answer, model[path][self.NEIGH_DOS_ROW])
        
    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_dumbnet(self, dumbnet):
        self.dumbnet = dumbnet

    def set_fw(self, fw):
        self.fw = fw

    def set_int(self, interface):
        self.interface = interface
        self.bfd_filter = {     "device"    : self.interface,
                                "op"        : dumbnet.FW_OP_BLOCK,
                                "dir"       : dumbnet.FW_DIR_IN,
                                "proto"     : dpkt.ip.IP_PROTO_UDP,
                                "src"       : dumbnet.addr("0.0.0.0/0", dumbnet.ADDR_TYPE_IP),
                                "dst"       : dumbnet.addr("0.0.0.0/0", dumbnet.ADDR_TYPE_IP),
                                "sport"     : [0, 0],
                                "dport"     : [BFD_PORT, BFD_PORT]
                                }


    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.dport == BFD_PORT:
            return (True, True)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        packet = bfd_control_packet()
        packet.parse(udp.data)
        src = dumbnet.ip_ntoa(ip.src)
        dst = dumbnet.ip_ntoa(ip.dst)
        id = "%s:%s" % (src, dst)
        id_rev = "%s:%s" % (dst, src)
        if id not in self.neighbors and id_rev not in self.neighbors:
            if not self.filter:
                self.log("BFD: Setting lokal packet filter for BFD")
                if self.platform == "Linux":
                    os.system("iptables -A INPUT -i %s -p udp --dport %i -j DROP" % (self.interface, BFD_PORT))
                elif self.platform == "Darwin":
                    os.system("ipfw -q add 31336 deny udp from any to any %d" % (BFD_PORT))
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall add rule name=bfd dir=in protocol=UDP localport=%d action=block" % BFD_PORT)
                else:
                    self.fw.add(self.bfd_filter)
                self.filter = True
                self.filter_checkbutton.set_active(True)
            self.log("BFD: got new session: %s -> %s" % (src, dst))
            iter = self.neighbor_treestore.append(None, [src, dst, bfd_control_packet.state_to_str[packet.state], bfd_control_packet.diag_to_str[packet.diag], self.auto_answer, False])
            self.neighbors[id] = (iter, random.randint(0x1, 0x7fffffff), self.auto_answer, False)
        if id in self.neighbors:
            (iter, discrim, answer, dos) = self.neighbors[id]
            if self.neighbor_treestore.iter_is_valid(iter):
                self.neighbor_treestore.set_value(iter, self.NEIGH_STATE_ROW, bfd_control_packet.state_to_str[packet.state])
                self.neighbor_treestore.set_value(iter, self.NEIGH_DIAG_ROW, bfd_control_packet.diag_to_str[packet.diag])
            if answer and packet.diag == bfd_control_packet.DIAG_NO:
                if packet.state == bfd_control_packet.STATE_DOWN:
                    packet.state = bfd_control_packet.STATE_INIT
                packet.your_discrim = packet.my_discrim
                packet.my_discrim = discrim
                packet.req_min_echo = 0
                udp_hdr = dpkt.udp.UDP( dport=BFD_PORT,
                                        sport=31337,
                                        data=packet.render()
                                        )
                udp_hdr.ulen += len(udp_hdr.data)
                ip_hdr = dpkt.ip.IP(    ttl=255,
                                        tos=0xC0,
                                        p=dpkt.ip.IP_PROTO_UDP,
                                        src=ip.dst,
                                        dst=ip.src,
                                        data=str(udp_hdr)
                                        )
                ip_hdr.len += len(ip_hdr.data)
                eth_hdr = dpkt.ethernet.Ethernet(   dst=eth.src,
                                                    src=eth.dst,
                                                    type=dpkt.ethernet.ETH_TYPE_IP,
                                                    data=str(ip_hdr)
                                                    )
                self.dumbnet.send(str(eth_hdr))
            elif dos and packet.state > bfd_control_packet.STATE_DOWN:
                packet.state = bfd_control_packet.STATE_DOWN
                tmp = packet.your_discrim
                packet.your_discrim = packet.my_discrim
                packet.my_discrim = tmp
                udp_hdr = dpkt.udp.UDP( dport=udp.dport,
                                        sport=udp.sport,
                                        data=packet.render()
                                        )
                udp_hdr.ulen += len(udp_hdr.data)
                ip_hdr = dpkt.ip.IP(    ttl=255,
                                        tos=0xC0,
                                        p=dpkt.ip.IP_PROTO_UDP,
                                        src=ip.dst,
                                        dst=ip.src,
                                        data=str(udp_hdr)
                                        )
                ip_hdr.len += len(ip_hdr.data)
                eth_hdr = dpkt.ethernet.Ethernet(   dst=eth.src,
                                                    src=eth.dst,
                                                    type=dpkt.ethernet.ETH_TYPE_IP,
                                                    data=str(ip_hdr)
                                                    )
                self.dumbnet.send(str(eth_hdr))

    # SIGNALS #

    def on_auto_answer_checkbutton_toggled(self, btn):
        self.auto_answer = btn.get_active()

    def on_filter_checkbutton_toggled(self, btn):
        if btn.get_active():
            if not self.filter:
                self.log("BFD: Setting lokal packet filter for BFD")
                if self.platform == "Linux":
                    os.system("iptables -A INPUT -i %s -p udp --dport %d -j DROP" % (self.interface, BFD_PORT))
                elif self.platform == "Darwin":
                    os.system("ipfw -q add 31336 deny udp from any to any %d" % (BFD_PORT))
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall add rule name=bfd dir=in protocol=UDP localport=%d action=block" % BFD_PORT)
                else:
                    self.fw.add(self.bfd_filter)
                self.filter = True
        else:
            if self.filter:
                self.log("BFD: Removing lokal packet filter for BFD")
                if self.platform == "Linux":
                    os.system("iptables -D INPUT -i %s -p udp --dport %d -j DROP" % (self.interface, BFD_PORT))
                elif self.platform == "Darwin":
                    os.system("ipfw -q delete 31336")
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall del rule name=bfd")
                else:
                    self.fw.delete(self.bfd_filter)
                self.filter = False
