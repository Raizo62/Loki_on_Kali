#       module_mpls.py
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
import struct
import tempfile
import threading

import loki_bindings

import dnet
import dpkt

import gobject
import gtk
import gtk.glade

class redirect_thread(threading.Thread):
    def __init__(self, parent, model, iter, from_mac, to_mac, num_label, from_label, to_label, filter):
        self.parent = parent
        self.model = model
        self.iter = iter
        self.filter = "ether src %s and ether dst %s and mpls" % (from_mac, to_mac)
        if filter != "":
            self.filter += " and %s" % filter
        self.num_label = num_label
        self.from_label = from_label
        self.to_label = to_label
        threading.Thread.__init__(self)

    def run(self):
        (handle, self.tmpfile) = tempfile.mkstemp(prefix="mpls-red-", suffix="-lock")
        os.close(handle)
        self.parent.log("MPLS: Redirection thread started")
        
        loki_bindings.mplsred.mplsred(self.parent.interface, self.parent.interface, self.num_label, self.from_label, self.to_label, self.filter, self.tmpfile, 0)

        self.parent.log("MPLS: Redirection thread terminated")
        if os.path.exists(self.tmpfile):
            os.remove(self.tmpfile)
        if self.model.iter_is_valid(self.iter):
            (ident,) = self.model.get(self.iter, self.parent.REDIRECT_INDEX_ROW)
            del self.parent.redirects[ident]
            self.model.remove(self.iter)
    
    def quit(self):
        if os.path.exists(self.tmpfile):
            os.remove(self.tmpfile)

class mod_class(object):
    PEER_SRC_ROW = 0
    PEER_DST_ROW = 1
    PEER_LABEL_ROW = 2
    PEER_EXP_ROW = 3
    PEER_TTL_ROW = 4
    PEER_DEPTH_ROW = 5

    REDIRECT_SRC_ROW = 0
    REDIRECT_DST_ROW = 1
    REDIRECT_INDEX_ROW = 2
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "mpls"
        self.group = "MPLS"
        self.gladefile = "/modules/module_mpls.glade"
        self.peer_treestore = gtk.TreeStore(str, str, str, str, str, int)
        self.redirect_treestore = gtk.TreeStore(str, str, str)
        self.peers = {}
        self.redirects = {}

    def start_mod(self):
        self.peers = {}
        self.redirects = {}

    def shut_mod(self):
        self.peer_treestore.clear()
        for i in self.redirects:
            (iter, thread) = self.redirects[i]
            if thread and thread.is_alive():
                thread.quit()
        self.redirect_treestore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_peer_treeview_row_activated" : self.on_peer_treeview_row_activated,
                "on_add_button_clicked" : self.on_add_button_clicked,
                "on_del_button_clicked" : self.on_del_button_clicked,
                "on_clear_button_clicked" : self.on_clear_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.peer_treeview = self.glade_xml.get_widget("peer_treeview")
        self.peer_treeview.set_model(self.peer_treestore)
        self.peer_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("SRC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_SRC_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DST")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_DST_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("LABEL")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_LABEL_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("EXP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_EXP_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("TTL")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_TTL_ROW)
        self.peer_treeview.append_column(column)

        self.redirect_treeview = self.glade_xml.get_widget("redirect_treeview")
        self.redirect_treeview.set_model(self.redirect_treestore)
        self.redirect_treeview.set_headers_visible(True)
        
        column = gtk.TreeViewColumn()
        column.set_title("SRC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.REDIRECT_SRC_ROW)
        self.redirect_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DST")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.REDIRECT_DST_ROW)
        self.redirect_treeview.append_column(column)

        self.src_entry = self.glade_xml.get_widget("src_entry")
        self.dst_entry = self.glade_xml.get_widget("dst_entry")
        self.nr_label_spinbutton = self.glade_xml.get_widget("nr_label_spinbutton")
        self.from_label_spinbutton = self.glade_xml.get_widget("from_label_spinbutton")
        self.to_label_spinbutton = self.glade_xml.get_widget("to_label_spinbutton")
        self.filter_entry = self.glade_xml.get_widget("filter_entry")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_int(self, interface):
        self.interface = interface

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_MPLS:
            return (True, False)
        return (False, False)

    def input_eth(self, eth, timestamp):
        src = dnet.eth_ntoa(eth.src)
        dst = dnet.eth_ntoa(eth.dst)
        data = eth.data
        src_dst = src + ":" + dst
        if src_dst not in self.peers:
            iter = self.peer_treestore.append(None, [src, dst, "", "", "", -1])
            dict = self.parse_label(data, iter, {})
            self.peers[src_dst] = (iter, dict)
            self.log("MPLS: Got new MPLS communication: %s -> %s" % (src, dst))
        else:
            (iter, dict) = self.peers[src_dst]
            self.parse_label(data, iter, dict)

    def parse_label(self, data, iter, dict, depth=0):
        (label, exp, bos, ttl) = self.get_label(data)
        if label in dict:
            (child, sub_dict) = dict[label]
        else:
            pad = " " * depth
            child = self.peer_treestore.append(iter, ["", "", pad + str(label), pad + str(exp), pad + str(ttl), depth])
            sub_dict = {}
        if bos == 0:
            self.parse_label(data[4:], child, sub_dict, depth + 1)
        dict[label] = (child, sub_dict)
        return dict

    def get_label(self, data):
        (data,) = struct.unpack("!L", data[:4])
        label = (data & 0xfffff000) >> 12
        exp = (data & 0x00000e00) >> 9
        bos = (data & 0x00000100) >> 8
        ttl = (data & 0x000000ff)
        return (label, exp, bos, ttl)

    def on_peer_treeview_row_activated(self, treeview, path, view_column):
        model = treeview.get_model()
        parent = iter = model.get_iter(path)
        prev = model.iter_parent(iter)
        while prev:
            parent = prev
            prev = model.iter_parent(parent)
        self.src_entry.set_text(model.get_value(parent, self.PEER_SRC_ROW))
        self.dst_entry.set_text(model.get_value(parent, self.PEER_DST_ROW))
        if parent != iter:
            self.nr_label_spinbutton.set_value(model.get_value(iter, self.PEER_DEPTH_ROW))
            self.from_label_spinbutton.set_value(int(model.get_value(iter, self.PEER_LABEL_ROW)))

    def on_add_button_clicked(self, btn):
        src = self.src_entry.get_text()
        dst = self.dst_entry.get_text()
        nr = int(self.nr_label_spinbutton.get_value())
        fl = int(self.from_label_spinbutton.get_value())
        tl = int(self.to_label_spinbutton.get_value())
        filter = self.filter_entry.get_text()
        index = "%s:%s:%i:%i:%i:%s" % (src, dst, nr, fl, tl, filter)
        if index not in self.redirects:
            iter = self.redirect_treestore.append(None, [src, dst, index])
            self.redirect_treestore.append(iter, ["#%i from %i" % (nr, fl), "%i" % tl, ""])
            if filter != "":
                self.redirect_treestore.append(iter, ["Filter", filter])
            thread = redirect_thread(self, self.redirect_treestore, iter, src, dst, nr, fl, tl, filter)
            self.redirects[index] = (iter, thread)
            thread.start()

    def on_del_button_clicked(self, btn):
        select = self.redirect_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) == 1:
            parent = model.iter_parent(model.get_iter(paths[0]))
            if not parent:
                parent = model.get_iter(paths[0])
            (iter, thread) = self.redirects[model.get_value(parent, self.REDIRECT_INDEX_ROW)]
            if thread and thread.is_alive():
                thread.quit()

    def on_clear_button_clicked(self, btn):
        for i in self.redirects:
            (iter, thread) = self.redirects[i]
            if thread and thread.is_alive():
                thread.quit()
        self.redirect_treestore.clear()
        self.redirects = {}
