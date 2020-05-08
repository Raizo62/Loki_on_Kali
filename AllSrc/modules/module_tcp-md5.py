#       module_bgp-md5.py
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
import tempfile
import threading
import time

import dpkt
import dnet

gobject = None
gtk = None
urwid = None

class bgp_md5bf(threading.Thread):
    def __init__(self, parent, iter, digest, data):
        self.parent = parent
        self.iter = iter
        self.digest = digest
        self.data = data
        self.obj = None
        threading.Thread.__init__(self)

    def run(self):
        if self.parent.platform == "Windows":
            import bf
        else:
            from loki_bindings import bf
        l = self.parent.parent
        self.obj = bf.tcpmd5_bf()
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
        
        if self.parent.ui == 'gtk':
            with gtk.gdk.lock:
                src = self.parent.liststore.get_value(self.iter, self.parent.SOURCE_ROW)
                dst = self.parent.liststore.get_value(self.iter, self.parent.DESTINATION_ROW)
                if not self.obj.pw is None:
                    self.parent.liststore.set_value(self.iter, self.parent.SECRET_ROW, self.obj.pw)
                    self.parent.log("TCP-MD5: Found password '%s' for connection %s->%s" % (self.obj.pw, src, dst))
                else:
                    self.paren.liststore.set_value(self.iter, self.parent.SECRET_ROW, "NOT FOUND")
                    self.parent.log("TCP-MD5: No password found for connection %s->%s" % (src, dst))
        self.obj = None

    def quit(self):
        if not self.obj is None:
            self.obj.stop()
            self.obj = None
    
class mod_class(object):
    SOURCE_ROW = 0
    DESTINATION_ROW = 1
    SECRET_ROW = 2
    
    def __init__(self, parent, platform, ui):
        self.parent = parent
        self.platform = platform
        self.name = "tcp-md5"
        self.gladefile = "/modules/module_tcp-md5.glade"
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
            self.liststore = gtk.ListStore(str, str, str)
        elif self.ui == 'urw':
            import urwid as urwid_
            global urwid
            urwid = urwid_
        self.opts = None

    def start_mod(self):
        self.opts = {}

    def shut_mod(self):
        if self.opts:
            for i in self.opts:
                (iter, data, digest, thread) = self.opts[i]
                if thread:
                    if thread.is_alive():
                        thread.quit()
        if self.ui == 'gtk':
            self.liststore.clear()
        
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_crack_button_clicked" : self.on_crack_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.treeview = self.glade_xml.get_widget("treeview")
        self.treeview.set_model(self.liststore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Source")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.SOURCE_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Destination")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.DESTINATION_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Secret")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.SECRET_ROW)
        self.treeview.append_column(column)
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_tcp_checks(self):
        return (self.check_tcp, self.input_tcp)

    def check_tcp(self, tcp):
        if tcp.opts != '':
            return (True, False)
        else:
            return (False, False)

    def input_tcp(self, eth, ip, tcp, timestamp):
        opts = dpkt.tcp.parse_opts(tcp.opts)
        for (opt, data) in opts:
            if opt == dpkt.tcp.TCP_OPT_MD5:
                src = dnet.ip_ntoa(ip.src)
                dst = dnet.ip_ntoa(ip.dst)
                ident = "%s:%i->%s:%i" % (src, tcp.sport, dst, tcp.dport)
                if ident not in self.opts:
                    if self.ui == 'gtk':
                        iter = self.liststore.append(["%s:%i" % (src, tcp.sport), "%s:%i" % (dst, tcp.dport), "CAPTURED"])
                    self.opts[ident] = (iter, str(eth.data), data, None)
                    self.log("TCP-MD5: Got MD5 data for connection %s" % (ident))

    # SIGNALS #

    def on_crack_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            src = model.get_value(iter, self.SOURCE_ROW)
            dst = model.get_value(iter, self.DESTINATION_ROW)
            ident = "%s->%s" % (src, dst)
            (iter, data, digest, thread) = self.opts[ident]
            if thread:
                return
            thread = bgp_md5bf(self, iter, digest, data)
            model.set_value(iter, self.SECRET_ROW, "RUNNING")
            thread.start()
            self.opts[ident] = (iter, data, digest, thread)
            
