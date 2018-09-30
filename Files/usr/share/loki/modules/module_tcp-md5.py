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

import dpkt
import dumbnet

import gobject
import gtk
import gtk.glade

class bgp_md5bf(threading.Thread):
    def __init__(self, parent, iter, bf, full, wl, digest, data):
        self.parent = parent
        self.iter = iter
        self.bf = bf
        self.full = full
        self.wl = wl
        self.digest = digest
        self.data = data
        self.running = True
        threading.Thread.__init__(self)

    def run(self):
        if self.bf and not self.wl:
            self.wl = ""
        (handle, self.tmpfile) = tempfile.mkstemp(prefix="tcp-md5-", suffix="-lock")
        os.close(handle)
        if self.platform == "Windows":
            import tcpmd5bf
            tcpmd5bf.bf(self.bf, self.full, self.wl, self.digest, self.data, self.tmpfile)
        else:
            import loki_bindings
            pw = loki_bindings.tcpmd5.tcpmd5bf.bf(self.bf, self.full, self.wl, self.digest, self.data, self.tmpfile)
        if self.running:
            src = self.parent.liststore.get_value(self.iter, self.parent.SOURCE_ROW)
            dst = self.parent.liststore.get_value(self.iter, self.parent.DESTINATION_ROW)
            if pw:
                self.parent.liststore.set_value(self.iter, self.parent.SECRET_ROW, pw)
                self.parent.log("TCP-MD5: Found password '%s' for connection %s->%s" % (pw, src, dst))
            else:
                self.paren.liststore.set_value(self.iter, self.parent.SECRET_ROW, "NOT FOUND")
                self.parent.log("TCP-MD5: No password found for connection %s->%s" % (src, dst))
            if os.path.exists(self.tmpfile):
                os.remove(self.tmpfile)

    def quit(self):
        self.running = False
        if os.path.exists(self.tmpfile):
            os.remove(self.tmpfile)

class mod_class(object):
    SOURCE_ROW = 0
    DESTINATION_ROW = 1
    SECRET_ROW = 2
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "tcp-md5"
        self.gladefile = "/modules/module_tcp-md5.glade"
        self.liststore = gtk.ListStore(str, str, str)
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

        self.bf_checkbutton = self.glade_xml.get_widget("bf_checkbutton")
        self.full_checkbutton = self.glade_xml.get_widget("full_checkbutton")
        self.wordlist_filechooserbutton = self.glade_xml.get_widget("wordlist_filechooserbutton")

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
                src = dumbnet.ip_ntoa(ip.src)
                dst = dumbnet.ip_ntoa(ip.dst)
                ident = "%s:%i->%s:%i" % (src, tcp.sport, dst, tcp.dport)
                if ident not in self.opts:
                    iter = self.liststore.append(["%s:%i" % (src, tcp.sport), "%s:%i" % (dst, tcp.dport), "CAPTURED"])
                    self.opts[ident] = (iter, str(eth.data), data, None)
                    self.log("TCP-MD5: Got MD5 data for connection %s" % (ident))

    # SIGNALS #

    def on_crack_button_clicked(self, btn):
        bf = self.bf_checkbutton.get_active()
        full = self.full_checkbutton.get_active()
        wl = self.wordlist_filechooserbutton.get_filename()
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
            thread = bgp_md5bf(self, iter, bf, full, wl, digest, data)
            model.set_value(iter, self.SECRET_ROW, "RUNNING")
            thread.start()
            self.opts[ident] = (iter, data, digest, thread)
            
