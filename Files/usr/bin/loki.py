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

import copy
import sys
import os
import platform
import signal
import threading
import time
import traceback
import string
import struct

import ConfigParser

import pygtk
pygtk.require('2.0')

import gobject
import gtk
gtk.gdk.threads_init()

import dpkt
import dumbnet

DEBUG = True

VERSION = "0.2.7"
PLATFORM = platform.system()

MODULE_PATH="/modules"
CONFIG_PATH=os.path.expanduser("~/.loki")
DATA_DIR="/usr/share/loki"
#~ For OSX Bundeling
#~ DATA_DIR=os.path.expandvars("$bundle_data/loki")

class about_window(gtk.Window):
    def __init__(self, parent):
        gtk.Window.__init__(self)
        self.set_title("About")
        self.set_default_size(150, 70)
        self.set_property("modal", True)
        label = gtk.Label("This is %s version %s by Daniel Mende - dmende@ernw.de\nRunning on %s" % (parent.__class__.__name__, VERSION, PLATFORM))
        button = gtk.Button(gtk.STOCK_CLOSE)
        button.set_use_stock(True)
        button.connect_object("clicked", gtk.Widget.destroy, self)
        buttonbox = gtk.HButtonBox()
        buttonbox.pack_start(button)
        vbox = gtk.VBox()
        vbox.pack_start(label, True, True, 0)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

class log_window(gtk.Window):
    def __init__(self, textbuffer):
        gtk.Window.__init__(self)
        self.set_title("Log")
        self.set_default_size(300, 400)
        textview = gtk.TextView(textbuffer)
        textview.set_editable(False)
        button = gtk.Button(gtk.STOCK_CLOSE)
        button.set_use_stock(True)
        button.connect_object("clicked", gtk.Widget.destroy, self)
        buttonbox = gtk.HButtonBox()
        buttonbox.pack_start(button)
        scrolledwindow = gtk.ScrolledWindow()
        scrolledwindow.add(textview)
        scrolledwindow.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        vbox = gtk.VBox()
        vbox.pack_start(scrolledwindow, True, True, 0)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

class module_preferences_window(gtk.Window):
    NAME_ROW = 0
    VALUE_ROW = 1
    TYPE_ROW = 2
    MIN_ROW = 3
    MAX_ROW = 4
    TOOLTIP_ROW = 5
    
    def __init__(self, parent, mod_name, dict):
        self.par = parent
        self.mod_name = mod_name
        self.dict = dict
        gtk.Window.__init__(self)
        self.set_title("%s Preferences" % mod_name.upper())
        self.set_default_size(250, 350)
        self.module_liststore = gtk.ListStore(str, str, str, int, int, str)
        notebook = gtk.Notebook()
        module_treeview = gtk.TreeView()
        module_treeview.set_model(self.module_liststore)
        module_treeview.set_headers_visible(True)
        module_treeview.set_tooltip_column(self.TOOLTIP_ROW)

        column = gtk.TreeViewColumn()
        column.set_title("Name")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NAME_ROW)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Value")
        render_text = gtk.CellRendererText()
        render_text.set_property('editable', True)
        render_text.connect('edited', self.edited_callback, self.module_liststore)
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.VALUE_ROW)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Type")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.TYPE_ROW)
        module_treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("Min")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.MIN_ROW)
        #~ module_treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("Max")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.MAX_ROW)
        #~ module_treeview.append_column(column)
        
        scrolledwindow = gtk.ScrolledWindow()
        scrolledwindow.set_property("vscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.set_property("hscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.add_with_viewport(module_treeview)
        vbox = gtk.VBox(False, 0)
        vbox.pack_start(scrolledwindow, True, True, 0)
        buttonbox = gtk.HButtonBox()
        close = gtk.Button(gtk.STOCK_CLOSE)
        close.set_use_stock(True)
        close.connect_object("clicked", self.close_button_clicked, None)
        buttonbox.pack_start(close)
        save = gtk.Button(gtk.STOCK_SAVE)
        save.set_use_stock(True)
        save.connect_object("clicked", self.save_button_clicked, None)
        buttonbox.pack_start(save)
        apply = gtk.Button(gtk.STOCK_APPLY)
        apply.set_use_stock(True)
        apply.connect_object("clicked", self.apply_button_clicked, None)
        buttonbox.pack_start(apply)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

        for name in dict:
            self.module_liststore.append([name, str(dict[name]["value"]), dict[name]["type"], dict[name]["min"], dict[name]["max"], "Min: %s   Max: %s" % (dict[name]["min"],dict[name]["max"] )])

    def edited_callback(self, cell, path, new_text, model):
        def int_(self, cell, path, new_text, model):
            try:
                val = int(new_text)
                assert(val >= model[path][self.MIN_ROW])
                assert(val <= model[path][self.MAX_ROW])
            except:
                pass
            else:
                model[path][self.VALUE_ROW] = new_text
                self.dict[model[path][self.NAME_ROW]]["value"] = val

        def str_(self, cell, path, new_text, model):
            try:
                assert(len(new_text) >= model[path][self.MIN_ROW])
                assert(len(new_text) <= model[path][self.MAX_ROW])
            except:
                pass
            else:
                model[path][self.VALUE_ROW] = new_text
                self.dict[model[path][self.NAME_ROW]]["value"] = new_text

        def float_(self, cell, path, new_text, model):
            try:
                val = float(new_text)
                assert(val >= model[path][self.MIN_ROW])
                assert(val <= model[path][self.MAX_ROW])
            except:
                pass
            else:
                model[path][self.VALUE_ROW] = new_text
                self.dict[model[path][self.NAME_ROW]]["value"] = val

        {   "str" : str_,
            "int" : int_,
            "float" : float_    }[model[path][self.TYPE_ROW]](self, cell, path, new_text, model)

    def close_button_clicked(self, btn):
        gtk.Widget.destroy(self)

    def save_button_clicked(self, btn):
        self.apply_button_clicked(None)
        config = ConfigParser.RawConfigParser()
        config.add_section(self.mod_name)
        for i in self.dict:
            config.set(self.mod_name, i, self.dict[i]["value"])
        path = CONFIG_PATH + "/"
        if not os.path.exists(path):
            os.mkdir(path, 0700)
        with open(path + self.mod_name +".cfg", 'wb') as configfile:
            config.write(configfile)
            self.par.log("Saved %s configuration" % self.mod_name)
        self.close_button_clicked(None)

    def apply_button_clicked(self, btn):
        (module, enabled) = self.par.modules[self.mod_name]
        module.set_config_dict(self.dict)

class preference_window(gtk.Window):
    MOD_NAME_ROW = 0
    MOD_ENABLE_ROW = 1
    MOD_RESET_ROW = 2
    MOD_CONFIG_ROW = 3
    
    def __init__(self, parent):
        self.par = parent
        gtk.Window.__init__(self)
        self.set_title("Preferences")
        self.set_default_size(300, 400)
        #self.set_property("modal", True)
        self.module_liststore = gtk.ListStore(str, bool, bool, bool)
        notebook = gtk.Notebook()
        module_treeview = gtk.TreeView()
        module_treeview.set_model(self.module_liststore)
        module_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Module")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.MOD_NAME_ROW)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Enabled")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.connect('toggled', self.toggle_callback, self.module_liststore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, "active", self.MOD_ENABLE_ROW)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Reset")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.set_property('radio', True)
        render_toggle.connect('toggled', self.reset_callback, self.module_liststore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, 'active', self.MOD_RESET_ROW)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Config")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.set_property('radio', True)
        render_toggle.connect('toggled', self.config_callback, self.module_liststore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, 'active', self.MOD_CONFIG_ROW)
        module_treeview.append_column(column)

        scrolledwindow = gtk.ScrolledWindow()
        scrolledwindow.set_property("vscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.set_property("hscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.add_with_viewport(module_treeview)
        notebook.append_page(scrolledwindow, tab_label=gtk.Label("Modules"))
        vbox = gtk.VBox(False, 0)
        vbox.pack_start(notebook, True, True, 0)
        buttonbox = gtk.HButtonBox()
        close = gtk.Button(gtk.STOCK_CLOSE)
        close.set_use_stock(True)
        close.connect_object("clicked", self.close_button_clicked, None)
        buttonbox.pack_start(close)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

        modlist = self.par.modules.keys()
        modlist.sort()
        try:
            for i in modlist:
                (module, enabled) = self.par.modules[i]
                if "get_config_dict" in dir(module) and "set_config_dict" in dir(module):
                    self.module_liststore.append([i, enabled, False, False])
                else:
                    self.module_liststore.append([i, enabled, False, True])        
        except Exception, e:
            print e
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
            print "failed to open module %s" % module

    def toggle_callback(self, cell, path, model):
        model[path][self.MOD_ENABLE_ROW] = not model[path][self.MOD_ENABLE_ROW]
        if model[path][self.MOD_ENABLE_ROW]:
            self.par.init_module(model[path][self.MOD_NAME_ROW])
        else:
            self.par.shut_module(model[path][self.MOD_NAME_ROW])

    def reset_callback(self, cell, path, model):
        model[path][self.MOD_RESET_ROW] = not model[path][self.MOD_RESET_ROW]
        if cell:
            gobject.timeout_add(750, self.reset_callback, None, path, model)
            cur = self.par.notebook.get_current_page()
            old_pos = self.par.shut_module(model[path][self.MOD_NAME_ROW])
            self.par.load_module(model[path][self.MOD_NAME_ROW], model[path][self.MOD_ENABLE_ROW])
            (module, enabled) = self.par.modules[model[path][self.MOD_NAME_ROW]]
            if enabled:
                self.par.init_module(model[path][self.MOD_NAME_ROW], old_pos)
                if old_pos == cur:
                    self.par.notebook.set_current_page(cur)
            return False

    def config_callback(self, cell, path, model):
        if not model[path][self.MOD_CONFIG_ROW]:
            name = model[path][self.MOD_NAME_ROW]
            (module, enabled) = self.par.modules[name]
            try:
                dict = module.get_config_dict()
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
                print "failed to load conf-dict from %s" % module
                dict = None
            wnd = module_preferences_window(self.par, name, dict)
            wnd.show_all()
        
    def close_button_clicked(self, arg):
        gtk.Widget.destroy(self)

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
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60

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
            if eth_new.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = dpkt.ip.IP(str(eth_new.data))
                for (check, call, name) in self.parent.ip_checks:
                    (ret, stop) = check(ip)
                    if ret:
                        call(copy.copy(eth), copy.copy(ip), timestamp)
                        if stop:
                            return
            eth = eth_new

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
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
        self.parent.log("Read thread terminated")

class dumbnet_thread(threading.Thread):
    def __init__(self, interface):
        threading.Thread.__init__(self)
        self.interface = interface
        self.sem = threading.Semaphore()
        self.running = True
        self.eth = dumbnet.eth(interface)
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

class codename_loki(object):
    def __init__(self):
        self.modules = {}
        self.groups = {}
        self.msg_id = 0
        self.configured = False
        self.pcap_thread = None
        self.dumbnet_thread = None
        self.fw = None
        self.data_dir = DATA_DIR
        self.devices = {}

        self.eth_checks = []
        self.ip_checks = []
        self.ip6_checks = []
        self.tcp_checks = []
        self.udp_checks = []
        self.sctp_checks = []

        self.module_active = []
        
        #gtk stuff
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)

        self.window.set_title(self.__class__.__name__)
        self.window.set_default_size(800, 600)

        #connect signal handlers
        self.window.connect("delete_event", self.delete_event)
        self.window.connect("destroy", self.destroy_event)

        self.toolbar = gtk.Toolbar()
        self.toolbar.set_tooltips(True)
        self.quit_button = gtk.ToolButton(gtk.STOCK_QUIT)
        self.quit_button.connect("clicked", self.on_quit_button_clicked)
        self.quit_button.set_tooltip_text("QUIT")
        self.toolbar.insert(self.quit_button, 0)
        self.about_button = gtk.ToolButton(gtk.STOCK_ABOUT)
        self.about_button.connect("clicked", self.on_about_button_clicked)
        self.about_button.set_tooltip_text("ABOUT")
        self.toolbar.insert(self.about_button, 0)
        self.log_button = gtk.ToolButton(gtk.STOCK_EDIT)
        self.log_button.connect("clicked", self.on_log_button_clicked)
        self.log_button.set_tooltip_text("LOG")
        self.toolbar.insert(self.log_button, 0)
        self.toolbar.insert(gtk.SeparatorToolItem(), 0)
        self.pref_button = gtk.ToolButton(gtk.STOCK_PREFERENCES)
        self.pref_button.connect("clicked", self.on_pref_button_clicked)
        self.pref_button.set_tooltip_text("PREFERENCES")
        self.toolbar.insert(self.pref_button, 0)
        self.network_button = gtk.ToolButton(gtk.STOCK_NETWORK)
        self.network_button.connect("clicked", self.on_network_button_clicked)
        self.network_button.set_tooltip_text("NETWORK")
        self.toolbar.insert(self.network_button, 0)
        self.toolbar.insert(gtk.SeparatorToolItem(), 0)
        self.open_togglebutton = gtk.ToggleToolButton(gtk.STOCK_OPEN)
        self.open_togglebutton.connect("toggled", self.on_open_togglebutton_toggled)
        self.open_togglebutton.set_tooltip_text("OPEN")
        self.toolbar.insert(self.open_togglebutton, 0)
        self.run_togglebutton = gtk.ToggleToolButton(gtk.STOCK_EXECUTE)
        self.run_togglebutton.connect("toggled", self.on_run_togglebutton_toogled)
        self.run_togglebutton.set_tooltip_text("RUN")
        self.toolbar.insert(self.run_togglebutton, 0)

        self.vbox = gtk.VBox(False, 0)
        self.vbox.pack_start(self.toolbar, False, False, 0)
        self.notebook = gtk.Notebook()
        self.vbox.pack_start(self.notebook, True, True, 0)
        self.statusbar = gtk.Statusbar()
        self.vbox.pack_start(self.statusbar, False, False, 0)
        self.window.add(self.vbox)

        self.log_textbuffer = gtk.TextBuffer()
        self.log_window = log_window(self.log_textbuffer)

    def main(self):
        print "This is %s version %s by Daniel Mende - dmende@ernw.de" % (self.__class__.__name__, VERSION)
        print "Running on %s" %(PLATFORM)

        self.load_all_modules()
        self.init_all_modules()
        self.window.show_all()
        
        gtk.main()

    def load_all_modules(self, path=DATA_DIR + MODULE_PATH):
        #import the modules
        if DEBUG:
            print "Loading modules..."
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
            print "Initialising modules..."
        for i in self.modules:
            self.init_module(i)
    
    def load_module(self, module, enabled=True):
        if DEBUG:
            print "load %s, enabled %i" % (module, enabled)
        try:
            mod = __import__(module)
            if DEBUG:
                print mod
            self.modules[module] = (mod.mod_class(self, PLATFORM), enabled)
        except Exception, e:
            print e
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60

    def init_module(self, module, pos=-1):
        if DEBUG:
            print "init %s" % module
        (mod, enabled) = self.modules[module]
        mod.set_log(self.log)
        try:
            root = mod.get_root()
        except Exception, e:
            print e
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
            print "failed to get root from module %s" % mod
            root = None
        if not root:
            root = gtk.Label(mod.name)
        group = getattr(mod, "group", "")
        if group != "":
            if group in self.groups:
                ntb = self.groups[group]
            else:
                ntb = gtk.Notebook()
                self.groups[group] = ntb
                self.notebook.insert_page(ntb, gtk.Label(group), 0)
            if root.get_parent():
                root.reparent(ntb)
                ntb.set_tab_label(root, gtk.Label(mod.name))
                ntb.reorder_child(root, pos)
            else:
                ntb.insert_page(root, gtk.Label(mod.name), pos)
            ntb.show_all()
        else:                
            if root.get_parent():
                root.reparent(self.notebook)
                self.notebook.set_tab_label(root, gtk.Label(mod.name))
                self.notebook.reorder_child(root, pos)
            else:
                self.notebook.insert_page(root, gtk.Label(mod.name), pos)
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
            if self.run_togglebutton.get_active():
                self.start_module(module)
                root.set_property("sensitive", True)
            else:
                root.set_property("sensitive", False)

        except Exception, e:
            print e
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
            print "failed to start module %s" % mod
        else:
            self.modules[module] = (mod, True)

    def load_mod_config(self, module):
        def str_(config, section, name, cdict):
            try:
                val = config.get(section, name)
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
                        print "conf %i from %s" % (len(cdict), file)
                    return cdict
        except Exception, e:
            print e
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
        return None

    def start_module(self, module):
        (mod, en) = self.modules[module]
        if en:
            try:
                if "set_ip" in dir(mod):
                    mod.set_ip(self.ip, self.mask)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if "set_ip6" in dir(mod):
                    mod.set_ip6(self.ip6, self.mask6, self.ip6_ll, self.mask6_ll)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if self.dumbnet_thread:
                    if "set_dumbnet" in dir(mod):
                        mod.set_dumbnet(self.dumbnet_thread)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if "set_fw" in dir(mod):
                    mod.set_fw(self.fw)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if "set_int" in dir(mod):
                    mod.set_int(self.interface)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                mod.start_mod()
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60

    def shut_module(self, module, delete=False):
        if DEBUG:
            print "shut %s" % module
        (mod, enabled) = self.modules[module]
        mod.shut_mod()
        for i in self.groups:
            ntb = self.groups[i]
            for j in ntb:
                if ntb.get_tab_label_text(j) == mod.name:
                    pos = ntb.page_num(j)
                    ntb.remove_page(pos)
                    #~ if ntb.get_n_pages() == 0:
                        #~ pos = self.notebook.page_num(ntb)
                        #~ self.notebook.remove_page(pos)
                        #~ del self.groups[i]
                        #~ print self.groups
                    break
            else:
                continue
            break
        for i in self.notebook:
            if self.notebook.get_tab_label_text(i) == mod.name:
                pos = self.notebook.page_num(i)
                self.notebook.remove_page(pos)
                break
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
        return pos

    def log(self, msg, module=None):
        #if not gtk.Object.flags(self.statusbar) & gtk.IN_DESTRUCTION:
        self.statusbar.push(self.msg_id, "[%i] %s" % (self.msg_id, msg))
        if DEBUG:
            print "[%i] %s" % (self.msg_id, msg)
        self.log_textbuffer.insert(self.log_textbuffer.get_end_iter(), "[%i] %s\n" % (self.msg_id, msg))
        self.msg_id += 1
        if module:
            if module not in self.module_active:
                for i in self.notebook:
                    if self.notebook.get_tab_label_text(i) == module:
                        if self.notebook.page_num(i) == self.notebook.get_current_page():
                            break
                        self.module_active.append(module)
                        self.flash_label(module, self.notebook.get_tab_label(i), 5)
                        break
                for i in self.groups:
                    ntb = self.groups[i]
                    for j in ntb:
                        if ntb.get_tab_label_text(j) == module:
                            if self.notebook.page_num(ntb) == self.notebook.get_current_page() and ntb.page_num(j) == ntb.get_current_page():
                                break
                            self.module_active.append(module)
                            self.flash_label(module, self.notebook.get_tab_label(ntb), 5)
                            self.module_active.append(self.notebook.get_tab_label_text(ntb))
                            self.flash_label(self.notebook.get_tab_label_text(ntb), ntb.get_tab_label(j), 5)
                            break
                    else:
                        continue
                    break

    def flash_label(self, module, label, times):
        if times > 0:
            if label.get_property("sensitive"):
                label.set_property("sensitive", False)
                gobject.timeout_add(500, self.flash_label, module, label, times)
            else:
                label.set_property("sensitive", True)
                gobject.timeout_add(500, self.flash_label, module, label, times - 1)
        else:
            self.module_active.remove(module)

    def send_msg(self, msg):
        dialog = gtk.MessageDialog(self.window, gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_INFO, gtk.BUTTONS_CLOSE, msg)
        label = gtk.Label(msg)
        dialog.vbox.pack_start(label, True, True, 0)
        dialog.run()
        dialog.destroy()
        
    def update_devices(self):
        self.devices = {}
        devs = pcap.findalldevs()
        for (name, descr, addr, flags) in devs:
            try:
                test = dumbnet.eth(name)
                mac = test.get()
                self.devices[name] = { 'mac' : mac, 'ip4' : [], 'ip6' : [], 'descr' : descr, 'flags' : flags }
            except:
                pass
            else:
                if len(addr) > 1:
                    for (ip, mask, net, gw) in addr:
                        try:
                            dumbnet.ip_aton(ip)
                            addr_dict = {}
                            addr_dict['ip'] = ip
                            addr_dict['mask'] = mask
                            addr_dict['net'] = net
                            addr_dict['gw'] = gw
                            self.devices[name]['ip4'].append(addr_dict)
                        except:
                            pass                            
                        try:
                            dumbnet.ip6_aton(ip)
                            addr_dict = {}
                            addr_dict['ip'] = ip
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

    ### EVENTS ###

    def on_run_togglebutton_toogled(self, btn):
        if btn.get_active():
            if not self.configured:
                self.on_network_button_clicked(None)
            if not self.configured:
                btn.set_active(False)
                return
            self.pcap_thread = pcap_thread(self, self.interface)
            self.dumbnet_thread = dumbnet_thread(self.interface)
            self.log("Listening on %s" % (self.interface))
            if PLATFORM != "Linux":
                self.fw = dumbnet.fw()
            for i in self.modules:
                self.start_module(i)
            for i in self.notebook:
                if self.notebook.get_tab_label_text(i) in self.groups:
                    ntb = self.groups[self.notebook.get_tab_label_text(i)]
                    for j in ntb:
                        j.set_property("sensitive", True)
                i.set_property("sensitive", True)
            self.network_button.set_property("sensitive", False)
            self.open_togglebutton.set_property("sensitive", False)
            self.dumbnet_thread.start()
            self.pcap_thread.start()
        else:
            for i in self.modules:
                (mod, en) = self.modules[i]
                mod.shut_mod()
            for i in self.notebook:
                if self.notebook.get_tab_label_text(i) in self.groups:
                    ntb = self.groups[self.notebook.get_tab_label_text(i)]
                    for j in ntb:
                        j.set_property("sensitive", False)
                i.set_property("sensitive", False)
            if self.pcap_thread:
                self.pcap_thread.quit()
                self.pcap_thread = None
            if self.dumbnet_thread:
                self.dumbnet_thread.quit()
                self.dumbnet_thread = None
            self.network_button.set_property("sensitive", True)
            self.open_togglebutton.set_property("sensitive", True)

    def on_open_togglebutton_toggled(self, btn):
        if btn.get_active():
            dialog = gtk.FileChooserDialog(title="Open", parent=self.window, action=gtk.FILE_CHOOSER_ACTION_OPEN, buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_OPEN,gtk.RESPONSE_OK))
            #dialog.set_current_folder()
            filter = gtk.FileFilter()
            filter.set_name("Pcap files")
            filter.add_pattern("*.cap")
            filter.add_pattern("*.pcap")
            dialog.add_filter(filter)
            filter = gtk.FileFilter()
            filter.set_name("All files")
            filter.add_pattern("*")
            dialog.add_filter(filter)
            response = dialog.run()
            if response == gtk.RESPONSE_OK:
                self.pcap_thread = pcap_thread_offline(self, dialog.get_filename())
                self.interface = "null"
                self.ip = "0.0.0.0"
                self.mask = "0.0.0.0"
                self.ip6 = "::"
                self.mask6 = "::"
                self.ip6_ll = "::"
                self.mask6_ll = "::"
                for i in self.modules:
                    self.start_module(i)
                for i in self.notebook:
                    if self.notebook.get_tab_label_text(i) in self.groups:
                        ntb = self.groups[self.notebook.get_tab_label_text(i)]
                        for j in ntb:
                            j.set_property("sensitive", True)
                    i.set_property("sensitive", True)
                self.run_togglebutton.set_property("sensitive", False)
                self.pcap_thread.start()
            else:
                btn.set_active(False)
            dialog.destroy()
        else:
            for i in self.modules:
                (mod, en) = self.modules[i]
                mod.shut_mod()
            for i in self.notebook:
                if self.notebook.get_tab_label_text(i) in self.groups:
                    ntb = self.groups[self.notebook.get_tab_label_text(i)]
                    for j in ntb:
                        j.set_property("sensitive", False)
                i.set_property("sensitive", False)
            if self.pcap_thread:
                self.pcap_thread.quit()
                self.pcap_thread = None
            self.run_togglebutton.set_property("sensitive", True)

    def on_pref_button_clicked(self, data):
        pref_window = preference_window(self)
        pref_window.show_all()

    def on_log_button_clicked(self, data):
        l_window = log_window(self.log_textbuffer)
        l_window.show_all()
    
    def on_network_combobox_changed(self, box, label):
        if PLATFORM == "Windows":
            descr = box.get_active_text()
            dev = None
            for i in self.devices:
                if self.devices[i]['descr'] == descr:
                    dev = i
            assert(dev != None)
        else:
            dev = box.get_active_text()
        str = ""
        if dev:
            if len(self.devices[dev]['ip4']) > 0:
                str += "\nIPv4:"
                for i in self.devices[dev]['ip4']:
                    str += "\n\t%s\n\t\t%s" % (i['ip'], i['mask'])
            else:
                str += "\nNo IPv4 Address"
            if len(self.devices[dev]['ip6']) > 0:
                str += "\nIPv6:"
                for i in self.devices[dev]['ip6']:
                    str += "\n\t%s\n\t\t%s" % (i['ip'], i['mask'])
            else:
                str += "\nNo IPv6 Address"
        label.set_text(str)
        
    def on_network_button_clicked(self, data):
        self.update_devices()
        
        dialog = gtk.MessageDialog(self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Select the interface to use")
        box = gtk.combo_box_new_text()
        for dev in self.devices:
            if PLATFORM == "Windows":
                box.append_text(self.devices[dev]['descr'])
            else:
                box.append_text(dev)
        dialog.vbox.pack_start(box)
        label = gtk.Label()
        dialog.vbox.pack_start(label)
        box.connect('changed', self.on_network_combobox_changed, label)
        dialog.vbox.show_all()
        
        box.set_active(0)
        ret = dialog.run()
        dialog.destroy()
        if ret == gtk.RESPONSE_OK:
            if PLATFORM == "Windows":
                self.interface = None
                descr = box.get_active_text()
                for i in self.devices:
                    if self.devices[i]['descr'] == descr:
                        self.interface = i
                assert(self.interface != None)
            else:
                self.interface = box.get_active_text()
            
            select4 = len(self.devices[self.interface]['ip4']) > 1
            if select4:
                dialog = gtk.MessageDialog(self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Select the interface to use")
                label = gtk.Label("Select the IPv4 address to use:")
                dialog.vbox.pack_start(label)
                box4 = gtk.combo_box_new_text()
                for i in self.devices[self.interface]['ip4']:
                    box4.append_text("%s %s" % (i['ip'], i['mask']))
                dialog.vbox.pack_start(box4)
                box4.set_active(0)
                dialog.vbox.show_all()
                ret = dialog.run()
                dialog.destroy()
                if ret != gtk.RESPONSE_OK:
                    return
                active = box4.get_active()
                self.ip = self.devices[self.interface]['ip4'][active]['ip']
                self.mask = self.devices[self.interface]['ip4'][active]['mask']
            else:
                if len(self.devices[self.interface]['ip4']) > 0:
                        self.ip = self.devices[self.interface]['ip4'][0]['ip']
                        self.mask = self.devices[self.interface]['ip4'][0]['mask']
                else:
                    self.ip = "0.0.0.0"
                    self.mask ="0.0.0.0"

            select6 = len(self.devices[self.interface]['ip6']) > 1
            v6done = False
            if select6:
                nl = 0
                ip = None
                mask = None
                for i in self.devices[self.interface]['ip6']:
                    if i['linklocal']:
                        self.ip6_ll = i['ip']
                        self.mask6_ll = i['mask']
                    else:
                        ip = i['ip']
                        mask = i['mask']
                        nl += 1
                if nl > 1:
                    dialog = gtk.MessageDialog(self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Select the interface to use")
                    label = gtk.Label("Select the IPv6 address to use:")
                    dialog.vbox.pack_start(label)
                    box6 = gtk.combo_box_new_text()
                    for i in self.devices[self.interface]['ip6']:
                        if not i['linklocal']:
                            box6.append_text("%s %s" % (i['ip'], i['mask']))
                    dialog.vbox.pack_start(box6)
                    box6.set_active(0)                        
                    dialog.vbox.show_all()
                    ret = dialog.run()
                    dialog.destroy()
                    if ret != gtk.RESPONSE_OK:
                        return
                    active = box6.get_active()
                    self.ip6 = self.devices[self.interface]['ip6'][active]['ip']
                    self.mask6 = self.devices[self.interface]['ip6'][active]['mask']
                    if self.ip6.startswith("fe80:"):
                        self.ip6_ll = self.ip6
                        self.mask6_ll = self.mask6
                else:
                    self.ip6 = ip
                    self.mask6 = mask
                    select6 = False
                    v6done = True
            else:
                if not v6done:
                    if len(self.devices[self.interface]['ip6']) > 0:
                        self.ip6 = self.devices[self.interface]['ip6'][0]['ip']
                        self.mask6 = self.devices[self.interface]['ip6'][0]['mask']
                        if self.ip6.startswith("fe80:"):
                            self.ip6_ll = self.ip6
                            self.mask6_ll = self.mask6
                    else:
                        self.ip6 = "::"
                        self.mask6 ="::"
                        self.ip6_ll = "::"
                        self.mask6_ll = "::"
            self.configured = True

    def on_about_button_clicked(self, data):
        window = about_window(self)
        window.show_all()

    def on_quit_button_clicked(self, data, foo=None):
        self.delete_event(None, None)
        self.destroy_event(None)
    
    def delete_event(self, widget, event, data=None):
        for i in self.modules.keys():
            (module, enabled) = self.modules[i]
            module.shut_mod()
        if self.pcap_thread:
            self.pcap_thread.quit()
        if self.dumbnet_thread:
            self.dumbnet_thread.quit()
        return False

    def destroy_event(self, widget, data=None):
        gtk.main_quit()

if __name__ == '__main__':
    if PLATFORM == "Linux" or PLATFORM == "FreeBSD" or PLATFORM == "Darwin":
        if os.geteuid() != 0:
            print "You must be root to run this script."
            sys.exit(1)
        import pcap
    elif PLATFORM == "Windows":
        def error():
            dialog = gtk.MessageDialog(gtk.Window(gtk.WINDOW_TOPLEVEL), gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, "Please install WinPcap to run Loki.")
            ret = dialog.run()
            dialog.destroy()
            sys.exit(1)
        try:
            import pcap
        except:
            gobject.timeout_add(100, error)
            gtk.main()
    else:
        print "%s is not supported yet." % (PLATFORM)
        sys.exit(1)
    app = codename_loki()
    signal.signal(signal.SIGINT, app.on_quit_button_clicked)
    try:
        app.main()
    except Exception, e:
        print e
        if DEBUG:
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
        app.delete_event(None, None)
    except:
        app.delete_event(None, None)

