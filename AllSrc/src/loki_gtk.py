#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       loki_gtk.py
#       
#       Copyright 2014 Daniel Mende <mail@c0decafe.de>
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

import base64
import copy
import hashlib
import sys
import os
import platform
import threading
import time
import traceback
import signal
import string
import struct

import ConfigParser

import dpkt
import dnet
import IPy

import loki

import pygtk
pygtk.require('2.0')

import gobject
import gtk
gtk.gdk.threads_init()

DEBUG = loki.DEBUG

VERSION = loki.VERSION
PLATFORM = loki.PLATFORM

MODULE_PATH = loki.MODULE_PATH
CONFIG_PATH = loki.CONFIG_PATH
DATA_DIR = loki.DATA_DIR

class network_window(object):
    BR_INT_ROW = 0
    BR_MAC_ROW = 1
    BR_ADR_ROW = 2
    BR_NET_ROW = 3
    BR_ACT_ROW = 4
    BR_INT_EDIT_ROW = 5
    BR_MAC_EDIT_ROW = 6
    BR_ADR_EDIT_ROW = 7
    BR_NET_EDIT_ROW = 8
    
    L2_SRC_INT_ROW = 0
    L2_SRC_DST_IP_ROW = 1
    L2_SRC_TO_MAC_ROW = 2
    L2_SRC_ACTIVE_ROW = 3
    
    L2_DST_INT_ROW = 0
    L2_DST_SRC_IP_ROW = 1
    L2_DST_TO_MAC_ROW = 2
    L2_DST_ACTIVE_ROW = 3
    
    L3_SRC_INT_ROW = 0
    L3_SRC_SRC_ROW = 1
    L3_SRC_DST_ROW = 2
    L3_SRC_PROTO_ROW = 3
    L3_SRC_DPORT_ROW = 4
    L3_SRC_TO_ROW = 5
    L3_SRC_ACTIVE_ROW = 6
    
    L3_DST_INT_ROW = 0
    L3_DST_SRC_ROW = 1
    L3_DST_DST_ROW = 2
    L3_DST_PROTO_ROW = 3
    L3_DST_DPORT_ROW = 4
    L3_DST_TO_ROW = 5
    L3_DST_ACTIVE_ROW = 6
    
    DEBUG = False
        
    def __init__(self, parent):
        self.parent = parent
        self.interfaces_liststore = gtk.ListStore(str)
        self.macaddresses_liststore = gtk.ListStore(str)
        self.addresses_liststore = gtk.ListStore(str)
        self.netmasks_liststore = gtk.ListStore(str)
        self.protocols_liststore = gtk.ListStore(str)
        self.protocols_liststore.append(["tcp"])
        self.protocols_liststore.append(["udp"])
        self.ports_liststore = gtk.ListStore(int)
        self.br_treestore = gtk.TreeStore(str, str, str, str, bool, bool, bool, bool, bool)
        self.l2_src_liststore = gtk.ListStore(str, str, str, bool)
        self.l2_dst_liststore = gtk.ListStore(str, str, str, bool)
        self.l3_src_liststore = gtk.ListStore(str, str, str, str, int, str, bool)
        self.l3_dst_liststore = gtk.ListStore(str, str, str, str, int, str, bool)
         
        self.glade_xml = gtk.glade.XML(DATA_DIR + MODULE_PATH + "/network_config.glade")
        dic = { "on_br_add_toolbutton_clicked" : self.on_br_add_toolbutton_clicked,
                "on_br_del_toolbutton_clicked" : self.on_br_del_toolbutton_clicked,
                "on_br_new_toolbutton_clicked" : self.on_br_new_toolbutton_clicked,
                "on_br_run_toolbutton_toggled" : self.on_br_run_toolbutton_toggled,
                "on_l2_src_add_toolbutton_clicked" : self.on_l2_src_add_toolbutton_clicked,
                "on_l2_src_del_toolbutton_clicked" : self.on_l2_src_del_toolbutton_clicked,
                "on_l2_src_new_toolbutton_clicked" : self.on_l2_src_new_toolbutton_clicked,
                "on_l2_dst_add_toolbutton_clicked" : self.on_l2_dst_add_toolbutton_clicked,
                "on_l2_dst_del_toolbutton_clicked" : self.on_l2_dst_del_toolbutton_clicked,
                "on_l2_dst_new_toolbutton_clicked" : self.on_l2_dst_new_toolbutton_clicked,
                "on_l2_run_toolbutton_toggled" : self.on_l2_run_toolbutton_toggled,
                "on_l3_src_add_toolbutton_clicked" : self.on_l3_src_add_toolbutton_clicked,
                "on_l3_src_del_toolbutton_clicked" : self.on_l3_src_del_toolbutton_clicked,
                "on_l3_src_new_toolbutton_clicked" : self.on_l3_src_new_toolbutton_clicked,
                "on_l3_dst_add_toolbutton_clicked" : self.on_l3_dst_add_toolbutton_clicked,
                "on_l3_dst_del_toolbutton_clicked" : self.on_l3_dst_del_toolbutton_clicked,
                "on_l3_dst_new_toolbutton_clicked" : self.on_l3_dst_new_toolbutton_clicked,
                "on_l3_run_toolbutton_toggled" : self.on_l3_run_toolbutton_toggled,
                "on_open_toolbutton_clicked" : self.on_open_toolbutton_clicked,
                "on_save_toolbutton_clicked" : self.on_save_toolbutton_clicked,
                "on_ok_button_clicked" : self.on_ok_button_clicked,
                "on_cancel_button_clicked" : self.on_cancel_button_clicked,
                }
        self.glade_xml.signal_autoconnect(dic)
        
        self.window = self.glade_xml.get_widget("network_window")
        #~ self.window.set_parent(self.parent.window)
        
        self.br_treeview = self.glade_xml.get_widget("br_treeview")
        self.br_treeview.set_model(self.br_treestore)
        self.br_treeview.set_headers_visible(True)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.interfaces_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_br_interfaces_combo_changed)
        column = gtk.TreeViewColumn("Interface", renderer_combo, text=self.BR_INT_ROW, editable=self.BR_INT_EDIT_ROW)
        self.br_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.macaddresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_br_macaddress_combo_changed)
        column = gtk.TreeViewColumn("MAC Address", renderer_combo, text=self.BR_MAC_ROW, editable=self.BR_MAC_EDIT_ROW)
        self.br_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_br_address_combo_changed)
        column = gtk.TreeViewColumn("Address", renderer_combo, text=self.BR_ADR_ROW, editable=self.BR_ADR_EDIT_ROW)
        self.br_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.netmasks_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_br_netmasks_combo_changed)
        column = gtk.TreeViewColumn("Netmask", renderer_combo, text=self.BR_NET_ROW, editable=self.BR_NET_EDIT_ROW)
        self.br_treeview.append_column(column)
        
        renderer_toggle = gtk.CellRendererToggle()
        renderer_toggle.connect("toggled", self.on_br_active_toggle_toggled)
        column = gtk.TreeViewColumn("Active", renderer_toggle, active=self.BR_ACT_ROW)
        self.br_treeview.append_column(column)
        
        self.l2_src_treeview = self.glade_xml.get_widget("l2_src_treeview")
        self.l2_src_treeview.set_model(self.l2_src_liststore)
        self.l2_src_treeview.set_headers_visible(True)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.interfaces_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l2_src_interfaces_combo_changed)
        column = gtk.TreeViewColumn("Interface", renderer_combo, text=self.L2_SRC_INT_ROW)
        self.l2_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l2_src_address_combo_changed)
        column = gtk.TreeViewColumn("Destination IP address", renderer_combo, text=self.L2_SRC_DST_IP_ROW)
        self.l2_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.macaddresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l2_src_macaddress_combo_changed)
        column = gtk.TreeViewColumn("NAT source MAC", renderer_combo, text=self.L2_SRC_TO_MAC_ROW)
        self.l2_src_treeview.append_column(column)
        
        renderer_toggle = gtk.CellRendererToggle()
        renderer_toggle.connect("toggled", self.on_l2_src_active_toggle_toggled)
        column = gtk.TreeViewColumn("Active", renderer_toggle, active=self.L2_SRC_ACTIVE_ROW)
        self.l2_src_treeview.append_column(column)
        
        self.l2_dst_treeview = self.glade_xml.get_widget("l2_dst_treeview")
        self.l2_dst_treeview.set_model(self.l2_dst_liststore)
        self.l2_dst_treeview.set_headers_visible(True)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.interfaces_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l2_dst_interfaces_combo_changed)
        column = gtk.TreeViewColumn("Interface", renderer_combo, text=self.L2_DST_INT_ROW)
        self.l2_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l2_dst_address_combo_changed)
        column = gtk.TreeViewColumn("Source IP address", renderer_combo, text=self.L2_DST_SRC_IP_ROW)
        self.l2_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.macaddresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l2_dst_macaddress_combo_changed)
        column = gtk.TreeViewColumn("NAT destination MAC", renderer_combo, text=self.L2_DST_TO_MAC_ROW)
        self.l2_dst_treeview.append_column(column)
        
        renderer_toggle = gtk.CellRendererToggle()
        renderer_toggle.connect("toggled", self.on_l2_dst_active_toggle_toggled)
        column = gtk.TreeViewColumn("Active", renderer_toggle, active=self.L2_DST_ACTIVE_ROW)
        self.l2_dst_treeview.append_column(column)
        
        self.l3_src_treeview = self.glade_xml.get_widget("l3_src_treeview")
        self.l3_src_treeview.set_model(self.l3_src_liststore)
        self.l3_src_treeview.set_headers_visible(True)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.interfaces_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_src_interfaces_combo_changed)
        column = gtk.TreeViewColumn("Interface", renderer_combo, text=self.L3_SRC_INT_ROW)
        self.l3_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_src_saddress_combo_changed)
        column = gtk.TreeViewColumn("Source IP address", renderer_combo, text=self.L3_SRC_SRC_ROW)
        self.l3_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_src_daddress_combo_changed)
        column = gtk.TreeViewColumn("Destination IP address", renderer_combo, text=self.L3_SRC_DST_ROW)
        self.l3_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.protocols_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_src_proto_combo_changed)
        column = gtk.TreeViewColumn("Protocol", renderer_combo, text=self.L3_SRC_PROTO_ROW)
        self.l3_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.ports_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_src_dport_combo_changed)
        column = gtk.TreeViewColumn("Destination port", renderer_combo, text=self.L3_SRC_DPORT_ROW)
        self.l3_src_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_src_toaddress_combo_changed)
        column = gtk.TreeViewColumn("To IP address", renderer_combo, text=self.L3_SRC_TO_ROW)
        self.l3_src_treeview.append_column(column)
        
        renderer_toggle = gtk.CellRendererToggle()
        renderer_toggle.connect("toggled", self.on_l3_src_active_toggle_toggled)
        column = gtk.TreeViewColumn("Active", renderer_toggle, active=self.L3_SRC_ACTIVE_ROW)
        self.l3_src_treeview.append_column(column)
        
        self.l3_dst_treeview = self.glade_xml.get_widget("l3_dst_treeview")
        self.l3_dst_treeview.set_model(self.l3_dst_liststore)
        self.l3_dst_treeview.set_headers_visible(True)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.interfaces_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_dst_interfaces_combo_changed)
        column = gtk.TreeViewColumn("Interface", renderer_combo, text=self.L3_DST_INT_ROW)
        self.l3_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_dst_saddress_combo_changed)
        column = gtk.TreeViewColumn("Source IP address", renderer_combo, text=self.L3_DST_SRC_ROW)
        self.l3_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_dst_daddress_combo_changed)
        column = gtk.TreeViewColumn("Destination IP address", renderer_combo, text=self.L3_DST_DST_ROW)
        self.l3_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.protocols_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_dst_proto_combo_changed)
        column = gtk.TreeViewColumn("Protocol", renderer_combo, text=self.L3_DST_PROTO_ROW)
        self.l3_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.ports_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_dst_dport_combo_changed)
        column = gtk.TreeViewColumn("Destination port", renderer_combo, text=self.L3_DST_DPORT_ROW)
        self.l3_dst_treeview.append_column(column)
        
        renderer_combo = gtk.CellRendererCombo()
        renderer_combo.set_property("editable", True)
        renderer_combo.set_property("model", self.addresses_liststore)
        renderer_combo.set_property("text-column", 0)
        renderer_combo.set_property("has-entry", True)
        renderer_combo.connect("edited", self.on_l3_dst_toaddress_combo_changed)
        column = gtk.TreeViewColumn("To IP address", renderer_combo, text=self.L3_DST_TO_ROW)
        self.l3_dst_treeview.append_column(column)
        
        renderer_toggle = gtk.CellRendererToggle()
        renderer_toggle.connect("toggled", self.on_l3_dst_active_toggle_toggled)
        column = gtk.TreeViewColumn("Active", renderer_toggle, active=self.L3_DST_ACTIVE_ROW)
        self.l3_dst_treeview.append_column(column)
        
        self.filechooser = gtk.FileChooserDialog("Open..",
                               None,
                               gtk.FILE_CHOOSER_ACTION_OPEN,
                               (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        self.filechooser.set_default_response(gtk.RESPONSE_OK)

        filter = gtk.FileFilter()
        filter.set_name("All files")
        filter.add_pattern("*")
        self.filechooser.add_filter(filter)

        filter = gtk.FileFilter()
        filter.set_name("Config file")
        filter.add_pattern("*.cfg")
        self.filechooser.add_filter(filter)
        
        self.devices = self.get_devices()
        
    def on_br_interfaces_combo_changed(self, widget, path, text):
        self.br_treestore[path][self.BR_INT_ROW] = text
        self.add_interfaces_store(text)
        try:
            mac = dnet.eth_ntoa(self.devices[text]["mac"])
            self.br_treestore[path][self.BR_MAC_ROW] = mac
        except:
            pass
    
    def on_br_macaddress_combo_changed(self, widget, path, text):
        if self.check_macaddress(text):
            self.br_treestore[path][self.BR_MAC_ROW] = text
            self.add_macaddresses_store(text)
    
    def on_br_address_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.br_treestore[path][self.BR_ADR_ROW] = text
            self.add_addresses_store(text)
    
    def on_br_netmasks_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.br_treestore[path][self.BR_NET_ROW] = text
            self.add_netmasks_store(text)
    
    def on_br_active_toggle_toggled(self, widget, path):
        self.br_treestore[path][self.BR_ACT_ROW] = not self.br_treestore[path][self.BR_ACT_ROW]
    
    def on_l2_src_interfaces_combo_changed(self, widget, path, text):
        self.l2_src_liststore[path][self.L2_SRC_INT_ROW] = text
        self.add_interfaces_store(text)
    
    def on_l2_src_address_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l2_src_liststore[path][self.L2_SRC_DST_IP_ROW] = text
            self.add_addresses_store(text)
        
    def on_l2_src_macaddress_combo_changed(self, widget, path, text):
        if self.check_macaddress(text):
            self.l2_src_liststore[path][self.L2_DST_TO_MAC_ROW] = text
            self.add_macaddresses_store(text)
    
    def on_l2_src_active_toggle_toggled(self, widget, path):
        self.l2_src_liststore[path][self.L2_SRC_ACTIVE_ROW] = not self.l2_src_liststore[path][self.L2_SRC_ACTIVE_ROW]
    
    def on_l2_dst_interfaces_combo_changed(self, widget, path, text):
        self.l2_dst_liststore[path][self.L2_DST_INT_ROW] = text
        self.add_interfaces_store(text)
    
    def on_l2_dst_address_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l2_dst_liststore[path][self.L2_DST_SRC_IP_ROW] = text
            self.add_addresses_store(text)
        
    def on_l2_dst_macaddress_combo_changed(self, widget, path, text):
        if self.check_macaddress(text):
            self.l2_dst_liststore[path][self.L2_DST_TO_MAC_ROW] = text
            self.add_macaddresses_store(text)
    
    def on_l2_dst_active_toggle_toggled(self, widget, path):
        self.l2_dst_liststore[path][self.L2_DST_ACTIVE_ROW] = not self.l2_dst_liststore[path][self.L2_DST_ACTIVE_ROW]
    
    def on_l3_src_interfaces_combo_changed(self, widget, path, text):
        self.l3_src_liststore[path][self.L3_SRC_INT_ROW] = text
        self.add_interfaces_store(text)
        
    def on_l3_src_saddress_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l3_src_liststore[path][self.L3_SRC_SRC_ROW] = text
            self.add_addresses_store(text)
    
    def on_l3_src_daddress_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l3_src_liststore[path][self.L3_SRC_DST_ROW] = text
            self.add_addresses_store(text)
    
    def on_l3_src_proto_combo_changed(self, widget, path, text):
        self.l3_src_liststore[path][self.L3_SRC_PROTO_ROW] = text
        self.add_protocols_store(text)
    
    def on_l3_src_dport_combo_changed(self, widget, path, text):
        if self.check_port(text):
            port = int(text)
            self.l3_src_liststore[path][self.L3_SRC_DPORT_ROW] = port
            self.add_ports_store(port)
    
    def on_l3_src_toaddress_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l3_src_liststore[path][self.L3_SRC_TO_ROW] = text
            self.add_addresses_store(text)
    
    def on_l3_src_active_toggle_toggled(self, widget, path):
        self.l3_src_liststore[path][self.L3_SRC_ACTIVE_ROW] = not self.l3_src_liststore[path][self.L3_SRC_ACTIVE_ROW]
    
    def on_l3_dst_interfaces_combo_changed(self, widget, path, text):
        self.l3_dst_liststore[path][self.L3_DST_INT_ROW] = text
        self.add_interfaces_store(text)
        
    def on_l3_dst_saddress_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l3_dst_liststore[path][self.L3_DST_SRC_ROW] = text
            self.add_addresses_store(text)
    
    def on_l3_dst_daddress_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l3_dst_liststore[path][self.L3_DST_DST_ROW] = text
            self.add_addresses_store(text)
    
    def on_l3_dst_proto_combo_changed(self, widget, path, text):
        self.l3_dst_liststore[path][self.L3_DST_PROTO_ROW] = text
        self.add_protocols_store(text)
    
    def on_l3_dst_dport_combo_changed(self, widget, path, text):
        if self.check_port(text):
            port = int(text)
            self.l3_dst_liststore[path][self.L3_DST_DPORT_ROW] = port
            self.add_ports_store(port)
    
    def on_l3_dst_toaddress_combo_changed(self, widget, path, text):
        if self.check_address(text):
            self.l3_dst_liststore[path][self.L3_DST_TO_ROW] = text
            self.add_addresses_store(text)
    
    def on_l3_dst_active_toggle_toggled(self, widget, path):
        self.l3_dst_liststore[path][self.L3_DST_ACTIVE_ROW] = not self.l3_dst_liststore[path][self.L3_DST_ACTIVE_ROW]
        
    def add_interfaces_store(self, interf):
        for row in self.interfaces_liststore:
            if row[0] == interf:
                return
        self.interfaces_liststore.append([interf])
    
    def add_macaddresses_store(self, addr):
        for row in self.macaddresses_liststore:
            if row[0] == addr:
                return
        self.macaddresses_liststore.append([addr])
        
    def add_addresses_store(self, addr):
        for row in self.addresses_liststore:
            if row[0] == addr:
                return
        self.addresses_liststore.append([addr])
    
    def add_netmasks_store(self, mask):
        for row in self.netmasks_liststore:
            if row[0] == mask:
                return
        self.netmasks_liststore.append([mask])
    
    def add_protocols_store(self, proto):
        for row in self.protocols_liststore:
            if row[0] == proto:
                return
        self.protos_liststore.append([proto])
    
    def add_ports_store(self, port):
        for row in self.ports_liststore:
            if row[0] == port:
                return
        self.ports_liststore.append([port])
    
    def check_macaddress(self, address):
        try:
            dnet.eth_aton(address)
        except:
            self.msg("MAC Address invalid")
            return False
        return True
    
    def check_address(self, address):
        try:
            dnet.ip_aton(address)
        except:
            try:
                dnet.ip6_aton(address)
            except:
                self.msg("Address invalid")
                return False
        return True
    
    def check_port(self, port):
        if type(port) == str:
            try:
                port = int(port)
            except:
                self.msg("Port invalid, no int")
                return False
        if port < 0 or port > 65535:
            self.msg("Port invalid, out of range")
            return False
        return True
    
    def on_br_add_toolbutton_clicked(self, btn):
        select = self.br_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) > 0:
            for i in paths:
                dev = self.select_device()
                if not dev is None:
                    self.br_treestore.append(model.get_iter(i), [dev, dnet.eth_ntoa(self.devices[dev]["mac"]), "", "", True, True, False, False, False])
        else:
            self.br_treestore.append(None, ["br23", "00:01:02:03:04:05", "0.0.0.0", "0.0.0.0", True, True, True, True, True])

    def on_br_del_toolbutton_clicked(self, btn):
        select = self.br_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) > 0:
            for i in paths:
                del self.br_treestore[i]
    
    def on_br_new_toolbutton_clicked(self, btn):
        #~ self.interfaces_liststore.clear()
        #~ self.macaddresses_liststore.clear()
        #~ self.addresses_liststore.clear()
        #~ self.netmasks_liststore.clear()
        self.br_treestore.clear()
        #~ self.devices = self.get_devices()
    
    def on_br_run_toolbutton_toggled(self, btn):
        if btn.get_active():
            self.execute_br()
        else:
            self.unexecute_br()
    
    def on_l2_src_add_toolbutton_clicked(self, btn):
        self.l2_src_liststore.append(["br23", "0.0.0.0", "00:01:02:03:04:05", True])
        
    def on_l2_src_del_toolbutton_clicked(self, btn):
        select = self.l2_src_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) > 0:
            for i in paths:
                del self.l2_src_liststore[i]
        
    def on_l2_src_new_toolbutton_clicked(self, btn):
        self.l2_src_liststore.clear()
        
    def on_l2_dst_add_toolbutton_clicked(self, btn):
        self.l2_dst_liststore.append(["br23", "0.0.0.0", "00:01:02:03:04:05", True])
        
    def on_l2_dst_del_toolbutton_clicked(self, btn):
        select = self.l2_dst_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) > 0:
            for i in paths:
                del self.l2_dst_liststore[i]
        
    def on_l2_dst_new_toolbutton_clicked(self, btn):
        self.l2_dst_liststore.clear()
        
    def on_l2_run_toolbutton_toggled(self, btn):
        if btn.get_active():
            self.execute_l2()
        else:
            self.unexecute_l2()
    
    def on_l3_src_add_toolbutton_clicked(self, btn):
        self.l3_src_liststore.append(["br23", "0.0.0.0", "0.0.0.0", "tcp", 80, "0.0.0.0", True])
    
    def on_l3_src_del_toolbutton_clicked(self, btn):
        select = self.l3_src_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) > 0:
            for i in paths:
                del self.l3_src_liststore[i]
    
    def on_l3_src_new_toolbutton_clicked(self, btn):
        self.l3_src_liststore.clear()
        
    def on_l3_dst_add_toolbutton_clicked(self, btn):
        self.l3_dst_liststore.append(["br23", "0.0.0.0", "0.0.0.0", "tcp", 80, "0.0.0.0", True])
    
    def on_l3_dst_del_toolbutton_clicked(self, btn):
        select = self.l3_dst_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) > 0:
            for i in paths:
                del self.l3_dst_liststore[i]
    
    def on_l3_dst_new_toolbutton_clicked(self, btn):
        self.l3_dst_liststore.clear()
    
    def on_l3_run_toolbutton_toggled(self, btn):
        if btn.get_active():
            self.execute_l3()
        else:
            self.unexecute_l3()
        
    def on_open_toolbutton_clicked(self, btn):
        response = self.filechooser.run()
        if response == gtk.RESPONSE_OK:
            self.load_config(self.filechooser.get_filename())
        self.filechooser.hide()
    
    def on_save_toolbutton_clicked(self, btn):
        response = self.filechooser.run()
        if response == gtk.RESPONSE_OK:
            self.save_config(self.filechooser.get_filename())
        self.filechooser.hide()
    
    def on_ok_button_clicked(self, btn):
        self.save_config(CONFIG_PATH + "/network.cfg")
        self.execute_br()
        self.execute_l2()
        self.execute_l3()
        self.parent.netcfg_configured = True
        self.parent.select_interface()
        self.window.hide()
    
    def on_cancel_button_clicked(self, btn):
        self.window.hide()
    
    def read_br_config(self):
        config = []
        i = self.br_treestore.get_iter_root()
        while i != None:
            (act, dev, mac, ip, mask) = self.br_treestore.get(i, self.BR_ACT_ROW, self.BR_INT_ROW, self.BR_MAC_ROW, self.BR_ADR_ROW, self.BR_NET_ROW)
            if not act:
                i = self.br_treestore.iter_next(i)
                continue
            if dev in self.devices:
                self.msg("Device '%s' already exists" % dev)
                i = self.br_treestore.iter_next(i)
                continue
            if not self.br_treestore.iter_has_child(i):
                self.msg("No Interfaces added to bridge")
                i = self.br_treestore.iter_next(i)
                continue
            ifs = []
            j = self.br_treestore.iter_children(i)
            while j != None:
                (interf, active) = self.br_treestore.get(j, self.BR_INT_ROW, self.BR_ACT_ROW)
                if interf not in self.devices:
                    self.msg("Interface not found")
                    j = self.br_treestore.iter_next(j)
                    continue
                ifs.append({ "dev" : interf,
                             "act" : active })
                j = self.br_treestore.iter_next(j)
            i = self.br_treestore.iter_next(i)
            config.append({ "act" : act,
                            "dev" : dev,
                            "mac" : mac,
                            "ip"  : ip,
                            "mask": mask,
                            "ifs" : ifs })
        return config
    
    def read_l2_config(self):
        src = [ { "act" : i[self.L2_SRC_ACTIVE_ROW],
                  "dev" : i[self.L2_SRC_INT_ROW],
                  "ip"  : i[self.L2_SRC_DST_IP_ROW],
                  "mac" : i[self.L2_SRC_TO_MAC_ROW]
                  } for i in self.l2_src_liststore ]
        dst = [ { "act" : i[self.L2_DST_ACTIVE_ROW],
                  "dev" : i[self.L2_DST_INT_ROW],
                  "ip"  : i[self.L2_DST_SRC_IP_ROW],
                  "mac" : i[self.L2_DST_TO_MAC_ROW]
                  } for i in self.l2_dst_liststore ]
        return { "src" : src, "dst" : dst }
    
    def read_l3_config(self):
        src = [ { "act" : i[self.L3_SRC_ACTIVE_ROW],
                  "dev" : i[self.L3_SRC_INT_ROW],
                  "src" : i[self.L3_SRC_SRC_ROW],
                  "dst" : i[self.L3_SRC_DST_ROW],
                  "proto": i[self.L3_SRC_PROTO_ROW],
                  "dport": i[self.L3_SRC_DPORT_ROW],
                  "to"  : i[self.L3_SRC_TO_ROW]
                  } for i in self.l3_src_liststore ]
        dst = [ { "act" : i[self.L3_DST_ACTIVE_ROW],
                  "dev" : i[self.L3_DST_INT_ROW],
                  "src" : i[self.L3_DST_SRC_ROW],
                  "dst" : i[self.L3_DST_DST_ROW],
                  "proto": i[self.L3_DST_PROTO_ROW],
                  "dport": i[self.L3_DST_DPORT_ROW],
                  "to"  : i[self.L3_DST_TO_ROW]
                  } for i in self.l3_dst_liststore ]
        return { "src" : src, "dst" : dst }
    
    def load_config(self, filename):
        parser = ConfigParser.RawConfigParser()
        try:
            parser.read(filename)
        except Exception, e:
            self.log("Can't read config: %s" %e)
            return
        br_config = []
        l2_config = { "src" : [], "dst" : []}
        l3_config = { "src" : [], "dst" : []}
        for i in parser.sections():
            if i.startswith("br_"):
                br_config.append({ "act" : parser.getboolean(i, "active"),
                                   "dev" : parser.get(i, "device"),
                                   "mac" : parser.get(i, "mac"),
                                   "ip"  : parser.get(i, "address"),
                                   "mask": parser.get(i, "netmask"),
                                   "ifs" : [ { "dev" : j.split("_")[1],
                                               "act" : parser.get(i, j) }
                                             for j in parser.options(i) if j.startswith("if_") ]
                                    })
            elif i.startswith("l2_src"):
                l2_config["src"].append(  { "act" : parser.getboolean(i, "active"),
                                            "dev" : parser.get(i, "device"),
                                            "ip"  : parser.get(i, "address"),
                                            "mac" : parser.get(i, "mac") })
            elif i.startswith("l2_dst_"):
                l2_config["dst"].append(  { "act" : parser.getboolean(i, "active"),
                                            "dev" : parser.get(i, "device"),
                                            "ip"  : parser.get(i, "address"),
                                            "mac" : parser.get(i, "mac") })
            elif i.startswith("l3_src"):
                l3_config["src"].append(  { "act" : parser.getboolean(i, "active"),
                                            "dev" : parser.get(i, "device"),
                                            "src" : parser.get(i, "source"),
                                            "dst" : parser.get(i, "destination"),
                                            "proto": parser.get(i, "protocol"),
                                            "dport": parser.getint(i, "dport"),
                                            "to"  : parser.get(i, "to") })
            elif i.startswith("l3_dst"):
                l3_config["dst"].append(  { "act" : parser.getboolean(i, "active"),
                                            "dev" : parser.get(i, "device"),
                                            "src" : parser.get(i, "source"),
                                            "dst" : parser.get(i, "destination"),
                                            "proto": parser.get(i, "protocol"),
                                            "dport": parser.getint(i, "dport"),
                                            "to"  : parser.get(i, "to") })
        self.set_br_config(br_config)
        self.set_l2_config(l2_config)
        self.set_l3_config(l3_config)
        
    def set_br_config(self, config):
        for i in config:
            br = self.br_treestore.append(None, [i["dev"], i["mac"], i["ip"], i["mask"], i["act"], True, True, True, True])
            for j in i["ifs"]:
                self.br_treestore.append(br, [j["dev"], "", "", "", j["act"], True, False, False, False])
    
    def set_l2_config(self, config):
        for i in config["src"]:
            self.l2_src_liststore.append([i["dev"], i["ip"], i["mac"], i["act"]])
        for i in config["dst"]:
            self.l2_dst_liststore.append([i["dev"], i["ip"], i["mac"], i["act"]])
    
    def set_l3_config(self, config):
        for i in config["src"]:
            self.l3_src_liststore.append([i["dev"], i["src"], i["dst"], i["proto"], i["dport"], i["to"], i["act"]])
        for i in config["dst"]:
            self.l3_dst_liststore.append([i["dev"], i["src"], i["dst"], i["proto"], i["dport"], i["to"], i["act"]])
    
    def save_config(self, filename):
        parser = ConfigParser.RawConfigParser()
        br_config = self.read_br_config()
        for i in br_config:
            parser.add_section("br_%s" % i["dev"])
            parser.set("br_%s" % i["dev"], "active", i["act"])
            parser.set("br_%s" % i["dev"], "device", i["dev"])
            parser.set("br_%s" % i["dev"], "mac", i["mac"])
            parser.set("br_%s" % i["dev"], "address", i["ip"])
            parser.set("br_%s" % i["dev"], "netmask", i["mask"])
            for j in i["ifs"]:
                parser.set("br_%s" % i["dev"], "if_%s" % j["dev"], j["act"])
        l2_config = self.read_l2_config()
        for i in l2_config["src"]:
            m = hashlib.sha256()
            m.update(i["dev"] + i["ip"] + i["mac"])
            uid = m.hexdigest()
            parser.add_section("l2_src_%s" % uid)
            parser.set("l2_src_%s" % uid, "active", i["act"])
            parser.set("l2_src_%s" % uid, "device", i["dev"])
            parser.set("l2_src_%s" % uid, "address", i["ip"])
            parser.set("l2_src_%s" % uid, "mac", i["mac"])
        for i in l2_config["dst"]:
            m = hashlib.sha256()
            m.update(i["dev"] + i["ip"] + i["mac"])
            uid = m.hexdigest()
            parser.add_section("l2_dst_%s" % uid)
            parser.set("l2_dst_%s" % uid, "active", i["act"])
            parser.set("l2_dst_%s" % uid, "device", i["dev"])
            parser.set("l2_dst_%s" % uid, "address", i["ip"])
            parser.set("l2_dst_%s" % uid, "mac", i["mac"])
        l3_config = self.read_l3_config()
        for i in l3_config["src"]:
            m = hashlib.sha256()
            m.update(i["dev"] + i["src"] + i["dst"] + i["proto"] + "%d" % i["dport"])
            uid = m.hexdigest()
            parser.add_section("l3_src_%s" % uid)
            parser.set("l3_src_%s" % uid, "active", i["act"])
            parser.set("l3_src_%s" % uid, "device", i["dev"])
            parser.set("l3_src_%s" % uid, "source", i["src"])
            parser.set("l3_src_%s" % uid, "destination", i["dst"])
            parser.set("l3_src_%s" % uid, "protocol", i["proto"])
            parser.set("l3_src_%s" % uid, "dport", i["dport"])
            parser.set("l3_src_%s" % uid, "to", i["to"])
        for i in l3_config["dst"]:
            m = hashlib.sha256()
            m.update(i["dev"] + i["src"] + i["dst"] + i["proto"] + "%d" % i["dport"])
            uid = m.hexdigest()
            parser.add_section("l3_dst_%s" % uid)
            parser.set("l3_dst_%s" % uid, "active", i["act"])
            parser.set("l3_dst_%s" % uid, "device", i["dev"])
            parser.set("l3_dst_%s" % uid, "source", i["src"])
            parser.set("l3_dst_%s" % uid, "destination", i["dst"])
            parser.set("l3_dst_%s" % uid, "protocol", i["proto"])
            parser.set("l3_dst_%s" % uid, "dport", i["dport"])
            parser.set("l3_dst_%s" % uid, "to", i["to"])
        
        if os.path.exists(filename):
            #ask for replacement
            pass
        with open(filename, 'wb') as configfile:
            parser.write(configfile)
            self.log("Saved bridge configuration to '%s'" % filename)

    def execute_br(self):
        br_config = self.read_br_config()            
        for i in br_config:
            if i["act"]:
                dev = i["dev"]
                self.log("Creating bridge interface '%s'" % dev)
                cmd = "brctl addbr %s" % dev
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
                for j in i["ifs"]:
                    if j["act"]:
                        d = j["dev"]
                        self.log("Adding interface '%s' to bridge '%s'" % (d, dev))
                        cmd = "ip link set dev %s up" % d
                        if not self.DEBUG:
                            os.system(cmd)
                        else:
                            self.log(cmd)
                        cmd = "brctl addif %s %s" % (dev, d)
                        if not self.DEBUG:
                            os.system(cmd)
                        else:
                            self.log(cmd)
                mac = i["mac"]
                self.log("Setting MAC address '%s' on bridge '%s'" % (mac, dev))
                cmd = "ip link set dev %s address %s" % (dev, mac)            
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
                ip = i["ip"]
                mask = len(IPy.IP(i["mask"]).strBin().replace("0", ""))
                self.log("Setting IP address '%s' on bridge '%s'" % (ip, dev))
                cmd = "ip addr add %s/%d dev %s" % (ip, mask, dev)
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
                self.log("Setting IPv6 link local address 'fe80::%s' on bridge '%s'" % (mac, dev))
                cmd = "ip addr add fe80::%s/64 dev %s" % (mac, dev)
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
                self.log("Setting link on bridge '%s' up" % dev)
                cmd = "ip link set dev %s up" % dev
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
    
    def unexecute_br(self):
        br_config = self.read_br_config()
        for i in br_config:
            if i["act"]:
                dev = i["dev"]
                self.log("Setting link on bridge '%s' down" % dev)
                cmd = "ip link set dev %s down" % dev
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
                ip = i["ip"]
                mask = len(IPy.IP(i["mask"]).strBin().replace("0", ""))
                self.log("Removing IP address '%s' from bridge '%s'" % (ip, dev))
                cmd = "ip addr del %s/%d dev %s" % (ip, mask, dev)
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
                for j in i["ifs"]:
                    if j["act"]:
                        d = j["dev"]
                        self.log("Removing interface '%s' from bridge '%s'" % (d, dev))
                        cmd = "brctl delif %s %s" % (dev, d)
                        if not self.DEBUG:
                            os.system(cmd)
                        else:
                            self.log(cmd)
                self.log("Removing bridge interface '%s'" % dev)
                cmd = "brctl delbr %s" % dev
                if not self.DEBUG:
                    os.system(cmd)
                else:
                    self.log(cmd)
    
    def execute_l2(self):
        l2_config = self.read_l2_config()
        for i in l2_config["src"]:
            self.log("Activating L2 Source NAT on '%s'" % i["dev"])
            cmd = "ebtables -t nat -A PREROUTING -p ip --ip-destination %s --in-interface %s -j snat --to-source %s" % (i["ip"], i["dev"], i["mac"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
        for i in l2_config["dst"]:
            self.log("Activating L2 Destination NAT on '%s'" % i["dev"])
            cmd = "ebtables -t nat -A PREROUTING -p ip --ip-source %s --in-interface %s -j dnat --to-destination %s" % (i["ip"], i["dev"], i["mac"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
    
    def unexecute_l2(self):
        l2_config = self.read_l2_config()
        for i in l2_config["src"]:
            self.log("Deleting L2 Source NAT on '%s'" % i["dev"])
            cmd = "ebtables -t nat -D PREROUTING -p ip --ip-destination %s --in-interface %s -j snat --to-source %s" % (i["ip"], i["dev"], i["mac"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
        for i in l2_config["dst"]:
            self.log("Deleting L2 Destination NAT on '%s'" % i["dev"])
            cmd = "ebtables -t nat -D PREROUTING -p ip --ip-source %s --in-interface %s -j dnat --to-destination %s" % (i["ip"], i["dev"], i["mac"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
    
    def execute_l3(self):
        l3_config = self.read_l3_config()
        for i in l3_config["src"]:
            self.log("Activating L3 Source NAT on '%s'" % i["dev"])
            cmd = "iptables -t nat -A POSTROUTING -p %s --dport %d -o %s -jSNAT --to %s --destination %s --source %s" % (i["proto"], i["dport"], i["dev"], i["to"], i["dst"], i["src"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
        for i in l3_config["src"]:
            self.log("Activating L3 Destination NAT on '%s'" % i["dev"])
            cmd = "iptables -t nat -A PREROUTING -p %s --dport %d -i %s -jSNAT --to %s --destination %s --source %s" % (i["proto"], i["dport"], i["dev"], i["to"], i["dst"], i["src"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
    
    def unexecute_l3(self):
        l3_config = self.read_l3_config()
        for i in l3_config["src"]:
            self.log("Deleting L3 Source NAT on '%s'" % i["dev"])
            cmd = "iptables -t nat -D POSTROUTING -p %s --dport %d -o %s -jSNAT --to %s --destination %s --source %s" % (i["proto"], i["dport"], i["dev"], i["to"], i["dst"], i["src"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
        for i in l3_config["src"]:
            self.log("Deleting L3 Destination NAT on '%s'" % i["dev"])
            cmd = "iptables -t nat -D PREROUTING -p %s --dport %d -i %s -jSNAT --to %s --destination %s --source %s" % (i["proto"], i["dport"], i["dev"], i["to"], i["dst"], i["src"])
            if not self.DEBUG:
                os.system(cmd)
            else:
                self.log(cmd)
    
    def select_device(self):
        def on_network_combobox_changed(box, label):
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
        box.connect('changed', on_network_combobox_changed, label)
        dialog.vbox.show_all()
        
        box.set_active(0)
        ret = dialog.run()
        dialog.destroy()
        interface = None
        if ret == gtk.RESPONSE_OK:
            if PLATFORM == "Windows":
                descr = box.get_active_text()
                for i in self.devices:
                    if self.devices[i]['descr'] == descr:
                        interface = i
                assert(interface != None)
            else:
                interface = box.get_active_text()
        return interface

    def get_devices(self):
        devices = {}
        devs = loki.pcap.findalldevs()
        for (name, descr, addr, flags) in devs:
            try:
                test = dnet.eth(name)
                mac = test.get()
                devices[name] = { 'mac' : mac, 'ip4' : [], 'ip6' : [], 'descr' : descr, 'flags' : flags }
            except:
                pass
            else:
                self.add_interfaces_store(name)
                self.add_macaddresses_store(dnet.eth_ntoa(mac))
                if len(addr) > 1:
                    for (ip, mask, net, gw) in addr:
                        try:
                            dnet.ip_aton(ip)
                            addr_dict = {}
                            addr_dict['ip'] = ip
                            self.add_addresses_store(ip)
                            addr_dict['mask'] = mask
                            self.add_netmasks_store(mask)
                            addr_dict['net'] = net
                            addr_dict['gw'] = gw
                            devices[name]['ip4'].append(addr_dict)
                        except:
                            pass                            
                        try:
                            dnet.ip6_aton(ip)
                            addr_dict = {}
                            addr_dict['ip'] = ip
                            self.add_addresses_store(ip)
                            addr_dict['mask'] = mask
                            self.add_netmasks_store(mask)
                            addr_dict['net'] = net
                            addr_dict['gw'] = gw
                            if ip.startswith("fe80:"):
                                addr_dict['linklocal'] = True
                            else:
                                addr_dict['linklocal'] = False
                            devices[name]['ip6'].append(addr_dict)
                        except:
                            pass
        return devices
    
    def msg(self, msg):
        print msg
    
    def log(self, msg):
        print msg

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
            if self.dict[i]["type"] == "str":
                config.set(self.mod_name, i, base64.b64encode(self.dict[i]["value"]))
            else:
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
        filechooser = gtk.FileChooserButton("Select a Wordlist")
        if not self.par.wordlist is None:
            filechooser.set_filename(self.par.wordlist)
        filechooser.connect('file-set', self.wordlist_callback)
        frame = gtk.Frame("Wordlist")
        frame.add(filechooser)
        vbox.pack_start(frame, expand=False, fill=False)
        vbox2 = gtk.VBox()
        bf_checkbutton = gtk.CheckButton("Use Bruteforce")
        bf_checkbutton.set_active(self.par.bruteforce)
        bf_checkbutton.connect('toggled', self.bf_callback)
        bf_full_checkbutton = gtk.CheckButton("Use full Charset")
        bf_full_checkbutton.set_active(self.par.bruteforce_full)
        bf_full_checkbutton.connect('toggled', self.bf_full_callback)
        vbox2.pack_start(bf_checkbutton)
        vbox2.pack_start(bf_full_checkbutton)
        frame = gtk.Frame("Bruteforce")
        frame.add(vbox2)
        vbox.pack_start(frame, expand=False, fill=False)
        threads_spinbutton = gtk.SpinButton()
        threads_spinbutton.set_range(1, 1024)
        threads_spinbutton.set_value(self.par.bruteforce_threads)
        threads_spinbutton.set_increments(1, 16)
        threads_spinbutton.set_numeric(True)
        threads_spinbutton.connect('value-changed', self.threads_callback)
        frame = gtk.Frame("Threads")
        frame.add(threads_spinbutton)
        vbox.pack_start(frame, expand=False, fill=False)
        
        scrolledwindow = gtk.ScrolledWindow()
        scrolledwindow.set_property("vscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.set_property("hscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.add_with_viewport(vbox)
        notebook.append_page(scrolledwindow, tab_label=gtk.Label("Bruteforce"))
        
        vbox = gtk.VBox(False, 0)
        combo = gtk.combo_box_new_text()
        for i in self.par.dot_prog_choices:
            combo.insert_text(0, i)
            if i == self.par.dot_prog:
                combo.set_active(0)
        combo.connect('changed', self.dot_callback)
        frame = gtk.Frame("Graph Layout")
        frame.add(combo)
        vbox.pack_start(frame, expand=False, fill=False)
        scrolledwindow = gtk.ScrolledWindow()
        scrolledwindow.set_property("vscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.set_property("hscrollbar-policy", gtk.POLICY_AUTOMATIC)
        scrolledwindow.add_with_viewport(vbox)
        notebook.append_page(scrolledwindow, tab_label=gtk.Label("Graph"))
        
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
    
    def dot_callback(self, combo):
        self.par.dot_prog = combo.get_active_text()
    
    def wordlist_callback(self, button):
        self.par.wordlist = button.get_filename()
    
    def bf_callback(self, button):
        self.par.bruteforce = button.get_active()
    
    def bf_full_callback(self, button):
        self.par.bruteforce_full = button.get_active()
    
    def threads_callback(self, button):
        self.par.threads = button.get_value_as_int()
        return True

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
            self.par.shut_module(model[path][self.MOD_NAME_ROW])
            self.par.load_module(model[path][self.MOD_NAME_ROW], model[path][self.MOD_ENABLE_ROW])
            (module, enabled) = self.par.modules[model[path][self.MOD_NAME_ROW]]
            if enabled:
                self.par.init_module(model[path][self.MOD_NAME_ROW])
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

class loki_gtk(loki.codename_loki):
    def __init__(self):
        loki.codename_loki.__init__(self)
        self.ui = 'gtk'

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
        loki.codename_loki.main(self)
        self.window.show_all()
        gtk.main()
	
    def load_all_modules(self, path=loki.DATA_DIR + loki.MODULE_PATH):
        loki.codename_loki.load_all_modules(self, path)
        for i in self.modules.keys():
            if not "get_root" in dir(self.modules[i][0]):
                del self.modules[i]
    
    def init_module_ui(self, mod):
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
                ntb.reorder_child(root, -1)
            else:
                ntb.insert_page(root, gtk.Label(mod.name), -1)
            ntb.show_all()
        else:                
            if root.get_parent():
                root.reparent(self.notebook)
                self.notebook.set_tab_label(root, gtk.Label(mod.name))
                self.notebook.reorder_child(root, -1)
            else:
                self.notebook.insert_page(root, gtk.Label(mod.name), -1)        
        if self.run_togglebutton.get_active():
            self.start_module(mod)
            root.set_property("sensitive", True)
        else:
            root.set_property("sensitive", False)
    
    def shut_module_ui(self, mod):
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
    
    def quit(self, data):
		self.on_quit_button_clicked(data)
    
    ### EVENTS ###

    def on_run_togglebutton_toogled(self, btn):
        if btn.get_active():
            if not self.configured:
                self.on_network_button_clicked(None)
            if not self.configured:
                btn.set_active(False)
                return
            self.pcap_thread = loki.pcap_thread(self, self.interface)
            self.dnet_thread = loki.dnet_thread(self.interface)
            self.log("Listening on %s" % (self.interface))
            if PLATFORM != "Linux":
                self.fw = dnet.fw()
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
            self.dnet_thread.start()
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
            if self.dnet_thread:
                self.dnet_thread.quit()
                self.dnet_thread = None
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
                self.pcap_thread = loki.pcap_thread_offline(self, dialog.get_filename())
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
        
    def on_advanced_network_button_clicked(self, data):
        if PLATFORM == "Linux":
            self.netcfg = network_window(self)
            if os.path.exists(CONFIG_PATH + "/network.cfg"):
                self.netcfg.load_config(CONFIG_PATH + "/network.cfg")
            self.netcfg.window.show_all()
        
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
        button = gtk.Button("Advanced Interface Config")
        dialog.vbox.pack_start(button)
        button.connect('clicked', self.on_advanced_network_button_clicked)
        if PLATFORM != "Linux":
            button.set_property("sensitive", False)
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
        self.shutdown()
        return False

    def destroy_event(self, widget, data=None):
        gtk.main_quit()
    
    def error_callback(self, msg):
        dialog = gtk.MessageDialog(gtk.Window(gtk.WINDOW_TOPLEVEL), gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, msg)
        ret = dialog.run()
        dialog.destroy()
        gtk.main_quit()
    
    def error(self, msg):
        gobject.timeout_add(100, self.error_callback, msg)
        gtk.main()

if __name__ == '__main__':
    app = loki_gtk()
    loki.pcap = app.check()
    signal.signal(signal.SIGINT, app.quit)
    try:
        app.main()
    except Exception, e:
        print e
        if loki.DEBUG:
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
        app.shutdown()
    except:
        app.shutdown()
