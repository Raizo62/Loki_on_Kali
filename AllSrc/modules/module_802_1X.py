#       module_802_1X.py
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

import struct
import threading

import dnet

import gobject
import gtk
import gtk.glade

DOT1X_ETH_TYPE = 0x888e
DOT1X_VERSION = 0x2

DOT1X_TYPE_EAP_PACKET = 0x0
DOT1X_TYPE_EAPOL_START = 0x1
DOT1X_TYPE_EAPOL_LOGOFF = 0x2
DOT1X_TYPE_EAPOL_KEY = 0x3
DOT1X_TYPE_EAPOL_ASF_ALERT = 0x4

DOT1X_TYPE_TO_STR = {   DOT1X_TYPE_EAP_PACKET   :   "DOT1X_TYPE_EAP_PACKET",
                        DOT1X_TYPE_EAPOL_START  :   "DOT1X_TYPE_EAPOL_START",
                        DOT1X_TYPE_EAPOL_LOGOFF :   "DOT1X_TYPE_EAPOL_LOGOFF",
                        DOT1X_TYPE_EAPOL_KEY    :   "DOT1X_TYPE_EAPOL_KEY",
                        DOT1X_TYPE_EAPOL_ASF_ALERT  :   "DOT1X_TYPE_EAPOL_ASF_ALERT"
                        }

class dot1x_header(object):
    def __init__(self, version = None, type = None):
        self.version = version
        self.type = type
    
    def render(self, data):
        return struct.pack("!BBH", self.version, self.type, len(data)) + data

    def parse(self, data):
        (self.version, self.type) = struct.unpack("!BB", data[:2])
        return data[4:]

EAP_CODE_REQUEST = 0x1
EAP_CODE_RESPONSE = 0x2
EAP_CODE_SUCCESS = 0x3
EAP_CODE_FAILURE = 0x4

EAP_CODE_TO_STR = { EAP_CODE_REQUEST    :   "EAP_CODE_REQUEST",
                    EAP_CODE_RESPONSE   :   "EAP_CODE_RESPONSE",
                    EAP_CODE_SUCCESS    :   "EAP_CODE_SUCCESS",
                    EAP_CODE_FAILURE    :   "EAP_CODE_FAILURE"
                    }

EAP_TYPE_IDENTITY = 0x1
EAP_TYPE_NOTIFICATION = 0x2
EAP_TYPE_NAK = 0x3
EAP_TYPE_MD5_CHALLENGE = 0x4
EAP_TYPE_ONE_TIME_PASSWORD = 0x5
EAP_TYPE_GENERIC_TOKEN_CARD = 0x6
#...
EAP_TYPE_EXPANDED_TYPES = 0xfe
EAP_TYPE_EXPERIMENTAL = 0xff

EAP_TYPE_TO_STR = { EAP_TYPE_IDENTITY       :   "EAP_TYPE_IDENTITY",
                    EAP_TYPE_NOTIFICATION   :   "EAP_TYPE_NOTIFICATION",
                    EAP_TYPE_NAK            :   "EAP_TYPE_NAK",
                    EAP_TYPE_MD5_CHALLENGE  :   "EAP_TYPE_MD5_CHALLENGE",
                    EAP_TYPE_ONE_TIME_PASSWORD  :   "EAP_TYPE_ONE_TIME_PASSWORD",
                    EAP_TYPE_GENERIC_TOKEN_CARD :   "EAP_TYPE_GENERIC_TOKEN_CARD",
                    #...
                    EAP_TYPE_EXPANDED_TYPES :   "EAP_TYPE_EXPANDED_TYPES",
                    EAP_TYPE_EXPERIMENTAL   :   "EAP_TYPE_EXPERIMENTAL"
                    }
                    
class eap_identity(object):
    def __init__(self, identity = None):
        self.identity = identity
    
    def render(self):
        return identity
    
    def parse(self, data):
        string = str(data).replace("\0", "")
        if len(string) > 0:
            self.identity = string
        else:
            self.identity = None
    
    def dissect(self, store, iter, data):
        if self.identity:
            store.append(iter, ["EAP_IDENTITY", "", self.identity])

class eap_notification(object):
    def __init__(self, msg = None):
        self.msg = identity
    
    def render(self):
        return msg
    
    def parse(self, data):
        string = str(data).replace("\0", "")
        if len(string) > 0:
            self.msg = string
        else:
            self.msg = None
    
    def dissect(self, store, iter, data):
        if self.msg:
            store.append(iter, ["EAP_NOTIFICATION", "", self.msg])

class eap_md5_challenge(object):
    def __init__(self, value = None):
        self.value = value
    
    def render(self):
        return struct.pack("!B16s", 16, self.value)
    
    def parse(self, data):
        (self.value,) = struct.unpack("!x16s", data[:17])
        return data[17:]
    
    def dissect(self, store, iter, data):
        if self.value:
            store.append(iter, ["EAP_MD5_CHALLENGE", "", self.value.encode("hex")])
        
EAP_TYPE_TO_OBJECT = { EAP_TYPE_IDENTITY    :   eap_identity,
                       EAP_TYPE_NOTIFICATION    :   eap_notification ,
                       EAP_TYPE_MD5_CHALLENGE   :   eap_md5_challenge
                       }
        
class eap_packet(object):
    def __init__(self, code = None, ident = None, type = None):
        self.code = code
        self.ident = ident
        self.type = type
    
    def render(self, data):
        if self.code == EAP_CODE_REQUEST or self.code == EAP_CODE_RESPONSE:
            return struct.pack("!BBHB", self.code, self.ident, len(data) + 5, self.type) + data
        else:
            return struct.pack("!BBH", self.code, self.ident, len(data) + 4) + data
        
    def parse(self, data):
        (self.code, self.ident) = struct.unpack("!BB", data[:2])
        if self.code == EAP_CODE_REQUEST or self.code == EAP_CODE_RESPONSE:
            (self.type,) = struct.unpack("!B", data[4])
            return data[5:]
        else:
            return data[4:]
    
    def dissect(self, store, iter, data):
        if self.code == EAP_CODE_REQUEST or self.code == EAP_CODE_RESPONSE:
            self.iter = store.append(iter, ["EAP", EAP_CODE_TO_STR[self.code], EAP_TYPE_TO_STR[self.type]])
            obj = EAP_TYPE_TO_OBJECT[self.type]()
            data = obj.parse(data)
            obj.dissect(store, self.iter, data)
        elif self.code == EAP_CODE_SUCCESS:
            self.iter = store.append(iter, ["EAP", EAP_CODE_TO_STR[self.code], ""])
        else:
            self.iter = store.append(iter, ["EAP", EAP_CODE_TO_STR[self.code], data.encode("hex")])
        
DOT1X_TYPE_TO_OBJECT = {    DOT1X_TYPE_EAP_PACKET   :   eap_packet,
                            #DOT1X_TYPE_EAPOL_START  :   None,
                            #DOT1X_TYPE_EAPOL_LOGOFF :   None,
                            #DOT1X_TYPE_EAPOL_KEY    :   None,
                            #DOT1X_TYPE_EAPOL_ASF_ALERT  :   None
                            }

class connection(object):
    def __init__(self, parent, src, dst):
        self.parent = parent
        self.src = src
        self.dst = dst
        self.iter = None
    
    def dissect(self, dot1x_hdr, data):
        type = dot1x_hdr.type
        if not self.iter:
            self.iter = self.parent.connection_treestore.append(None, [self.src, self.dst, DOT1X_TYPE_TO_STR[type]])
        else:
            self.parent.connection_treestore.set(self.iter, self.parent.CONN_DST_ROW, self.dst, self.parent.CONN_TYPE_ROW, DOT1X_TYPE_TO_STR[type])
        obj = DOT1X_TYPE_TO_OBJECT[type]()
        data = obj.parse(data)
        obj.dissect(self.parent.connection_treestore, self.iter, data)
        
class mod_class(object):
    CONN_SRC_ROW = 0
    CONN_DST_ROW = 1
    CONN_TYPE_ROW = 2
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "802.1X"
        self.gladefile = "/modules/module_802_1X.glade"
        self.connection_treestore = gtk.TreeStore(str, str, str)
        self.connection_list = {}

    def start_mod(self):
        pass

    def shut_mod(self):
        self.connection_treestore.clear()
        self.connection_list = {}

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { }
        self.glade_xml.signal_autoconnect(dic)
        
        self.connection_treeview = self.glade_xml.get_widget("connection_treeview")
        self.connection_treeview.set_model(self.connection_treestore)
        self.connection_treeview.set_headers_visible(False)
        
        column = gtk.TreeViewColumn()
        column.set_title("SRC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.CONN_SRC_ROW)
        self.connection_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DST")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.CONN_DST_ROW)
        self.connection_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("TYPE")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.CONN_TYPE_ROW)
        self.connection_treeview.append_column(column)
        
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == DOT1X_ETH_TYPE:
            return (True, False)
        return (False, False)
    
    def input_eth(self, eth, timestamp):
        src = dnet.eth_ntoa(eth.src)
        if src not in self.connection_list:
            dst = dnet.eth_ntoa(eth.dst)
            self.connection_list[src] = connection(self, src, dst)
        hdr = dot1x_header()
        #try:
        data = hdr.parse(eth.data)
        self.connection_list[src].dissect(hdr, data)
        #except:
        #    pass
