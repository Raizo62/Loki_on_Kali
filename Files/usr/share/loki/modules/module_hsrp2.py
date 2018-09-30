#       module_hsrp2.py
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
import time

import dumbnet
import dpkt

import gobject
import gtk
import gtk.glade

HSRP2_VERSION = 2
HSRP2_PORT = 1985
HSRP2_MULTICAST_ADDRESS = "224.0.0.102"
HSRP2_MULTICAST_MAC = "01:00:5e:00:00:66"

class hsrp2_tlv:
    TYPE_GROUP_STATE = 1
    TYPE_INTERFACE_STATE = 2
    TYPE_TEXT_AUTH = 3
    TYPE_MD5_AUTH = 4
    
    def __init__(self, type=None):
        self.type = type

    def render(self, data):
        return struct.pack("!BB", self.type, len(data)) + data

    def parse(self, data):
        (self.type, self.len) = struct.unpack("!BB", data[:2])
        return data[2:]

class hsrp2_group_state_tlv(hsrp2_tlv):
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |    Type=1     |  Length=40    | HSRP Version  |    Opcode     |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |     State     |   IP Version  |         Group Number          |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                         Identifier(6octets)                   |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |         Identifier            |       Priority(4octets)       |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |       Priority cont.          |      Hello Time(4octets)      |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |       Hello Time cont.        |      Hold Time(4octets)       |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |       Hold Time cont.         |  Virtual IP Address(16octets) |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                  Virtual IP Address cont.                     |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                  Virtual IP Address cont.                     |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                  Virtual IP Address cont.                     |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |    Virtual IP Address cont.   |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    OP_CODE_HELLO = 0
    OP_CODE_COUP = 1
    OP_CODE_RESIGN = 2

    STATE_DISABLED = 0
    STATE_INIT = 1
    STATE_LEARN = 2
    STATE_LISTEN = 3
    STATE_SPEAK = 4
    STATE_STANDBY = 5
    STATE_ACTIVE = 6
    
    def __init__(self, op_code=None, state=None, ip_ver=None, group=None, id=None, prio=None, hello_time=None, hold_time=None, ip=None):
        hsrp2_tlv.__init__(self, hsrp2_tlv.TYPE_GROUP_STATE)
        self.op_code = op_code
        self.state = state
        self.ip_ver = ip_ver
        self.group = group
        self.id = id
        self.prio = prio
        self.hello_time = hello_time
        self.hold_time = hold_time
        self.ip = ip

    def render(self):
        data = struct.pack("!BBBBH", HSRP2_VERSION, self.op_code, self.state, self.ip_ver, self.group) + self.id + struct.pack("!III", self.prio, self.hello_time, self.hold_time)
        if self.ip_ver == 4:
            data += self.ip + "\00" * 12
        elif self.ip_ver == 6:
            data += self.ip
        else:
            raise Exeption("HSRP2: hsrp2_group_state_tlv.render(): wrong IP version in packet")
        return hsrp2_tlv.render(self, data)

    def parse(self, data):
        (ver, self.op_code, self.state, self.ip_ver, self.group) = struct.unpack("!BBBBH", data[:6])
        self.id = data[6:12]
        (self.prio, self.hello_time, self.hold_time) = struct.unpack("!III", data[12:24])
        if self.ip_ver == 4:
            self.ip = data[24:28]
        elif self.ip_ver == 6:
            self.ip = data[24:40]
        else:
            raise Exeption("HSRP2: hsrp2_group_state_tlv.parse(): wrong IP version in packet")
        return data[40:]

class hsrp2_interface_state_tlv(hsrp2_tlv):
   #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |    Type=2     |    Length=4   |         Active Groups         |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |       Passive Groups          |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
    def __init__(self, active_groups=None, passive_groups=None):
        hsrp2_tlv.__init__(self, hsrp2_tlv.TYPE_INTERFACE_STATE)
        self.active_groups = active_groups
        self.passive_groups = passive_groups

    def render(self):
        return hsrp2_tlv.render(self, struct.pack("!HH", self.active_groups, self.passive_groups))

    def parse(self, data):
        (self.active_groups, self.passive_groups) = struct.unpack("!HH", data[:4])
        return data[4:]

class hsrp2_text_auth_tlv(hsrp2_tlv):
   #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |    Type=3     |   Length=8    |  Authentication Data(8octets) |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                   Authentication Data cont.                   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |   Authentication Data cont.   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def __init__(self, auth_data=None):
        hsrp2_tlv.__init__(self, hsrp2_tlv.TYPE_TEXT_AUTH)
        self.auth_data = auth_data

    def render(self):
        return hsrp2_tlv.render(self, self.auth_data[:8])

    def parse(self, data):
        self.auth_data = data[:8]
        return data[8:]

class hsrp2_md5_auth_tlv(hsrp2_tlv):
   #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |    Type=4     |    Length     |   Algorithm   |   Padding     |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |             Flags             |      IP Address(4octets)      |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |       IP Address cont.        |         Key ID(4octets)       |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |         Key ID cont.          | Authentication Data(16octets) |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                   Authentication Data cont.                   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                   Authentication Data cont.                   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                   Authentication Data cont.                   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |   Authentication Data cont.   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    AUTH_ALGO_MD5 = 1

    def __init__(self, algo=None, addr=None, id=None):
        hsrp2_tlv.__init__(self, hsrp2_tlv.TYPE_MD5_AUTH)
        self.algo = algo
        self.flags = 0x00
        self.addr = addr
        self.id = id

    def render(self):
        return hsrp2_tlv.render(self, struct.pack("!BxI", self.algo, self.flags) + self.addr + struct.pack("!I", self.id) + "\00" * 16)

    def parse(self, data):
        (self.algo, self.flags) = struct.unpack("!BxI", data[:4])
        ### LOOKOUT FOR v6 ADDRESS !!! ###
        ### dont re-impl. the wireshark bug ###
        #self.addr = data[4:8]
        

class hsrp2_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True

    def run(self):
        self.parent.log("HSRP2: Thread started")
        while self.running:
            for i in self.parent.peers:
                (iter, pkg, state, arp) = self.parent.peers[i]
                if state:
                    hsrp2_group_state = hsrp2_group_state_tlv(  hsrp2_group_state_tlv.OP_CODE_HELLO,
                                                                hsrp2_group_state_tlv.STATE_ACTIVE,
                                                                pkg["hsrp2_group_state_tlv"].ip_ver,
                                                                pkg["hsrp2_group_state_tlv"].group,
                                                                self.parent.mac,
                                                                255,
                                                                pkg["hsrp2_group_state_tlv"].hello_time,
                                                                pkg["hsrp2_group_state_tlv"].hold_time,
                                                                pkg["hsrp2_group_state_tlv"].ip
                                                                )
                    data = hsrp2_group_state.render()
                    if "hsrp2_text_auth_tlv" in pkg:
                        hsrp2_text_auth = hsrp2_text_auth_tlv(pkg["hsrp2_text_auth_tlv"].auth_data)
                        data += hsrp2_text_auth.render()
                    elif "hsrp2_md5_auth_tlv" in pkg:
                        pass
                    
                    udp_hdr = dpkt.udp.UDP( sport=HSRP2_PORT,
                                            dport=HSRP2_PORT,
                                            data=data
                                            )
                    udp_hdr.ulen += len(udp_hdr.data)
                    ip_hdr = dpkt.ip.IP(    ttl=1,
                                            p=dpkt.ip.IP_PROTO_UDP,
                                            src=self.parent.ip,
                                            dst=dumbnet.ip_aton(HSRP2_MULTICAST_ADDRESS),
                                            data=str(udp_hdr)
                                            )
                    ip_hdr.len += len(ip_hdr.data)
                    eth_hdr = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton(HSRP2_MULTICAST_MAC),
                                                        src=self.parent.mac,
                                                        type=dpkt.ethernet.ETH_TYPE_IP,
                                                        data=str(ip_hdr)
                                                        )
                    self.parent.dumbnet.send(str(eth_hdr))
                    if arp:
                        src_mac = dumbnet.eth_aton("00:00:0c:9f:f0:%02x" % (pkg["hsrp2_group_state_tlv"].group))
                        brdc_mac = dumbnet.eth_aton("ff:ff:ff:ff:ff:ff")
                        stp_uplf_mac = dumbnet.eth_aton("01:00:0c:cd:cd:cd")
                        ip = pkg["hsrp2_group_state_tlv"].ip
                        arp_hdr = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                            pro=dpkt.arp.ARP_PRO_IP,
                                            op=dpkt.arp.ARP_OP_REPLY,
                                            sha=src_mac,
                                            spa=ip,
                                            tha=brdc_mac,
                                            tpa=ip
                                            )
                        eth_hdr = dpkt.ethernet.Ethernet(   dst=brdc_mac,
                                                            src=src_mac,
                                                            type=dpkt.ethernet.ETH_TYPE_ARP,
                                                            data=str(arp_hdr)
                                                            )
                        self.parent.dumbnet.send(str(eth_hdr))

                        arp_hdr = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                            pro=dpkt.arp.ARP_PRO_IP,
                                            op=dpkt.arp.ARP_OP_REPLY,
                                            sha=src_mac,
                                            spa=ip,
                                            tha=stp_uplf_mac,
                                            tpa=ip
                                            )
                        eth_hdr = dpkt.ethernet.Ethernet(   dst=stp_uplf_mac,
                                                            src=src_mac,
                                                            type=dpkt.ethernet.ETH_TYPE_ARP,
                                                            data=str(arp_hdr)
                                                            )
                        self.parent.dumbnet.send(str(eth_hdr))
                        self.parent.peers[i] = (iter, pkg, state, arp - 1)
            time.sleep(1)
        self.parent.log("HSRP2: Thread terminated")

    def shutdown(self):
        self.running = False


class mod_class(object):
    STORE_SRC_ROW = 0
    STORE_IP_ROW = 1
    STORE_PRIO_ROW = 2
    STORE_STATE_ROW = 3
    STORE_AUTH_ROW = 4
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "hsrp-v2"
        self.group = "HOT-STANDBY"
        self.gladefile = "/modules/module_hsrp2.glade"
        self.liststore = gtk.ListStore(str, str, int, str, str)
        self.thread = None

    def start_mod(self):
        self.peers = {}
        self.thread = hsrp2_thread(self)

    def shut_mod(self):
        if self.thread:
            if self.thread.is_alive():
                self.thread.shutdown()
        self.liststore.clear()
        
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_get_button_clicked" : self.on_get_button_clicked,
                "on_release_button_clicked" : self.on_release_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.treeview = self.glade_xml.get_widget("treeview")
        self.treeview.set_model(self.liststore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Source")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_SRC_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_IP_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Priority")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_PRIO_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Status")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_STATE_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Auth")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_AUTH_ROW)
        self.treeview.append_column(column)

        self.arp_checkbutton = self.glade_xml.get_widget("arp_checkbutton")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dumbnet.ip_aton(ip)

    def set_dumbnet(self, dumbnet):
        self.dumbnet = dumbnet
        self.mac = dumbnet.eth.get()

    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.dport == HSRP2_PORT:
            (ver, ) = struct.unpack("!xxB", str(udp.data)[:3])
            if ver == HSRP2_VERSION:
                return (True, True)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        if ip.src != self.ip:
            if ip.src not in self.peers:
                pkg = {}
                ip_addr = ""
                prio = 0
                auth = ""
                tlv = hsrp2_tlv()
                left = str(udp.data)
                while len(left) > 0:
                    left = tlv.parse(left)
                    if tlv.type == hsrp2_tlv.TYPE_GROUP_STATE:
                        hsrp2_group_state = hsrp2_group_state_tlv()
                        left = hsrp2_group_state.parse(left)
                        pkg["hsrp2_group_state_tlv"] = hsrp2_group_state
                        ip_addr = hsrp2_group_state.ip
                        prio = hsrp2_group_state.prio
                    elif tlv.type == hsrp2_tlv.TYPE_TEXT_AUTH:
                        hsrp2_text_auth = hsrp2_text_auth_tlv()
                        left = hsrp2_text_auth.parse(left)
                        pkg["hsrp2_text_auth_tlv"] = hsrp2_text_auth
                        auth = hsrp2_text_auth.auth_data
                    else:
                        return
                src = dumbnet.ip_ntoa(ip.src)
                iter = self.liststore.append([src, dumbnet.ip_ntoa(ip_addr), prio, "Seen", auth])
                self.peers[ip.src] = (iter, pkg, False, False)
                self.log("HSRP2: Got new peer %s" % (src))

    # SIGNALS #

    def on_get_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            peer = dumbnet.ip_aton(model.get_value(iter, self.STORE_SRC_ROW))
            (iter, pkg, run, arp) = self.peers[peer]
            if self.arp_checkbutton.get_active():
                arp = 3
            else:
                arp = 0
            self.peers[peer] = (iter, pkg, True, arp)
            model.set_value(iter, self.STORE_STATE_ROW, "Taken")
        if not self.thread.is_alive():
            self.thread.start()

    def on_release_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            peer = dumbnet.ip_aton(model.get_value(iter, self.STORE_SRC_ROW))
            (iter, pkg, run, arp) = self.peers[peer]
            self.peers[peer] = (iter, pkg, False, arp)
            model.set_value(iter, self.STORE_STATE_ROW, "Released")
