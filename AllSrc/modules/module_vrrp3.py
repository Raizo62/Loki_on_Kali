#       module_vrrp3.py
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

import dnet
import dpkt

import gobject
import gtk
import gtk.glade

VRRP3_VERSION = 3
VRRP3_MULTICAST_ADDRESS = "224.0.0.18"
VRRP3_MULTICAST_MAC = "01:00:5e:00:00:12"

### HELPER_FUNKTIONS ###

def ichecksum_func(data, sum=0):
    ''' Compute the Internet Checksum of the supplied data.  The checksum is
    initialized to zero.  Place the return value in the checksum field of a
    packet.  When the packet is received, check the checksum, by passing
    in the checksum field of the packet and the data.  If the result is zero,
    then the checksum has not detected an error.
    '''
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in xrange(0,len(data),2):
        if i + 1 >= len(data):
            sum += ord(data[i]) & 0xFF
        else:
            w = ((ord(data[i]) << 8) & 0xFF00) + (ord(data[i+1]) & 0xFF)
            sum += w

    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # one's complement the result
    sum = ~sum

    return sum & 0xFFFF

class vrrp3_packet(object):
    #~ 0                   1                   2                   3
    #~ 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |(rsvd) |     Max Adver Int     |          Checksum             |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                                                               |
    #~ +                                                               +
    #~ |                       IPvX Address(es)                        |
    #~ +                                                               +
    #~ +                                                               +
    #~ +                                                               +
    #~ +                                                               +
    #~ |                                                               |
    #~ +                                                               +
    #~ |                                                               |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    TYPE_ADVERTISEMENT = 1
    
    def __init__(self, id=None, prio=None, max_advert_int=100, ips=[]):
        self.id = id
        self.prio = prio
        self.max_advert_int = max_advert_int
        self.ips = ips

    def render(self):
        data = struct.pack("!BBBBHH", (VRRP3_VERSION << 4) | self.TYPE_ADVERTISEMENT, self.id, self.prio, len(self.ips), (self.max_advert_int & 0xFFF), 0)
        for i in self.ips:
            data += i
        return data

    def build_checksum(self, vrrp_data, src, dst, version=4):
        if version == 4:
            #v4 pseudo header?
            pass
        elif version == 6:
            input = src + dst + strcut.pack("!I3xB", len(vrrp_data), dpkt.ip.IP_PROTO_VRRP)
            return vrrp_data[:6] + ichecksum_func(input + vrrp_data) + vrrp_data[8:] 
    
    def parse(self, data, version=4):
        (ver_type, self.id, self.prio, num_ips, max_advert_int, sum) = struct.unpack("!BBBBH", data[:6])
        self.max_advert_int = max_advert_int & 0xFFF
        left = data[8:]
        if version == 4:
            for i in xrange(num_ips):
                self.ips.append(left[:4])
                left = left[4:]
        elif version == 6:
            for i in xrange(num_ips):
                self.ips.append(left[:16])
                left = left[16:]

class vrrp3_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True

    def run(self):
        self.parent.log("VRRP-3: Thread started")
        while self.running:
            for i in self.parent.peers:
                (iter, pkg, state, arp) = self.parent.peers[i]
                if state:
                    src_mac = dnet.eth_aton("00:00:5e:00:01:%02x" % (pkg.id))
                    vrrp = vrrp_packet(pkg.id, 255, pkg.auth_type, pkg.auth_data, 1, pkg.ips)
                    data = vrrp.render()
                    ip_hdr = dpkt.ip.IP(    ttl=255,
                                            p=dpkt.ip.IP_PROTO_VRRP,
                                            src=self.parent.ip,
                                            dst=dnet.ip_aton(VRRP3_MULTICAST_ADDRESS),
                                            data=data
                                            )
                    ip_hdr.len += len(ip_hdr.data)
                    ip_hdr.data = vrrp.build_checksum(ip_hdr.data, ip_hdr)
                    eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(VRRP3_MULTICAST_MAC),
                                                        src=src_mac,
                                                        type=dpkt.ethernet.ETH_TYPE_IP,
                                                        data=str(ip_hdr)
                                                        )
                    self.parent.dnet.send(str(eth_hdr))
                    if arp:
                        brdc_mac = dnet.eth_aton("ff:ff:ff:ff:ff:ff")
                        stp_uplf_mac = dnet.eth_aton("01:00:0c:cd:cd:cd")
                        src_mac = self.parent.mac
                        for j in pkg.ips:
                            arp_hdr = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                                pro=dpkt.arp.ARP_PRO_IP,
                                                op=dpkt.arp.ARP_OP_REPLY,
                                                sha=src_mac,
                                                spa=j,
                                                tha=brdc_mac,
                                                tpa=j
                                                )
                            eth_hdr = dpkt.ethernet.Ethernet(   dst=brdc_mac,
                                                                src=src_mac,
                                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                                data=str(arp_hdr)
                                                                )
                            self.parent.dnet.send(str(eth_hdr))

                            arp_hdr = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                                pro=dpkt.arp.ARP_PRO_IP,
                                                op=dpkt.arp.ARP_OP_REPLY,
                                                sha=src_mac,
                                                spa=j,
                                                tha=stp_uplf_mac,
                                                tpa=j
                                                )
                            eth_hdr = dpkt.ethernet.Ethernet(   dst=stp_uplf_mac,
                                                                src=src_mac,
                                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                                data=str(arp_hdr)
                                                                )
                            self.parent.dnet.send(str(eth_hdr))
                        self.parent.peers[i] = (iter, pkg, state, arp - 1)
            time.sleep(1)
        self.parent.log("VRRP-3: Thread terminated")

    def shutdown(self):
        self.running = False

class mod_class(object):
    LIST_SRC_ROW = 0
    LIST_IP_ROW = 1
    LIST_ID_ROW = 2
    LIST_PRIO_ROW = 3
    LIST_STATE_ROW = 4
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "vrrp-v3"
        self.group = "HOT-STANDBY"
        self.gladefile = "/modules/module_vrrp3.glade"
        self.liststore = gtk.ListStore(str, str, int, int, str)
        self.thread = None

    def start_mod(self):
        self.peers = {}
        self.thread = vrrp3_thread(self)

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
        column.add_attribute(render_text, 'text', self.LIST_SRC_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.LIST_IP_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("ID")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.LIST_ID_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Priority")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.LIST_PRIO_ROW)
        self.treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Status")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.LIST_STATE_ROW)
        self.treeview.append_column(column)

        self.arp_checkbutton = self.glade_xml.get_widget("arp_checkbutton")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    #~ def get_eth_checks(self):
        #~ return (self.check_eth, self.input_eth)

    def get_ip_checks(self):
        return (self.check_ip, self.input_ip)

    #~ def check_eth(self, eth):
        #~ if dnet.eth_ntoa(eth.dst).startswith("00:00:5e:00:01:"):
            #~ return (True, True)
        #~ return (False, False)
 
    #~ def input_eth(self, eth, timestamp):
        #~ id = int(dnet.eth_ntoa(eth.dst)[-2:])
        #~ for i in self.liststore:
            #~ if i[self.LIST_ID_ROW] == id:
                #~ if i[self.LIST_STATE_ROW] == "Taken":
                    #~ eth.dst == self.mac
                    #~ self.dnet.send(str(eth))

    def check_ip(self, ip):
        if ip.p == dpkt.ip.IP_PROTO_VRRP:
            (ver_type,) = struct.unpack("!B", str(ip.data)[0])
            if (ver_type >> 4) == VRRP3_VERSION:
                return (True, True)
        return (False, False)

    def input_ip(self, eth, ip, timestamo):
        if ip.src != self.ip:
            if ip.src not in self.peers:
                pkg = vrrp_packet()
                pkg.parse(str(ip.data))
                src = dnet.ip_ntoa(ip.src)
                ips = []
                for i in pkg.ips:
                    ips.append(dnet.ip_ntoa(i))
                iter = self.liststore.append([src, " ".join(ips), pkg.id, pkg.prio, "Seen"])
                self.peers[ip.src] = (iter, pkg, False, False)
                self.log("VRRP-3: Got new peer %s" % (src))

    # SIGNALS #

    def on_get_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            peer = dnet.ip_aton(model.get_value(iter, self.LIST_SRC_ROW))
            (iter, pkg, run, arp) = self.peers[peer]
            if self.arp_checkbutton.get_active():
                arp = 3
            else:
                arp = 0
            self.peers[peer] = (iter, pkg, True, arp)
            model.set_value(iter, self.LIST_STATE_ROW, "Taken")
        if not self.thread.is_alive():
            self.thread.start()

    def on_release_button_clicked(self, btn):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            peer = dnet.ip_aton(model.get_value(iter, self.LIST_SRC_ROW))
            (iter, pkg, run, arp) = self.peers[peer]
            self.peers[peer] = (iter, pkg, False, arp)
            model.set_value(iter, self.LIST_STATE_ROW, "Released")
