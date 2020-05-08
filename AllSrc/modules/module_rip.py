#       module_rip.py
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

RIP_VERSION = 2
RIP_PORT = 520
RIP_MULTICAST_ADDRESS = "224.0.0.9"
RIP_MULTICAST_MAC = "01:00:5e:00:00:09"

class rip_message(object):
    #~  0                   1                   2                   3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |  command (1)  |  version (1)  |       must be zero (2)        |
    #~ +---------------+---------------+-------------------------------+
    #~ |                                                               |
    #~ ~                         RIP Entry (20)                        ~
    #~ |                                                               |
    #~ +---------------+---------------+---------------+---------------+

    COMMAND_REQUEST = 1
    COMMAND_RESPONSE = 2
    
    def __init__(self, command=None, entries=None):
        self.command = command
        if not entries:
            self.entries = []
        else:
            self.entries = entries

    def render(self):
        data = struct.pack("!BBxx", self.command, RIP_VERSION)
        for i in self.entries:
            data += i.render()
        return data

    def parse(self, data):
        (self.command,) = struct.unpack("!Bxxx", data[:4])
        left = data[4:]
        while left:
            (af,) = struct.unpack("!H", data[:2])
            if af == 0xffff:
                entry = rip_auth()
            else:
                entry = rip_entry()
            left = entry.parse(left)
            self.entries.append(entry)

class rip_entry(object):
    #~  0                   1                   2                   3 3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ | Address Family Identifier (2) |        Route Tag (2)          |
    #~ +-------------------------------+-------------------------------+
    #~ |                         IP Address (4)                        |
    #~ +---------------------------------------------------------------+
    #~ |                         Subnet Mask (4)                       |
    #~ +---------------------------------------------------------------+
    #~ |                         Next Hop (4)                          |
    #~ +---------------------------------------------------------------+
    #~ |                         Metric (4)                            |
    #~ +---------------------------------------------------------------+

    AF_INET = 2

    def __init__(self, af=None, tag=None, addr=None, mask=None, nh=None, metric=None):
        self.af = af
        self.tag = tag
        self.addr = addr
        self.mask = mask
        self.nh = nh
        self.metric = metric

    def render(self):
        return struct.pack("!HH", self.af, self.tag) + self.addr + self.mask + self.nh + struct.pack("!I", self.metric)

    def parse(self, data):
        (self.af, self.tag) = struct.unpack("!HH", data[:4])
        self.addr = data[4:8]
        self.mask = data[8:12]
        self.nh = data[12:16]
        (self.metric, ) = struct.unpack("!I", data[16:20])
        return data[20:]

class rip_auth(object):
    #~  0                   1                   2                   3 3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |             0xFFFF            |    Authentication Type (2)    |
    #~ +-------------------------------+-------------------------------+
    #~ ~                       Authentication (16)                     ~
    #~ +---------------------------------------------------------------+

    AUTH_SIMPLE = 2

    def __init__(self, type=None, data=None):
        self.type = type
        self.data = data

    def render(self):
        return struct.pack("!HH16s", 0xffff, self.type, self.data)

    def parse(self, data):
        (self.type, self.data) = struct.unpack("!xxH16s", data[:20])
        return data[20:]

class rip_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.running = True
        self.parent = parent

    def run(self):
        self.parent.log("RIP: Thread started")
        timer = 15
        while self.running:
            if timer == 15:
                timer = 0
                rlist = []
                for ip in self.parent.routes:
                    (iter, mask, nh, metrik) = self.parent.routes[ip]
                    rlist.append(rip_entry(rip_entry.AF_INET, 0, dnet.ip_aton(ip), dnet.ip_aton(mask), dnet.ip_aton(nh), int(metrik)))
                msg = rip_message(rip_message.COMMAND_RESPONSE, rlist)
                data = msg.render()
                for dst in self.parent.hosts:
                    udp_hdr = dpkt.udp.UDP( sport=RIP_PORT,
                                            dport=RIP_PORT,
                                            data=data
                                            )
                    udp_hdr.ulen += len(udp_hdr.data)
                    ip_hdr = dpkt.ip.IP(    ttl=2,
                                            p=dpkt.ip.IP_PROTO_UDP,
                                            src=self.parent.ip,
                                            dst=dnet.ip_aton(RIP_MULTICAST_ADDRESS),
                                            data=str(udp_hdr)
                                            )
                    ip_hdr.len += len(ip_hdr.data)
                    eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(RIP_MULTICAST_MAC),
                                                        src=self.parent.mac,
                                                        type=dpkt.ethernet.ETH_TYPE_IP,
                                                        data=str(ip_hdr)
                                                        )
                    self.parent.dnet.send(str(eth_hdr))
            timer = timer + 1
            time.sleep(1)
        self.parent.log("RIP: Thread terminated")

    def shutdown(self):
        self.running = False

class mod_class(object):
    HOST_IP_ROW = 0

    ROUTE_IP_ROW = 0
    ROUTE_MASK_ROW = 1
    ROUTE_NEXT_HOP_ROW = 2
    ROUTE_METRIC_ROW = 3
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "rip"
        self.group = "ROUTING"
        self.gladefile = "/modules/module_rip.glade"
        self.host_treestore = gtk.TreeStore(str)
        self.route_liststore = gtk.ListStore(str, str, str, str)
        self.thread = None

    def start_mod(self):
        self.thread = rip_thread(self)
        self.hosts = {}
        self.routes = {}

    def shut_mod(self):
        if self.thread:
            if self.thread.is_alive():
                self.thread.shutdown()
        self.host_treestore.clear()
        self.route_liststore.clear()
        
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_add_button_clicked" : self.on_add_button_clicked,
                "on_del_button_clicked" : self.on_del_button_clicked,
                "on_clear_button_clicked" : self.on_clear_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.host_treeview = self.glade_xml.get_widget("host_treeview")
        self.host_treeview.set_model(self.host_treestore)
        self.host_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Host")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOST_IP_ROW)
        self.host_treeview.append_column(column)

        self.route_treeview = self.glade_xml.get_widget("route_treeview")
        self.route_treeview.set_model(self.route_liststore)
        self.route_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.ROUTE_IP_ROW)
        self.route_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Mask")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.ROUTE_MASK_ROW)
        self.route_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Next Hop")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.ROUTE_NEXT_HOP_ROW)
        self.route_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Metric")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.ROUTE_METRIC_ROW)
        self.route_treeview.append_column(column)

        self.ip_entry = self.glade_xml.get_widget("ip_entry")
        self.mask_entry = self.glade_xml.get_widget("mask_entry")
        self.nh_entry = self.glade_xml.get_widget("nh_entry")
        self.metric_entry = self.glade_xml.get_widget("metric_entry")

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

    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.dport == RIP_PORT:
            return (True, False)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        if ip.dst == dnet.ip_aton(RIP_MULTICAST_ADDRESS) and ip.src != self.ip:
            if ip.src not in self.hosts:
                src = dnet.ip_ntoa(ip.src)
                iter = self.host_treestore.append(None, [src])
                self.log("RIP: Got new host %s" % (src))
                self.hosts[ip.src] = (iter, src)
                msg = rip_message()
                msg.parse(udp.data)
                for i in msg.entries:
                    nh = dnet.ip_ntoa(i.nh)
                    if nh == "0.0.0.0":
                        nh = src
                    self.host_treestore.append(iter, ["%s/%s via %s metric %d" % (dnet.ip_ntoa(i.addr), dnet.ip_ntoa(i.mask), nh, i.metric)])
            else:
                (iter, src) = self.hosts[ip.src]
                msg = rip_message(None, [])
                msg.parse(udp.data)
                path = self.host_treestore.get_path(iter)
                expanded = self.host_treeview.row_expanded(path)
                child = self.host_treestore.iter_children(iter)
                while child:
                  self.host_treestore.remove(child)
                  child = self.host_treestore.iter_children(iter)
                for i in msg.entries:
                    nh = dnet.ip_ntoa(i.nh)
                    if nh == "0.0.0.0":
                        nh = src
                    self.host_treestore.append(iter, ["%s/%s via %s metric %d" % (dnet.ip_ntoa(i.addr), dnet.ip_ntoa(i.mask), nh, i.metric)])
                if expanded:
                    self.host_treeview.expand_row(path, False)
    # SIGNALS #

    def on_add_button_clicked(self, btn):
        ip = self.ip_entry.get_text()
        mask = self.mask_entry.get_text()
        nh = self.nh_entry.get_text()
        metric = self.metric_entry.get_text()
        if ip not in self.routes:
            iter = self.route_liststore.append([ip, mask, nh, metric])
            self.routes[ip] = (iter, mask, nh, metric)
            if not self.thread.is_alive():
                self.thread.start()

    def on_del_button_clicked(self, btn):
        select = self.route_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            ip = model.get_value(iter, self.ROUTE_IP_ROW)
            del self.routes[ip]
            del model[iter]
            if not len(self.hosts):
                self.thread.shutdown()
                
    def on_clear_button_clicked(self, btn):
        self.routes = {}
        self.route_liststore.clear()
        if not len(self.hosts):
            self.thread.shutdown()
