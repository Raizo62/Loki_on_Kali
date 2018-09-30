#       module_bgp.py
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

import sys
import signal
import threading
import socket
import struct
import time

import gobject
import gtk
import gtk.glade

BGP_PORT = 179

### BGP_PACKET_STRUCTURES ###

class bgp_msg(object):
    TYPE_OPEN = 1
    TYPE_UPDATE = 2
    TYPE_NOTIFICATION = 3
    TYPE_KEEPALIVE = 4
    
    def __init__(self, msg_type):
        self.type = msg_type

    def render(self, data):
        return ('\xff' * 16) +  struct.pack("!HB", len(data) + 19, self.type) + data

class bgp_open(bgp_msg):
    BGP_VERSION = 4
    
    def __init__(self, my_as, hold_time = 256, identity = "1.3.3.7", parameters = []):
        bgp_msg.__init__(self, self.TYPE_OPEN)
        self.my_as = my_as
        self.hold_time = hold_time
        self.identity = identity
        self.parameters = parameters

    def render(self):
        self.data = struct.pack("!BHH", self.BGP_VERSION, self.my_as, self.hold_time) + socket.inet_aton(self.identity)
        data = ""
        for x in self.parameters:
            data += x.render()
        if data:    self.data += struct.pack("!B", len(data))
        else:       self.data += '\x00'
        return bgp_msg.render(self, self.data + data)

class bgp_parameter(object):
    PARAMETER_CAPABILITY = 2

    def __init__(self, type):
        self.type = type

    def render(self, data = ""):
        a = struct.pack("!BB", self.type, len(data))
        return a + data

class bgp_capability(bgp_parameter):
    CAPABILITY_MP = 1
    CAPABILITS_ROUTE_REFRESH_1 = 2
    CAPABILITS_ROUTE_REFRESH_2 = 128

    def __init__(self, cap_type):
        bgp_parameter.__init__(self, bgp_parameter.PARAMETER_CAPABILITY)
        self.cap_type = cap_type

    def render(self, data = ""):
        a = struct.pack("!BB", self.cap_type, len(data))
        return bgp_parameter.render(self, a + data)

class bgp_capability_mp(bgp_capability):
    def __init__(self, af, sub_af):
        bgp_capability.__init__(self, bgp_capability.CAPABILITY_MP)
        self.af = af
        self.sub_af = sub_af
        
    def render(self):
        return bgp_capability.render(self, struct.pack("!HBB", self.af, 0, self.sub_af))

class bgp_update(bgp_msg):
    def __init__(self, wroutes, path_attr, nlri):
        bgp_msg.__init__(self, self.TYPE_UPDATE)
        self.wroutes = wroutes
        self.path_attr = path_attr
        self.nlri = nlri

    def render(self):
        w_data = ""
        for x in self.wroutes:
            w_data += x.render()
        w_data = struct.pack("!H", len(w_data)) + w_data
        p_data = ""
        for x in self.path_attr:
            p_data += x.render()
        p_data = struct.pack("!H", len(p_data)) + p_data
        n_data = ""
        for x in self.nlri:
            n_data += x.render()
        return bgp_msg.render(self, w_data + p_data + n_data)
        
class bgp_notification(bgp_msg):
    def __init__(self, err_code, err_sub, data = ""):
        bgp_msg.__init__(self, self.TYPE_NOTIFICATION)
        self.err_code = err_code
        self.err_sub = err_sub
        self.data = data
    
    def render(self):
        err = struct.pack("!BB", self.err_code, self.err_sub)
        return bgp_msg.render(self, err + self.data)

class bgp_keepalive(bgp_msg):
    def __init__(self):
        bgp_msg.__init__(self, self.TYPE_KEEPALIVE)

    def render(self):
        return bgp_msg.render(self, "")

class bgp_withdrawn_route(object):
    def __init__(self, length, prefix):
        self.length = length
        self.prefix = socket.inet_aton(prefix)

    def render(self):
        data = struct.pack("!B", self.length)
        for x in xrange(0, self.length / 8):
            data += self.prefix[x:x+1]
        return data

class bgp_path_attr(object):
    PATH_ATTR_ORIGIN = 1
    PATH_ATTR_AS_PATH = 2
    PATH_ATTR_NEXT_HOP = 3
    PATH_ATTR_MULTI_EXIT_DISC = 4
    PATH_ATTR_LOCAL_PREF = 5
    PATH_ATTR_MP_REACH_NLRI = 14
    PATH_ATTR_MP_UNREACH_NLRI = 14
    PATH_ATTR_EXTENDED_COMMUNITIES = 16
    
    def __init__(self, flags, type):
        self.flags = flags
        self.type = type

    def render(self, data):
        ret = struct.pack("!BBB", self.flags, self.type, len(data))
        return ret + data

class bgp_path_attr_origin(bgp_path_attr):
    ORIGIN_IGP = 0
    ORIGIN_EGP = 1
    ORIGIN_INCOMPLETE = 2
    
    def __init__(self, origin):
        bgp_path_attr.__init__(self, 0x40, self.PATH_ATTR_ORIGIN)
        self.origin = origin

    def render(self):
        return bgp_path_attr.render(self, struct.pack("!B", self.origin))

class bgp_as_path_segment(object):
    AS_PATH_AS_SET = 1
    AS_PATH_AS_SEQUENCE = 2
    
    def __init__(self, type, values):
        self.type = type
        self.values = values

    def render(self):
        data = struct.pack("!BB", self.type, len(self.values))
        for x in self.values:
            data += struct.pack("!H", x)
        return data

class bgp_path_attr_as_path(bgp_path_attr):
    def __init__(self, value):
        bgp_path_attr.__init__(self, 0x40, self.PATH_ATTR_AS_PATH)
        self.value = value

    def render(self):
        data = ""
        for x in self.value:
            data += x.render()
        return bgp_path_attr.render(self, data)
        
class bgp_path_attr_next_hop(bgp_path_attr):
    def __init__(self, next_hop):
        bgp_path_attr.__init__(self, 0x40, self.PATH_ATTR_NEXT_HOP)
        self.next_hop = socket.inet_aton(next_hop)

    def render(self):
        return bgp_path_attr.render(self, self.next_hop)

class bgp_path_attr_multi_exit_disc(bgp_path_attr):
    def __init__(self, multi_exit_disc):
        bgp_path_attr.__init__(self, 0x80, self.PATH_ATTR_MULTI_EXIT_DISC)
        self.multi_exit_disc = multi_exit_disc

    def render(self):
        return bgp_path_attr.render(self, struct.pack("!L", self.multi_exit_disc))

class bgp_path_attr_local_pref(bgp_path_attr):
    def __init__(self, local_pref):
        bgp_path_attr.__init__(self, 0x40, self.PATH_ATTR_LOCAL_PREF)
        self.local_pref = local_pref

    def render(self):
        return bgp_path_attr.render(self, struct.pack("!L", self.local_pref))

class bgp_extended_community(object):
    def __init__(self, encode, type, subtype, val1, val2 = "", val3 = ""):
        self.encode = encode
        self.type = type
        self.subtype = subtype
        self.val1 = val1
        self.val2 = val2
        self.val3 = val3

    def render(self):
        if self.encode == "two-octed":
            return struct.pack("!BBHL", self.type, self.subtype, self.val1, self.val2)
        if self.encode == "ipv4":
            data = struct.pack("!BB", self.type, self.subtype)
            data += socket.inet_aton(self.val1)
            data += struct.pack("!H", self.val2)
            return data
        if self.encode == "opaque":
            a = self.val1 % 256
            return struct.pack("!BBLH", self.type, self.subtype, self.val1 / 256, a)
        if self.encode == "ospf-domain":
            data = struct.pack("!BB", self.type, self.subtype)
            data += socket.inet_aton(self.val1)
            data += struct.pack("!BB", self.val2, self.val3)
            return data
        else:
            a = self.val1 % 4096
            b = a % 16
            return struct.pack("!BLHB", self.type, self.val1 / 4096, a / 16, b)

class bgp_path_attr_extended_communities(bgp_path_attr):
    def __init__(self, communities):
        bgp_path_attr.__init__(self, 0xc0, self.PATH_ATTR_EXTENDED_COMMUNITIES)
        self.communities = communities

    def render(self):
        data = ""
        for x in self.communities:
            data += x.render()
        return bgp_path_attr.render(self, data)

class bgp_mp_rfc3107_nlri(object):
    def __init__(self, length, stack, prefix):
        self.length = length
        self.stack = stack
        self.prefix = prefix
        
    def render(self):
        data = struct.pack("!B", self.length)
        x = self.stack.split(':')
        for y in xrange(0, len(x)):
            a = int(x[y]) % 16
            data += struct.pack("!H", int(x[y]) / 16)
            a *= 16
            if y == len(x) - 1:
                a += 1
            data += struct.pack("!B", a)
        b = self.prefix.split(':')
        data += struct.pack("!LL", int(b[0]), int(b[1]))
        data += socket.inet_aton(b[2])
        return data
    
class bgp_path_attr_mp_reach_nlri(bgp_path_attr):
    AF_IPV4 = 1
    SUB_AF_VPN = 128

    def __init__(self, type, next_hop, snpa, net_reach):
        bgp_path_attr.__init__(self, 0x80, self.PATH_ATTR_MP_REACH_NLRI)
        if type == "ipv4-mpls":
            self.af_id = self.AF_IPV4
            self.sub_af_id = self.SUB_AF_VPN
            self.addr_len = 12
        else:
            self.af_id = 0
            self.sub_af_id = 0
            self.addr_len = 0

        self.next_hop = next_hop
        self.snpa = snpa
        self.net_reach = net_reach

    def render(self):
        data = struct.pack("!HBB", self.af_id, self.sub_af_id, self.addr_len)
        a = self.next_hop.split(':')
        data += struct.pack("!LL", int(a[0]), int(a[1]))
        data += socket.inet_aton(a[2])
        data += struct.pack("!B", len(self.snpa))
        for x in self.snpa:
            data += x.render()
        for x in self.net_reach:
            data += x.render()
        return bgp_path_attr.render(self, data)

class bgp_path_attr_mp_unreach_nlri(bgp_path_attr):
    def __init__(self, type, wroutes):
        bgp_path_attr.__init__(self, 0x80, self.PATH_ATTR_MP_UNREACH_NLRI)
        if type == "ipv4-mpls":
            self.af_id = AF_IPV4
            self.sub_af_id = SUB_AF_VPN
        else:
            self.af_id = 0
            self.sub_af_id = 0
        self.wroutes = wroutes

    def render(self):
        data = struct.pack("!BH", self.af_id, self.sub_af_id)
        for x in self.wroutes:
            data += x.render()
        return bgp_path_attr.render(self, data)

class bgp_nlri(object):
    def __init__(self, length, prefix):
        self.length = length
        self.prefix = socket.inet_aton(prefix)

    def render(self):
        data = struct.pack("!B", self.length)
        for x in xrange(0, self.length / 8):
            data += self.prefix[x:x+1]
        return data

### BGP_SESSION_CLASS ###

class bgp_session(threading.Thread):
    def __init__(self, parent, host, parameters, my_as, hold_time = 256, md5 = [], identity = "1.3.3.7"):
        self.parent = parent
        self.log = parent.log
        self.liststore = parent.liststore
        self.host = host
        self.dest = None
        self.sock = None
        self.parameters = parameters
        self.my_as = my_as
        self.hold_time = hold_time
        self.md5 = md5
        self.identity = identity
        self.keepalive_msg = bgp_keepalive()
        self.active = False
        self.fuzz = False
        self.msg = None
        self.sem = threading.Semaphore()
        threading.Thread.__init__(self)

    def connect(self, dest, timeout = 1, bf = False):
        self.dest = dest
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

        if self.parent.platform == "Linux" or self.parent.platform == "FreeBSD":
            import loki_bindings
            for (i, j) in self.md5:
                if i == self.dest:
                    loki_bindings.tcpmd5.tcpmd5.set(self.sock.fileno(), self.parent.ip, i, BGP_PORT, j)
            
        self.sock.connect((self.dest, BGP_PORT))
        if not bf:
            msg = bgp_open(self.my_as, self.hold_time, self.identity, self.parameters)
            self.sock.send(msg.render())
            self.active = True
        
    def update(self, msg):
        self.fuzz = False
        self.sem.acquire()
        self.msg = msg
        self.sem.release()

    def shutdown(self):
        self.active = False
    
    def run(self):
        iter = self.liststore.append([self.host, self.host])
        
        self.keepalive()
        self.log("BGP: Keepalive thread terminated for %s" % (self.host))

        if self.liststore.iter_is_valid(iter):
            self.liststore.remove(iter)
        
        del self.parent.sessions[self.host]

    def keepalive(self):
        while self.active:
            self.sem.acquire()
            try:
                self.sock.send(self.keepalive_msg.render())
                if self.msg:
                    self.sock.send(self.msg.render())
                    self.msg = None
            except socket.error:
                self.log("BGP: Connection to %s interupted" % (self.host))
                self.active = False
            self.sem.release()
            time.sleep(self.hold_time / 4)
        if self.parent.platform == "Linux" or self.parent.platform == "FreeBSD":
            import loki_bindings
            for (i, j) in self.md5:
                if i == self.dest:
                    loki_bindings.tcpmd5.tcpmd5.clear(self.sock.fileno(), self.parent.ip, i, BGP_PORT)
        self.sock.close()

### MODULE_CLASS ###

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "bgp"
        self.group = "ROUTING"
        self.gladefile = "/modules/module_bgp.glade"
        self.liststore = gtk.ListStore(str, str)
        self.sessions = {}

    def start_mod(self):
        self.sessions = {}
        self.md5 = []
        self.msg = None
        self.parameters = []

    def shut_mod(self):
        for i in self.sessions:
            self.sessions[i].shutdown()
        self.liststore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_connect_button_clicked" : self.on_connect_button_clicked,
                "on_update_button_clicked" : self.on_update_button_clicked,
                "on_disconnect_button_clicked" : self.on_disconnect_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)
        self.treeview = self.glade_xml.get_widget("connection_view")
        self.treeview.set_model(self.liststore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Hosts")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.treeview.append_column(column)

        self.md5_entry = self.glade_xml.get_widget("md5_entry")
        if self.platform != "Linux" and self.platform != "FreeBSD":
            self.md5_entry.set_text("not available on %s" % self.platform)
            self.md5_entry.set_property("sensitive", False)            

        self.ip_entry = self.glade_xml.get_widget("ip_entry")
        self.as_entry = self.glade_xml.get_widget("as_entry")
        self.params_entry = self.glade_xml.get_widget("params_entry")
        self.hold_entry = self.glade_xml.get_widget("hold_entry")

        self.msg_view = self.glade_xml.get_widget("msg_view")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = ip

    # SIGNALS #

    def on_connect_button_clicked(self, data):
        ip = self.ip_entry.get_text()
        if ip in self.sessions:
            self.log("BGP: Host already created")
            return

        md5 = []
        if self.platform == "Linux" or self.platform == "FreeBSD":
            secret = self.md5_entry.get_text()
            if not secret == "":
                md5.append((ip, secret))
        
        params_cmd = self.params_entry.get_text()
        if params_cmd != "":
            params_cmd = "parameters = %s" % (params_cmd)
            try:
                exec(params_cmd)
            except Exception, e:
                self.log("BGP: Can't compile connection parameters: %s" % (e))
                return
        else:
            parameters = []
        as_num = int(self.as_entry.get_text())
        hold = int(self.hold_entry.get_text())
        self.sessions[ip] = bgp_session(self, ip, parameters, as_num, hold, md5, self.ip)
        try:
            self.sessions[ip].connect(ip)
        except Exception, e:
            self.log("BGP: Can't connect to %s: %s" %  (ip, e.__str__()))
            del self.sessions[ip]
            return
        self.log("BGP: Connected to %s" % (ip))
        try:
            self.sessions[ip].start()
        except Exception, e:
            self.log("BGP: Can't start thread for %s: %s" % (ip, e.__str__()))
            del self.sessions[ip]
            return
        self.log("BGP: Keepalive thread started for %s" % (ip))

    def on_update_button_clicked(self, data):
        buffer = self.msg_view.get_buffer()
        text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter())
        if text != "":
            try:
                exec("msg = " + text)
            except Exception, e:
                self.log("BGP: Can't compile update statement: %s" % (e))
                return
            select = self.treeview.get_selection()
            (model, paths) = select.get_selected_rows()
            for i in paths:
                host = model.get_value(model.get_iter(i), 1)
                self.log("BGP: Sending update to %s" % (host))
                self.sessions[host].update(msg)

    def on_disconnect_button_clicked(self, data):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 1)
            self.log("BGP: Shuting down connection to %s" % (host))
            self.sessions[host].shutdown()
