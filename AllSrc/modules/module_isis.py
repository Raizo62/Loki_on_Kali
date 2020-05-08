#       module_isis.py
#       
#       Copyright 2013 Daniel Mende <dmende@ernw.de>
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
import hmac
import math
import os
import struct
import tempfile
import threading
import time

import dnet
import dpkt
import IPy

import gobject
import gtk
import gtk.glade

ISIS_VERSION = 1
ISIS_PROTOCOL_DISCRIMINATOR = 0x83
ISIS_ALL_L1_IS_MAC = "01:80:c2:00:00:14"
ISIS_ALL_L2_IS_MAC = "01:80:c2:00:00:15"

class isis_pdu_header(object):
    TYPE_L1_HELLO = 15
    TYPE_L2_HELLO = 16
    TYPE_P2P_HELLO = 17
    TYPE_L1_LINK_STATE = 18
    TYPE_L2_LINK_STATE = 20
    TYPE_L1_COMPLETE_SEQUENCE = 24
    TYPE_L2_COMPLETE_SEQUENCE = 25
    TYPE_L1_PARTIAL_SEQUENCE = 26
    TYPE_L2_PARTIAL_SEQUENCE = 27
    
    def __init__(self, sys_id_length=None, pdu_type=None, eco=None, user_eco=None):
        self.sys_id_length = sys_id_length
        self.pdu_type = pdu_type
        self.eco = eco
        self.user_eco = user_eco
        
    def render(self, data):
        return struct.pack("!BBBBBBBB", ISIS_PROTOCOL_DISCRIMINATOR, len(data)+8, ISIS_VERSION, self.sys_id_length,
                                self.pdu_type, ISIS_VERSION, self.eco, self.user_eco) + data
    
    def parse(self, data):
        (self.header_length, self.sys_id_length, self.pdu_type, self.eco, self.user_eco) = struct.unpack("!xBxBBxBB", data[:8])
        return data[8:] 

class isis_pdu_lan_hello(isis_pdu_header):
    def __init__(self, level=None, circuit_type=None, source_id=None, hold_timer=None, priority=None, lan_id=None, tlvs=[], mtu=1497):
        self.circuit_type = circuit_type
        self.source_id = source_id
        self.hold_timer = hold_timer
        self.priority = priority
        self.lan_id = lan_id
        self.tlvs = tlvs
        self.mtu = mtu
        if level is not None:
            isis_pdu_header.__init__(self, 0, level, 0, 0)
        else:
            isis_pdu_header.__init__(self)
    
    def __repr__(self):
        return "ISIS-HELLO CircT(%x) SysID(%s) HoldT(%d) Prio(%d) LanID(%s) TLVs(%s)" % \
                    (
                     self.circuit_type,
                     self.source_id.encode("hex"),
                     self.hold_timer,
                     self.priority,
                     self.lan_id.encode("hex"),
                     ", ".join([ str(i) for i in self.tlvs ])
                    )
    
    def render(self):
        tlv_data = ""
        for t in self.tlvs:
            tlv_data += t.render()
        while len(tlv_data) < self.mtu - 27:
            t = isis_tlv(isis_tlv.TYPE_PADDING, "\x00" * min(255, self.mtu - 27 - 2 - len(tlv_data)))
            tlv_data += t.render()
        return isis_pdu_header.render(self, struct.pack("!B6sHHB7s", self.circuit_type, self.source_id, self.hold_timer,
                                len(tlv_data) + 27, self.priority, self.lan_id)) + tlv_data
        
    def parse(self, data):
        data = isis_pdu_header.parse(self, data)
        (self.circuit_type, self.source_id, self.hold_timer, self.pdu_length, self.priority, self.lan_id) = struct.unpack("!B6sHHB7s", data[:19])
        self.tlvs = parse_tlvs(data[19:])

class isis_pdu_link_state(isis_pdu_header):
    MODX = 4102
    def __init__(self, level=None, lifetime=None, lsp_id=None, sequence=None, type_block=None, tlvs=[]):
        self.lifetime = lifetime
        self.lsp_id = lsp_id
        self.sequence = sequence
        self.type_block = type_block
        self.tlvs = tlvs
        self.checksum = None
        if level is not None:
            isis_pdu_header.__init__(self, 0, level, 0, 0)
        else:
            isis_pdu_header.__init__(self)
    
    def __repr__(self):
        return "ISIS-LSP Live(%d) ID(%s) Seq(%d) Type(%x) TLVs(%s)" % \
                (
                 self.lifetime,
                 self.lsp_id.encode("hex"),
                 self.sequence,
                 self.type_block,
                 ", ".join([ str(i) for i in self.tlvs ])
                )
        
    def render(self):
        tlv_data = ""
        for t in self.tlvs:
            tlv_data += t.render()
        data = isis_pdu_header.render(self, struct.pack("!HH8sIHB", len(tlv_data) + 27, self.lifetime, self.lsp_id,
                                    self.sequence, 0, self.type_block)) + tlv_data
        if self.checksum is None:
            self.checksum = self.lsp_checksum(data[12:], 12)
        return data[:24] + self.checksum + data[26:]
        
    def parse(self, data):
        data = isis_pdu_header.parse(self, data)
        (self.pdu_length, self.lifetime, self.lsp_id, self.sequence) = struct.unpack("!HH8sI", data[:16])
        self.checksum = data[16:18]
        self.type_block, = struct.unpack("!B", data[18])
        self.tlvs = parse_tlvs(data[19:])

    def lsp_checksum(self, data, offset):
        l = len(data)
        left = l
        p = 0
        c0 = 0
        c1 = 0
        while left != 0:
            partial_len = min(left, self.MODX)
            for i in xrange(partial_len):
                c0 = c0 + ord(data[p])
                c1 += c0
                p += 1
            c0 = int(math.fmod(c0, 255))
            c1 = int(math.fmod(c1, 255))
            left -= partial_len
        x = int(math.fmod((l - offset - 1) * c0 - c1, 255))
        if x <= 0:
            x += 255
        y = 510 - c0 - x
        if y > 255:
            y -= 255
        return chr(x)+chr(y)

class isis_pdu_complete_sequence(isis_pdu_header):
    def __init__(self, level=None, source_id=None, start_lsp=None, end_lsp=None, tlvs=[]):
        self.source_id = source_id
        self.start_lsp = start_lsp
        self.end_lsp = end_lsp
        self.tlvs = tlvs
        if level is not None:
            isis_pdu_header.__init__(self, 0, level, 0, 0)
        else:
            isis_pdu_header.__init__(self)
        
    def render(self):
        tlv_data = ""
        for t in self.tlvs:
            tlv_data += t.render()
        return isis_pdu_header.render(self, struct.pack("!H7s8s8s", len(tlv_data) + 33, self.source_id, self.start_lsp, self.end_lsp)) + tlv_data
        
    def parse(self, data):
        data = self.isis_pdu_header(self, data)
        (self.pdu_length, self.source_id, self.start_lsp, self.end_lsp) = struct.unpack("!H7s8s8s", data[:25])
        self.tlvs = parse_tlvs(data[25:])

def get_tlv(pdu, ttype):
    for i in pdu.tlvs:
        if i.t == ttype:
            return i
    return None

def parse_tlvs(data):
    tlvs = []
    while len(data) > 0:
        tlv = isis_tlv()
        data_new = tlv.parse(data)
        if tlv.t == isis_tlv.TYPE_AREA_ADDRESS:
            tlv = isis_tlv_area_address()
            data = tlv.parse(data)
        elif tlv.t == isis_tlv.TYPE_AUTHENTICATION:
            tlv = isis_tlv_authentication()
            data = tlv.parse(data)
        else:
            data = data_new
        tlvs.append(tlv)
    return tlvs
        
class isis_tlv(object):
    TYPE_AREA_ADDRESS =     0x01
    TYPE_IS_REACH =         0x02
    TYPE_ES_NEIGHBOUR =     0x03
    TYPE_IS_NEIGHBOURS =    0x06
    TYPE_PADDING =          0x08
    TYPE_LSP_ENTRIES =      0x09
    TYPE_AUTHENTICATION =   0x0a
    TYPE_IP_INT_REACH =     0x80
    TYPE_PROTOCOL_SUPPORT = 0x81
    TYPE_IP_INT_ADDRESS =   0x84
    TYPE_HOSTNAME =         0x89
    TYPE_RESTART_SIGNALING= 0xd3
    TYPE_IP6_INT_ADDRESS =  0xe8
    TYPE_IP6_INT_REACH =    0xec
    
    type_to_str = { 0x01    :   "TYPE_AREA_ADDRESS",
                    0x02    :   "TYPE_IS_REACH",
                    0x03    :   "TYPE_ES_NEIGHBOUR",
                    0x06    :   "TYPE_IS_NEIGHBOURS",
                    0x08    :   "TYPE_PADDING",
                    0x09    :   "TYPE_LSP_ENTRIES",
                    0x0a    :   "TYPE_AUTHENTICATION",
                    0x80    :   "TYPE_IP_INT_REACH",
                    0x81    :   "TYPE_PROTOCOL_SUPPORT",
                    0x84    :   "TYPE_IP_INT_ADDRESS",
                    0x89    :   "TYPE_HOSTNAME",
                    0xd3    :   "TYPE_RESTART_SIGNALING",
                    0xe8    :   "TYPE_IP6_INT_ADDRESS",
                    0xec    :   "TYPE_IP6_INT_REACH"
                    }
    
    def __init__(self, t=None, v=None):
        self.t = t
        self.v = v
    
    def __repr__(self):
        return "ISIS-TLV %s v(%s)" % (self.type_to_str[self.t], self.v.encode("hex"))
    
    def render(self, data=None):
        if data is None:
            data = self.v
        return struct.pack("!BB", self.t, len(data)) + data
    
    def parse(self, data):
        (self.t, self.l) = struct.unpack("!BB", data[:2])
        self.v = data[2:2+self.l]
        return data[2+self.l:]

class isis_tlv_authentication(isis_tlv):
    AUTH_TYPE_NONE =        0x00 
    AUTH_TYPE_CLEAR_TEXT =  0x01
    AUTH_TYPE_HMAC_MD5 =    0x36
    
    def __init__(self):
        self.auth_type = None
        self.secret = None
        self.digest = None
        isis_tlv.__init__(self, isis_tlv.TYPE_AUTHENTICATION)
    
    def __repr__(self):
        if self.auth_type == self.AUTH_TYPE_CLEAR_TEXT:
            return "Clear Text: '%s'" % self.secret
        elif self.auth_type == self.AUTH_TYPE_HMAC_MD5:
            if not self.secret is None:
                return "HMAC-MD5: '%s'" % self.secret
            else:
                return "HMAC-MD5"
        return ""
    
    def render(self):
        if self.auth_type == self.AUTH_TYPE_CLEAR_TEXT:
            data = chr(self.auth_type) + self.secret
        elif self.auth_type == self.AUTH_TYPE_HMAC_MD5:
            if self.digest is None:
                data = chr(self.auth_type) + "\x00" * 16
            else:
                data = chr(self.auth_type) + self.digest
        else:
            return ""
        return isis_tlv.render(self, data)
    
    def parse(self, data):
        data = isis_tlv.parse(self, data)
        self.auth_type, = struct.unpack("!B", self.v[0])
        if self.auth_type == self.AUTH_TYPE_CLEAR_TEXT:
            self.secret = self.v[1:]
        elif self.auth_type == self.AUTH_TYPE_HMAC_MD5:
            self.digest = self.v[1:]
        return data

class isis_tlv_area_address(isis_tlv):
    def __init__(self):
        self.addresses = []
        isis_tlv.__init__(self, isis_tlv.TYPE_AREA_ADDRESS)
        
    def __repr__(self):
        return ", ".join([a.encode("hex") for a in self.addresses])
    
    def render(self):
        data = ""
        for i in self.addresses:
            data += struct.pack("!B", len(i)) + i
        return isis_tlv.render(self, data)
        
    def parse(self, data):
        data = isis_tlv.parse(self, data)
        while len(self.v) > 0:
            (alen, ) = struct.unpack("!B", self.v[:1])
            self.addresses.append(self.v[1:1+alen])
            self.v = self.v[1+alen:]
        return data
        
class isis_md5bf(threading.Thread):
    def __init__(self, parent, iter, digest, data, identifier):
        self.parent = parent
        self.iter = iter
        self.digest = digest
        self.data = data
        self.identifier = identifier
        self.obj = None
        threading.Thread.__init__(self)

    def run(self):
        if self.parent.platform == "Windows":
            import bf
        else:
            from loki_bindings import bf
        l = self.parent.parent
        self.obj = bf.isis_hmac_md5_bf()
        self.obj.num_threads = l.bruteforce_threads
        if not l.bruteforce:
            self.obj.mode = bf.MODE_WORDLIST
            self.obj.wordlist = l.wordlist
        else:
            if not l.bruteforce_full:
                self.obj.mode = bf.MODE_ALPHANUM
            else:
                self.obj.mode = bf.MODE_FULL
        self.obj.pre_data = self.data
        self.obj.hash_data = self.digest
        
        self.obj.start()
        while self.obj.running:
            time.sleep(0.01)
        
        #if self.parent.ui == 'gtk':
        with gtk.gdk.lock:        
            if self.parent.neighbor_treestore.iter_is_valid(self.iter):
                if not self.obj.pw is None:
                    self.parent.neighbor_treestore.set_value(self.iter, self.parent.NEIGH_CRACK_ROW, self.obj.pw)
                    self.parent.log("ISIS: Found password '%s' for %s" % (self.obj.pw, self.identifier))
                else:
                    self.parent.neighbor_treestore.set_value(self.iter, self.parent.NEIGH_CRACK_ROW, "NOT FOUND")
                    self.parent.log("ISIS: No password found for %s" % (self.identifier))
        self.obj = None

    def quit(self):
        if not self.obj is None:
            self.obj.stop()
            self.obj = None
        
class isis_thread(threading.Thread):
    def __init__(self, parent):
        self.parent = parent
        self.running = True
        self.hello = False
        self.exchange = False
        self.sequence = 1
        self.count = 0
        threading.Thread.__init__(self)
    
    def send_multicast(self, pdu):
        if not self.parent.auth is None and not self.parent.auth_secret is None:
            if self.parent.auth.auth_type == isis_tlv_authentication.AUTH_TYPE_HMAC_MD5:
                local = copy.deepcopy(pdu)
                if local.pdu_type == isis_pdu_header.TYPE_L1_HELLO or local.pdu_type == isis_pdu_header.TYPE_L2_HELLO:
                    pass #does cisco auth hellos with hmac?
                elif local.pdu_type == isis_pdu_header.TYPE_L1_LINK_STATE or local.pdu_type == isis_pdu_header.TYPE_L2_LINK_STATE:
                    local.lifetime = 0
                    local.checksum = "\x00\x00"
                    get_tlv(local, isis_tlv.TYPE_AUTHENTICATION).digest = None
                    mac = hmac.new(self.parent.auth_secret)
                    mac.update(local.render())
                    get_tlv(pdu, isis_tlv.TYPE_AUTHENTICATION).digest = struct.pack("!16s", mac.digest())
                elif local.pdu_type == isis_pdu_header.TYPE_L1_COMPLETE_SEQUENCE or local.pdu_type == isis_pdu_header.TYPE_L2_COMPLETE_SEQUENCE:
                    local.lifetime = 0
                    local.checksum = "\x00\x00"
                    get_tlv(local, isis_tlv.TYPE_AUTHENTICATION).digest = None
                    mac = hmac.new(self.parent.auth_secret)
                    mac.update(local.render())
                    get_tlv(pdu, isis_tlv.TYPE_AUTHENTICATION).digest = struct.pack("!16s", mac.digest())
        data = pdu.render()
        llc = "\xfe\xfe\x03" + data
        eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(ISIS_ALL_L1_IS_MAC if self.parent.level == isis_pdu_header.TYPE_L1_HELLO else ISIS_ALL_L2_IS_MAC),
                                            src=self.parent.mac,
                                            type=len(llc),
                                            data=llc
                                            )
        self.parent.dnet.send(str(eth_hdr))
    
    def refresh_lsps(self, level, tblock):
        #neighbors
        is_reach = "\x00" + struct.pack("!BBBB", 0x00, 0x80, 0x80, 0x80) + self.parent.sysid + "\x00"
        if not self.parent.neighbors is None:
            for i in self.parent.neighbors:
                is_reach += struct.pack("!BBBB", 0x00, 0x80, 0x80, 0x80) + self.parent.neighbors[i]["hello"].source_id + "\x00"
        es_neigh = struct.pack("!BBBB", 0x0a, 0x80, 0x80, 0x80)
        tlvs = [    isis_tlv(isis_tlv.TYPE_IS_REACH, is_reach),
                    isis_tlv(isis_tlv.TYPE_ES_NEIGHBOUR, es_neigh)
                    ]
        if not self.parent.auth is None:
            tlvs = [self.parent.auth] + tlvs
        lsp = isis_pdu_link_state(level,
                                  1199,
                                  self.parent.sysid + "\x01\x00",
                                  self.sequence,
                                  tblock,
                                  tlvs
                                  )
        self.parent.lsps[0x0100] = lsp
        self.send_multicast(lsp)
        self.sequence = self.sequence + 1
        #local routes
        protos = ""
        if "ip" in dir(self.parent) and not self.parent.ip is None:
            protos += "\xcc" #IP
        if "ip6_ll" in dir(self.parent) and not self.parent.ip6_ll is None:
            protos += "\x8e" #IP6
        local_net = IPy.IP("%s/%s" % (dnet.ip_ntoa(self.parent.ip), dnet.ip_ntoa(self.parent.mask)), make_net=True)
        ip_int_reach = "%s%s%s" % (struct.pack("!BBBB", 0x0a, 0x80, 0x80, 0x80),
                                   dnet.ip_aton(str(local_net.net())),
                                   dnet.ip_aton(str(local_net.netmask()))
                                   )
        for i in self.parent.nets:
            ip_int_reach += "%s%s%s" % (struct.pack("!BBBB", 0x0a, 0x80, 0x80, 0x80),
                                        dnet.ip_aton(self.parent.nets[i]["net"]),
                                        dnet.ip_aton(self.parent.nets[i]["mask"])
                                        )
        if not self.parent.loopback is None:
            ip_int_reach += "%s%s%s" % (struct.pack("!BBBB", 0x00, 0x80, 0x80, 0x80),
                                       self.parent.loopback,
                                       "\xff\xff\xff\xff"
                                       )
        local_net6 = IPy.IP("%s/%s" % (dnet.ip6_ntoa(self.parent.ip6), self.parent.mask6), make_net=True)
        ip6_int_reach = "%s%s" % (struct.pack("!IBB", 0x0a, 0x0, self.parent.mask6),
                                  dnet.ip6_aton(str(local_net6.net()))[:self.parent.mask6//8]
                                  )
        for i in self.parent.nets6:
            ip6_int_reach += "%s%s" % (struct.pack("!IBB", 0x0a, 0x0, int(self.parent.nets6[i]["mask"])),
                                       dnet.ip6_aton(self.parent.nets6[i]["net"])[:int(self.parent.nets6[i]["mask"])//8]
                                       )
        ip6_int_reach += "%s%s" % (struct.pack("!IBB", 0x00, 0x0, 128),
                                       self.parent.loopback6
                                       )
        is_reach = "\x00"
        is_reach += struct.pack("!BBBB", 0x0a, 0x80, 0x80, 0x80) + self.parent.lan_id
        tlvs = [    isis_tlv(isis_tlv.TYPE_AREA_ADDRESS, self.parent.area),
                    isis_tlv(isis_tlv.TYPE_PROTOCOL_SUPPORT, protos),
                    isis_tlv(isis_tlv.TYPE_HOSTNAME, self.parent.hostname)
                    ]        
        if "ip" in dir(self.parent) and not self.parent.ip is None:
            if not self.parent.loopback is None:
                tlvs.append(isis_tlv(isis_tlv.TYPE_IP_INT_ADDRESS, self.parent.loopback))
            else:
                tlvs.append(isis_tlv(isis_tlv.TYPE_IP_INT_ADDRESS, self.parent.ip))
            tlvs.append(isis_tlv(isis_tlv.TYPE_IP_INT_REACH, ip_int_reach))
        if "ip6_ll" in dir(self.parent) and not self.parent.ip6_ll is None:
            if not self.parent.loopback6 is None:
                tlvs.append(isis_tlv(isis_tlv.TYPE_IP6_INT_ADDRESS, self.parent.loopback6))
            else:
                tlvs.append(isis_tlv(isis_tlv.TYPE_IP6_INT_ADDRESS, self.parent.ip6))
            tlvs.append(isis_tlv(isis_tlv.TYPE_IP6_INT_REACH, ip6_int_reach))
        tlvs += [   isis_tlv(isis_tlv.TYPE_IS_REACH, is_reach)      #only in L1 ? FIXME
                    ]
        if not self.parent.auth is None:
            tlvs = [self.parent.auth] + tlvs
        lsp = isis_pdu_link_state(level,
                                  1199,
                                  self.parent.sysid + "\x00\x00",
                                  self.sequence,
                                  tblock,
                                  tlvs
                                  )
        self.parent.lsps[0x0000] = lsp
        self.send_multicast(lsp)
        self.sequence = self.sequence + 1
    
    def run(self):
        while(self.running):
            if self.parent.dnet:
                if self.parent.level == isis_pdu_header.TYPE_L1_HELLO:
                    lsp_level = isis_pdu_header.TYPE_L1_LINK_STATE
                    csnp_level = isis_pdu_header.TYPE_L1_COMPLETE_SEQUENCE
                    tblock = 0x01
                elif self.parent.level == isis_pdu_header.TYPE_L2_HELLO:
                    lsp_level = isis_pdu_header.TYPE_L2_LINK_STATE
                    csnp_level = isis_pdu_header.TYPE_L2_COMPLETE_SEQUENCE
                    tblock = 0x02
                else:
                    lsp_level = isis_pdu_header.TYPE_L1_LINK_STATE
                    csnp_level = isis_pdu_header.TYPE_L1_COMPLETE_SEQUENCE
                    tblock = 0x01
                if self.hello and len(self.parent.neighbors) > 0 and self.count % 3 == 0:
                    protos = ""
                    if "ip" in dir(self.parent) and not self.parent.ip is None:
                        protos += "\xcc" #IP
                    if "ip6_ll" in dir(self.parent) and not self.parent.ip is None:
                        protos += "\x8e" #IP6
                    tlvs = [    isis_tlv(isis_tlv.TYPE_PROTOCOL_SUPPORT, protos),
                                isis_tlv(isis_tlv.TYPE_AREA_ADDRESS, self.parent.area)
                                ]
                    if "ip" in dir(self.parent) and not self.parent.ip is None:
                        tlvs.append(isis_tlv(isis_tlv.TYPE_IP_INT_ADDRESS, self.parent.ip))
                    if "ip6_ll" in dir(self.parent) and not self.parent.ip6_ll is None:
                        tlvs.append(isis_tlv(isis_tlv.TYPE_IP6_INT_ADDRESS, self.parent.ip6_ll))
                    tlvs += [   isis_tlv(isis_tlv.TYPE_RESTART_SIGNALING, "\x00\x00\x00"),
                                isis_tlv(isis_tlv.TYPE_IS_NEIGHBOURS, "".join(self.parent.neighbors.keys())),
                                ]
                    if not self.parent.auth is None:
                        tlvs = [self.parent.auth] + tlvs
                    if self.parent.level == isis_pdu_header.TYPE_L1_HELLO:
                        ctype = 0x01
                    elif self.parent.level == isis_pdu_header.TYPE_L2_HELLO:
                        ctype = 0x02
                    if self.parent.lan_id == None:
                        self.parent.lan_id = self.parent.sysid + "\x01"
                    hello = isis_pdu_lan_hello( self.parent.level,
                                                ctype,
                                                self.parent.sysid,
                                                self.parent.hold_time,
                                                self.parent.priority,
                                                self.parent.lan_id,
                                                tlvs,
                                                self.parent.mtu - 3 - 14
                                                )
                    self.send_multicast(hello)
                    
                    if self.exchange and (self.init or self.parent.nets_changed or self.count % 600 == 0):
                        self.refresh_lsps(lsp_level, tblock)              
                        self.parent.nets_changed = False
                        self.init = False
                    
                    if not len(self.parent.lsps) == 0 and self.count % 10 == 0:
                        entries = []
                        refresh_needed = False
                        for i in self.parent.lsps:
                            self.parent.lsps[i].lifetime -= 10
                            if self.parent.lsps[i].lifetime <= 300:
                                refresh_needed = True
                            entries += [struct.pack("!H8sI2s",
                                                    self.parent.lsps[i].lifetime, 
                                                    self.parent.lsps[i].lsp_id,
                                                    self.parent.lsps[i].sequence,
                                                    self.parent.lsps[i].checksum)]
                        #~ import pprint
                        #~ print "#" * 80
                        #~ pprint.pprint(self.parent.neighbors)
                        #~ print "#" * 80
                        if self.parent.lan_id == self.parent.sysid + "\x01":
                            #we are DR
                            for n in self.parent.neighbors:
                                cur = self.parent.neighbors[n]
                                rem = []
                                for l in cur["lsps"]:
                                    lsp = cur["lsps"][l]["lsp"]
                                    if lsp.lifetime > 10:
                                        lsp.lifetime -= 10
                                    else:
                                        lsp.lifetime = 0
                                        rem.append(l)
                                for l in rem:
                                    del cur["lsps"][l]
                                    entries += [struct.pack("!H8sI2s", lsp.lifetime, lsp.lsp_id, lsp.sequence, lsp.checksum)]
                            
                            entries = "".join(sorted(set(entries)))
                            tlvs = [ isis_tlv(isis_tlv.TYPE_LSP_ENTRIES, entries) ]
                            if not self.parent.auth is None:
                                tlvs = [self.parent.auth] + tlvs
                            csnp = isis_pdu_complete_sequence(csnp_level,
                                                              self.parent.sysid + "\x00",
                                                              "\x00" * 8,
                                                              "\xff" * 8,
                                                              tlvs
                                                              )
                            ##CSNP only if DR
                            self.send_multicast(csnp)
                        
                        if refresh_needed:
                            self.refresh_lsps(lsp_level, tblock)
                
            if not self.running:
                return
            self.count += 1
            time.sleep(self.parent.sleep_time)
    
    def quit(self):
        self.running = False
        
class mod_class(object):
    NEIGH_HOST_ROW = 0
    NEIGH_ID_ROW = 1
    NEIGH_AREA_ROW = 2
    NEIGH_AUTH_ROW = 3
    NEIGH_CRACK_ROW = 4
    NEIGH_DICT_ROW = 5

    NET_NET_ROW = 0
    NET_MASK_ROW = 1
    NET_TYPE_ROW = 2
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "isis"
        self.group = "ROUTING"
        self.gladefile = "/modules/module_isis.glade"
        self.neighbor_treestore = gtk.TreeStore(str, str, str, str, str, gobject.TYPE_PYOBJECT)
        self.network_liststore = gtk.ListStore(str, str)
        self.level_liststore = gtk.ListStore(str, int)
        self.level_liststore.append(["Level 1", isis_pdu_header.TYPE_L1_HELLO])
        self.level_liststore.append(["Level 2", isis_pdu_header.TYPE_L2_HELLO])
        #~ self.auth_type_liststore = gtk.ListStore(str, int)
        #~ for i in dir(isis_tlv_authentication):
            #~ if i.startswith("AUTH_"):
                #~ exec("val = isis_tlv_authentication." + i)
                #~ self.auth_type_liststore.append([i, val])
        self.dnet = None
        self.thread = None
        self.mtu = 1514
        self.sleep_time = 1
        self.level = None
        self.area = None
        self.loopback = None
        self.loopback6 = None
        self.sysid = "loki4u"
        self.hostname = "loki4u"
        self.priority = 0x40
        self.hold_time = 30
        self.auth_secret = None
        self.mac = "\x00\x00\x00\x00\x00\x00"
        self.lsdb = {}

    def start_mod(self):
        self.thread = isis_thread(self)
        self.neighbors = None
        self.neighbors_l1 = {}
        self.neighbors_l2 = {}
        self.nets = {}
        self.nets6 = {}
        self.lsps = {}
        self.nets_changed = False
        self.lan_id = None
        self.auth = None
        self.bf = {}
        self.thread.start()

    def shut_mod(self):
        if self.thread:
            self.thread.quit()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_hello_togglebutton_toggled"     : self.on_hello_togglebutton_toggled,
                "on_bf_button_clicked"              : self.on_bf_button_clicked,
                "on_add_button_clicked"             : self.on_add_button_clicked,
                "on_remove_button_clicked"          : self.on_remove_button_clicked,
                "on_show_topology_button_clicked"   : self.on_show_topology_button_clicked,
                "on_save_topology_button_clicked"   : self.on_save_topology_button_clicked,
            }
        self.glade_xml.signal_autoconnect(dic)

        self.neighbor_treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.neighbor_treeview.set_model(self.neighbor_treestore)
        self.neighbor_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("HOST")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_HOST_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("ID")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_ID_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("AREA")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_AREA_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("AUTH")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_AUTH_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("CRACK")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_CRACK_ROW)
        self.neighbor_treeview.append_column(column)
        
        self.network_treeview = self.glade_xml.get_widget("network_treeview")
        self.network_treeview.set_model(self.network_liststore)
        self.network_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Network")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.network_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Netmask")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.network_treeview.append_column(column)
        
        self.level_combobox = self.glade_xml.get_widget("level_combobox")
        self.level_combobox.set_model(self.level_liststore)
        self.level_combobox.set_active(0)
        
        self.hello_tooglebutton = self.glade_xml.get_widget("hello_tooglebutton")
        self.area_entry = self.glade_xml.get_widget("area_entry")
        self.loopback_entry = self.glade_xml.get_widget("loopback_entry")
        self.auth_data_entry = self.glade_xml.get_widget("auth_data_entry")
        #~ self.id_spinbutton = self.glade_xml.get_widget("id_spinbutton")
        #~ self.auth_type_combobox = self.glade_xml.get_widget("auth_type_combobox")
        #~ self.auth_type_combobox.set_model(self.auth_type_liststore)
        #~ self.auth_type_combobox.set_active(0)
        self.network_entry = self.glade_xml.get_widget("network_entry")
        self.netmask_entry = self.glade_xml.get_widget("netmask_entry")
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)
        self.mask = dnet.ip_aton(mask)

    def set_ip6(self, ip6, mask6, ip6_ll, mask6_ll):
        self.ip6 = dnet.ip6_aton(ip6)
        self.mask6 = len(IPy.IP(mask6).strBin().replace("0", ""))
        self.ip6_ll = dnet.ip6_aton(ip6_ll)
        self.mask6_ll = len(IPy.IP(mask6_ll).strBin().replace("0", ""))

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    def set_int(self, interface):
        self.interface = interface

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.dst == dnet.eth_aton(ISIS_ALL_L1_IS_MAC) or eth.dst == dnet.eth_aton(ISIS_ALL_L2_IS_MAC):
            return (True, True)
        return (False, False)
        
    def input_eth(self, eth, timestamp):
        if eth.src != self.mac:
            data = str(eth.data)[3:]
            if eth.dst == dnet.eth_aton(ISIS_ALL_L1_IS_MAC) or eth.dst == dnet.eth_aton(ISIS_ALL_L2_IS_MAC):
                if eth.dst == dnet.eth_aton(ISIS_ALL_L1_IS_MAC):
                    neighbors = self.neighbors_l1
                    level = "L1: "
                else:
                    neighbors = self.neighbors_l2
                    level = "L2: "
                header = isis_pdu_header()
                header.parse(data)
                if header.pdu_type == isis_pdu_header.TYPE_L1_HELLO or \
                        header.pdu_type == isis_pdu_header.TYPE_L2_HELLO:
                    hello = isis_pdu_lan_hello()
                    hello.parse(data)
                    if eth.src not in neighbors:
                        auth = get_tlv(hello, isis_tlv.TYPE_AUTHENTICATION)
                        if not auth is None:
                            self.auth = auth
                            auth = str(auth)
                        else:
                            auth = "None"
                        cur = {}
                        cur["hello"] = hello
                        with gtk.gdk.lock:
                            cur["iter"] = self.neighbor_treestore.append(None, [
                                                                        level + dnet.eth_ntoa(eth.src), 
                                                                        hello.source_id.encode("hex"), 
                                                                        str(get_tlv(hello, isis_tlv.TYPE_AREA_ADDRESS)),
                                                                        auth, 
                                                                        "",
                                                                        cur
                                                                    ])
                        cur["lsps"] = {}
                        
                        self.log("ISIS: Got new peer %s" % (dnet.eth_ntoa(eth.src)))
                        neighbors[eth.src] = cur
                    else:
                        neighbors[eth.src]["hello"] = hello
                    if self.lan_id == None:
                        if hello.priority > self.priority:
                            self.lan_id = hello.lan_id
                        elif hello.priority == self.priority:
                            remote, = struct.unpack("!Q", "\x00\x00" + eth.src)
                            local, = struct.unpack("!Q", "\x00\x00" + self.mac)
                            if remote > local:
                                self.lan_id = hello.lan_id
                elif header.pdu_type == isis_pdu_header.TYPE_L1_LINK_STATE or \
                        header.pdu_type == isis_pdu_header.TYPE_L2_LINK_STATE:
                    if eth.src in neighbors:
                        cur = neighbors[eth.src]
                        lsp = isis_pdu_link_state()
                        lsp.parse(data)
                        auth = get_tlv(lsp, isis_tlv.TYPE_AUTHENTICATION)
                        if not auth is None:
                            self.auth = auth
                            auth = str(self.auth)
                        else:
                            auth = "None"
                        if lsp.lsp_id in cur["lsps"]:
                            with gtk.gdk.lock:
                                self.neighbor_treestore.remove(cur["lsps"][lsp.lsp_id]["iter"])
                            del cur["lsps"][lsp.lsp_id]
                        new = {}
                        lsp_id = lsp.lsp_id
                        lsp_hname_tlv = get_tlv(lsp, isis_tlv.TYPE_HOSTNAME)
                        if lsp_hname_tlv is None:
                            if lsp_id[:-2] == '6c6f6b693475'.decode("hex"):
                                lsp_hname = "loki4u"
                            else:
                                lsp_hname = None
                        else:
                            lsp_hname = lsp_hname_tlv.v
                        lsp_new = { 'sequence' : lsp.sequence,
                                    'csum'     : lsp.checksum,
                                    'ip_reach' : [],
                                    'ip6_reach': [],
                                    'is_reach' : [],
                                    }
                        with gtk.gdk.lock:
                            new["iter"] = self.neighbor_treestore.append(cur["iter"], [
                                                                        "LSP",
                                                                        lsp.lsp_id.encode("hex"),
                                                                        "",
                                                                        auth,
                                                                        "",
                                                                        new
                                                                    ])
                        new["lsp"] = lsp
                        cur["lsps"][lsp.lsp_id] = new
                        tlv = get_tlv(lsp, isis_tlv.TYPE_IP_INT_REACH)
                        if not tlv is None:
                            prefixes = tlv.v
                            while len(prefixes) > 0:
                                lsp_new['ip_reach'].append({ 'metric'   :   ord(prefixes[0]),
                                                             'prefix'   :   dnet.ip_ntoa(prefixes[4:8]),
                                                             'mask'     :   dnet.ip_ntoa(prefixes[8:12])
                                                             })
                                with gtk.gdk.lock:
                                    self.neighbor_treestore.append(new["iter"], [
                                                                    "IP reachability",
                                                                    "%d" % ord(prefixes[0]),
                                                                    dnet.ip_ntoa(prefixes[4:8]) + " / " + dnet.ip_ntoa(prefixes[8:12]),
                                                                    "",
                                                                    "",
                                                                    {}
                                                                ])
                                prefixes = prefixes[12:]
                        tlv = get_tlv(lsp, isis_tlv.TYPE_IP6_INT_REACH)
                        if not tlv is None:
                            prefixes = tlv.v
                            while len(prefixes) > 0:
                                metric,prefixlen = struct.unpack("!IxB", prefixes[:6])
                                lsp_new['ip6_reach'].append({ 'metric'   :   metric,
                                                              'prefix'   :   dnet.ip6_ntoa(prefixes[6:6+(prefixlen//8)]+"\x00"*(16-(prefixlen//8))),
                                                              'mask'     :   prefixlen
                                                              })
                                with gtk.gdk.lock:
                                    self.neighbor_treestore.append(new["iter"], [
                                                                    "IP6 reachability",
                                                                    "%d" % metric,
                                                                    "%s/%d" % (dnet.ip6_ntoa(prefixes[6:6+(prefixlen//8)]+"\x00"*(16-(prefixlen//8))), prefixlen),
                                                                    "",
                                                                    "",
                                                                    {}
                                                                ])
                                prefixes = prefixes[6+(prefixlen//8):]
                        tlv = get_tlv(lsp, isis_tlv.TYPE_IS_REACH)
                        if not tlv is None:
                            ises = tlv.v[1:]
                            while len(ises) > 0:
                                lsp_new['is_reach'].append({ 'metric'   :   ord(ises[0]),
                                                             'id'   :   ises[4:11].encode("hex")
                                                             })
                                with gtk.gdk.lock:
                                    self.neighbor_treestore.append(new["iter"], [
                                                                    "IS reachability",
                                                                    "%d" % ord(ises[0]),
                                                                    ises[4:11].encode("hex"),
                                                                    "",
                                                                    "",
                                                                    {}
                                                                ])
                                ises = ises[11:]
                        self.thread.exchange = True
                        self.thread.init = True
                        
                        host = lsp_id[:-2].encode("hex")
                        lsp_id = "%d%d" % (ord(lsp_id[-1:]), ord(lsp_id[-2:-1]))
                        if host in self.lsdb:
                            if self.lsdb[host]['hostname'] is None and not lsp_hname is None:
                                self.lsdb[host]['hostname'] = lsp_hname
                            if lsp_id in self.lsdb[host]['links']:
                                entry = self.lsdb[host]['links'][lsp_id]
                                if lsp_new['sequence'] > entry['sequence']:
                                    self.log("ISIS: updating lsp %s:%s" % (host, lsp_id))
                                    self.lsdb[host]['links'][lsp_id] = lsp_new
                            else:
                                self.lsdb[host]['links'][lsp_id] = lsp_new
                        else:
                            self.lsdb[host] = { 'hostname'  :   lsp_hname,
                                                'links'     :  { lsp_id : lsp_new } 
                                                }
                        
                    
    #SIGNALS
    
    def on_hello_togglebutton_toggled(self, btn):
        if btn.get_active():
            self.level_combobox.set_property("sensitive", False)
            self.area_entry.set_property("sensitive", False)
            self.loopback_entry.set_property("sensitive", False)
            self.auth_data_entry.set_property("sensitive", False)
            self.level = self.level_liststore[self.level_combobox.get_active()][1]
            if self.level == isis_pdu_header.TYPE_L1_HELLO:
                self.neighbors = self.neighbors_l1
            else:
                self.neighbors = self.neighbors_l2
            area = self.area_entry.get_text().decode("hex")
            self.area = struct.pack("!B", len(area)) + area
            self.loopback = None
            self.loopback6 = None
            for i in self.loopback_entry.get_text().split(","):
                try:
                    self.loopback = dnet.ip_aton(i.strip())
                except:
                    self.loopback = None
                    try:
                        self.loopback6 = dnet.ip6_aton(i.strip())
                    except:
                        self.loopback6 = None
            self.auth_secret = self.auth_data_entry.get_text()
            self.log("ISIS: Hello thread activated")
        else:
            self.auth_data_entry.set_property("sensitive", True)
            self.area_entry.set_property("sensitive", True)
            self.level_combobox.set_property("sensitive", True)
            self.loopback_entry.set_property("sensitive", True)
            self.log("ISIS: Hello thread deactivated")
        self.thread.hello = btn.get_active()
        
    def on_add_button_clicked(self, btn):
        net = self.network_entry.get_text()
        mask = self.netmask_entry.get_text()
        try:
            dnet.ip_aton(net)
            dnet.ip_aton(mask)
            nets = self.nets
        except:
            try:
                dnet.ip6_aton(net)
                if int(mask) > 128 or int(mask) < 0:
                    raise
                nets = self.nets6
            except:
                self.network_entry.set_text("")
                self.netmask_entry.set_text("")
                return
        iter = self.network_liststore.append([net, mask])
        nets[self.network_liststore.get_string_from_iter(iter)] = {
                "net"   :   net,
                "mask"  :   mask,
            }
        self.nets_changed = True
        
    def on_remove_button_clicked(self, btn):
        select = self.network_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            self.network_liststore.remove(iter)
            if self.network_liststore.get_string_from_iter(iter) in self.nets:
                del self.nets[self.network_liststore.get_string_from_iter(iter)]
            elif self.network_liststore.get_string_from_iter(iter) in self.nets6:
                del self.nets6[self.network_liststore.get_string_from_iter(iter)]
        self.nets_changed = True
    
    def on_bf_button_clicked(self, btn):
        select = self.neighbor_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            obj = model.get_value(iter, self.NEIGH_DICT_ROW)
            if "lsps" in obj:
                ident = model.get_value(iter, self.NEIGH_HOST_ROW).split(" ")[1]
                pdu = obj["hello"]
            else:
                ident = model.get_value(iter, self.NEIGH_ID_ROW)
                pdu = obj["lsp"]
            if ident in self.bf:
                if self.bf[ident].is_alive():
                    return
            enc = model.get_value(iter, self.NEIGH_AUTH_ROW)
            if not enc == "HMAC-MD5":
                self.log("ISIS: Cant crack %s, doesnt use HMAC-MD5 authentication" % ident)
                return
            local = copy.deepcopy(pdu)
            if local.pdu_type == isis_pdu_header.TYPE_L1_HELLO or local.pdu_type == isis_pdu_header.TYPE_L2_HELLO:
                digest = get_tlv(local, isis_tlv.TYPE_AUTHENTICATION).digest
                get_tlv(local, isis_tlv.TYPE_AUTHENTICATION).digest = None
                data = local.render()
            elif local.pdu_type == isis_pdu_header.TYPE_L1_LINK_STATE or local.pdu_type == isis_pdu_header.TYPE_L2_LINK_STATE:
                local.lifetime = 0
                local.checksum = "\x00\x00"
                digest = get_tlv(local, isis_tlv.TYPE_AUTHENTICATION).digest
                get_tlv(local, isis_tlv.TYPE_AUTHENTICATION).digest = None
                data = local.render()
            thread = isis_md5bf(self, iter, digest, data, ident)
            model.set_value(iter, self.NEIGH_CRACK_ROW, "RUNNING")
            thread.start()
            self.bf[ident] = thread
    
    def create_topology(self):
        try:
            import pygraphviz
        except:
            return None
        G = pygraphviz.AGraph(directed=True)
        
        for host in self.lsdb:
            G.add_node(host, label='Router:\\n%s\\nID: %s' % (self.lsdb[host]["hostname"], host), shape="box", color="red")
            for link in self.lsdb[host]['links']:
                G.add_node(host+link, label="IS:\\n%s" % host+link, shape="diamond")
                G.add_edge(host, host+link, color="red", arrowhead=None, style="dashed")
                lsp = self.lsdb[host]['links'][link]
                for is_reach in lsp['is_reach']:
                    G.add_node(is_reach['id'], label="IS:\\n%s" % is_reach['id'], shape="diamond")
                    G.add_edge(host+link, is_reach['id'], weight=is_reach['metric'], label="%d" % is_reach['metric'])
                for ip_reach in lsp['ip_reach']:
                    G.add_node(ip_reach['prefix']+"/"+ip_reach['mask'], label="IPv4\\n%s\\n%s" % (ip_reach['prefix'],ip_reach['mask']))
                    G.add_edge(host+link, ip_reach['prefix']+"/"+ip_reach['mask'], weight=ip_reach['metric'], label="%d" % ip_reach['metric'])
                for ip6_reach in lsp['ip6_reach']:
                    G.add_node(ip6_reach['prefix']+"/%d" % ip6_reach['mask'], label="IPv6\\n%s/%d" % (ip6_reach['prefix'], ip6_reach['mask']))
                    G.add_edge(host+link, ip6_reach['prefix']+"/%d" % ip6_reach['mask'], weight=ip6_reach['metric'], label="%d" % ip6_reach['metric'])
        return G
    
    def on_show_topology_button_clicked(self, btn):
        try:
            import xdot
        except:
            return
        dwindow = xdot.DotWindow()
        dwindow.base_title = "ISIS Topology"
        dwindow.widget.filter = self.parent.dot_prog
        dwindow.set_dotcode(self.create_topology().to_string())
        dwindow.show_all()
    
    def on_save_topology_button_clicked(self, btn):
        dialog = gtk.FileChooserDialog(title="Save", parent=self.parent.window, action=gtk.FILE_CHOOSER_ACTION_SAVE, buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_SAVE,gtk.RESPONSE_OK))
        ffilter = gtk.FileFilter()
        ffilter.set_name(".dot files")
        ffilter.add_pattern("*.dot")
        dialog.add_filter(ffilter)
        ffilter = gtk.FileFilter()
        ffilter.set_name(".png files")
        ffilter.add_pattern("*.png")
        dialog.add_filter(ffilter)
        response = dialog.run()
        if response == gtk.RESPONSE_OK:
            _, ext = os.path.splitext(dialog.get_filename())
            if ext.lower() == ".dot":
                self.create_topology().write(dialog.get_filename())
            elif ext.lower() == ".png":
                self.create_topology().draw(dialog.get_filename(), 'png', 'dot')
        dialog.destroy()
    
    def get_config_dict(self):
        return {    "mtu" : {   "value" : self.mtu,
                                "type" : "int",
                                "min" : 1,
                                "max" : 1514
                                },
                    "hold_time" : {
                               "value" : self.hold_time,
                                "type" : "int",
                                "min" : 0x0000,
                                "max" : 0xffff
                                },
                    "sysid" : { "value" : self.sysid.encode("hex"),
                                "type" : "str",
                                "min" : 12,
                                "max" : 12
                                },
                    "hostname":{"value" : self.hostname,
                                "type" : "str",
                                "min" : 1,
                                "max" : 1514
                                },
                    "priority":{"value" : self.priority,
                                "type" : "int",
                                "min" : 0x01,
                                "max" : 0xff
                                },
                    }
    def set_config_dict(self, dict):
        if dict:
            self.mtu = dict["mtu"]["value"]
            self.hold_time = dict["hold_time"]["value"]
            self.sysid = dict["sysid"]["value"].decode("hex")
            self.hostname = dict["hostname"]["value"]
            self.priority = dict["priority"]["value"]
