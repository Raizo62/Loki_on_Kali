#       module_ospf.py
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

import hashlib
import random
import socket
import struct
import os
import tempfile
import threading
import time

import dnet
import dpkt
import IPy

gobject = None
gtk = None
urwid = None

OSPF_VERSION = 2

SO_BINDTODEVICE	= 25

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
    
def ospf_lsa_checksum(lsa):
    ''' Fletcher checksum for OSPF LSAs, returned as a 2 byte string.
    Give the whole LSA packet as argument.
    For details on the algorithm, see RFC 2328 chapter 12.1.7 and RFC 905 Annex B.
    '''

    CHKSUM_OFFSET = 16
    if len(lsa) < CHKSUM_OFFSET:
        raise Exception("LSA Packet too short (%s bytes)" % len(lsa))

    c0 = c1 = 0
    # Calculation is done with checksum set to zero
    lsa = lsa[:CHKSUM_OFFSET] + "\x00\x00" + lsa[CHKSUM_OFFSET+2:]
    for char in lsa[2:]:  #  leave out age
        c0 += ord(char)
        c1 += c0
    c0 %= 255
    c1 %= 255

    x = ((len(lsa) - CHKSUM_OFFSET - 1) * c0 - c1) % 255
    if (x <= 0):
        x += 255
    y = 510 - c0 - x
    if (y > 255):
        y -= 255
    #checksum = (x << 8) + y
    return chr(x) + chr(y)

def ospf_get_lsa_by_type(type):
    if type == ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS:
        return ospf_router_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_NETWORK_LINKS:
        return ospf_network_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_IP:
        return ospf_summary_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_ASBR:
        return ospf_summary_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_AS_EXTERNAL:
        return ospf_as_external_link_advertisement()
    else:
        raise Exception("Unknown LSA type '%x'" % (type))


### OSPF_PACKET_STRUCTURES ###

class ospf_header(object):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|   Version #   |     Type      |         Packet length         |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Router ID                            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                           Area ID                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|           Checksum            |             AuType            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Authentication                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Authentication                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    TYPE_HELLO = 1
    TYPE_DATABESE_DESCRIPTION = 2
    TYPE_LINK_STATE_REQUEST = 3
    TYPE_LINK_STATE_UPDATE = 4
    TYPE_LINK_STATE_ACK = 5

    AUTH_NONE = 0
    AUTH_SIMPLE = 1
    AUTH_CRYPT = 2
    
    def __init__(self, type=None, id=None, area=None, auth_type=None, auth_data=None):
        self.version = OSPF_VERSION
        self.type = type
        self.id = id
        self.area = area
        self.auth_type = auth_type
        self.auth_data = auth_data

    def auth_to_string(self, type=None):
        if not type:
            type = self.auth_type
        if type == self.AUTH_NONE:
            return "NONE"
        elif type == self.AUTH_SIMPLE:
            return "PLAIN"
        elif type == self.AUTH_CRYPT:
            return "CRYPT"

    def render(self, data):
        if self.auth_type == self.AUTH_CRYPT:
            ret = "%s%s%s%s%s" % (  struct.pack("!BBH", self.version, self.type, len(data) + 24),
                                    self.id,
                                    struct.pack("!LHH", self.area, 0, self.auth_type),
                                    self.auth_data.render(),
                                    data
                                    )
            if self.auth_data.type == ospf_crypt_auth_data.TYPE_MD5:
                hash = hashlib.md5()
            hash.update(ret)
            hash.update(self.auth_data.key)
            ret = "%s%s" % (ret, hash.digest())
        else:
            ret = "%s%s%s%s" % (struct.pack("!BBH", self.version, self.type, len(data) + 24),
                                self.id,
                                struct.pack("!LHHQ", self.area, 0, self.auth_type, 0),
                                data
                                )
            ret = ret[:12] + struct.pack("!H", ichecksum_func(ret)) + ret[14:]
            if self.auth_type == self.AUTH_SIMPLE:
                if len(self.auth_data) < 8:
                    self.auth_data += "\x00" * (8 - len(self.auth_data))
                ret = ret[:16] + self.auth_data + ret[24:]
        return ret

    def parse(self, data):
        (self.version, self.type, self.len, self.id, self.area, csum, self.auth_type, self.auth_data) = struct.unpack("!BBHLLHHQ", data[:24])
        return data[24:]

class ospf_crypt_auth_data(object):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|              0                |    Key ID     | Auth Data Len |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                 Cryptographic sequence number                 |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    TYPE_MD5 = 1

    def __init__(self, key=None, id=None, type=None, sequence=None):
        self.key = key
        self.id = id
        self.type = type
        self.sequence = sequence

    def type_to_len(self, type):
        if type == self.TYPE_MD5:
            return 16

    def len_to_type(self, len):
        if len == 16:
            return self.TYPE_MD5

    def render(self):
        return struct.pack("!xxBBL", self.id, self.type_to_len(self.type), self.sequence)

    def parse(self, data):
        (self.id, len, self.sequence) = struct.unpack("!xxBBL", data)
        self.type = self.len_to_type(len)

class ospf_hello(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                        Network Mask                           |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|         HelloInterval         |    Options    |    Rtr Pri    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     RouterDeadInterval                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      Designated Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                   Backup Designated Router                    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Neighbor                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    OPTION_TOS_CAPABILITY = 0x1
    OPTION_EXTERNAL_ROUTING_CAPABILITY = 0x2
    OPTION_CONTAINS_LSS = 0x10
    OPTION_DEMAND_CIRCUITS = 0x20
    OPTION_ZERO_BIT = 0x40

    def __init__(self, area=None, auth_type=None, auth_data=None, id=None, net_mask=None, hello_interval=None, options=None, router_prio=None, router_dead_interval=None, designated_router=None, backup_designated_router=None, neighbors=None):
        self.net_mask = net_mask
        self.hello_interval = hello_interval
        self.options = options
        self.router_prio = router_prio
        self.router_dead_interval = router_dead_interval
        self.designated_router = designated_router
        self.backup_designated_router = backup_designated_router
        self.neighbors = neighbors
        ospf_header.__init__(self, ospf_header.TYPE_HELLO, id, area, auth_type, auth_data)

    def render(self):
        neighbors = ""
        if self.neighbors:
            for i in self.neighbors:
                neighbors += i
        data = self.net_mask + struct.pack("!HBBLLL", self.hello_interval, self.options, self.router_prio, self.router_dead_interval, self.designated_router, self.backup_designated_router) + neighbors
        return ospf_header.render(self, data)

    def parse(self, data):
        hello = ospf_header.parse(self, data)
        (self.net_mask, self.hello_interval, self.options, self.router_prio, self.router_dead_interval, self.designated_router, self.backup_designated_router) = struct.unpack("!LHBBLLL", hello[:20])
        if len(hello) > 24:
            self.neighbors = []
            for i in xrange(24, len(hello)-4, 4):
                self.neighbors.append(hello[i:i+4])

class ospf_database_description(ospf_header):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|               MTU             |    Options    |0|0|0|0|0|I|M|MS
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     DD sequence number                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                                                               |
    #+-                                                             -+
    #|                             A                                 |
    #+-                 Link State Advertisement                    -+
    #|                           Header                              |
    #+-                                                             -+
    #|                                                               |
    #+-                                                             -+
    #|                                                               |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    FLAGS_INIT = 0x4
    FLAGS_MORE = 0x2
    FLAGS_MASTER_SLAVE = 0x1

    def __init__(self, area=None, auth_type=None, auth_data=None, id=None, mtu=None, options=None, flags=None, sequence_number=None):
        self.mtu = mtu
        self.options = options
        self.flags = flags
        self.sequence_number = sequence_number
        self.lsdb = []
        ospf_header.__init__(self, ospf_header.TYPE_DATABESE_DESCRIPTION, id, area, auth_type, auth_data)
        
    def render(self, data):
        return ospf_header.render(self, struct.pack("!HBBL", self.mtu, self.options, self.flags, self.sequence_number) + data)

    def parse(self, data, parse_lsa=False):
        descr = ospf_header.parse(self, data)
        (self.mtu, self.options, self.flags, self.sequence_number) = struct.unpack("!HBBL", descr[:8])
        left = descr[8:]
        gone = 32
        if parse_lsa:
            while left and gone < self.len and len(left) >= 20:
                lsa = ospf_link_state_advertisement_header()
                lsa.parse(left[:20])
                #print "%i:%i parsed lsa %s type %s %s" % (self.len, gone, left[:20].encode("hex"), lsa.ls_type, lsa)
                self.lsdb.append(lsa)
                left = left[20:]
                gone += 20
        else:
            return left

class ospf_link_state_request(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          LS type                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Link State ID                           |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     Advertising Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, area=None, auth_type=0, auth_data=0, id=None, ls_type=None, ls_id=None, advert_router=None):
        self.ls_type = ls_type
        self.ls_id = ls_id
        self.advert_router = advert_router
        ospf_header.__init__(self, ospf_header.TYPE_LINK_STATE_REQUEST, id, area, auth_type, auth_data)

    def render(self):
        data = struct.pack("!L", self.ls_type) + self.ls_id
        for i in self.advert_router:
            data += i
        return ospf_header.render(self, data)

    def parse(self, data):
        request = self.ospf_header.parse(data)
        (self.ls_type, self.ls_id) = struct.unpack("!LL", request)
        self.advert_router = []
        for i in xrange(8, len(request)-4, 4):
            self.advert_router.append(request[i,i+4])

class ospf_link_state_update(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      # advertisements                         |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                                                               |
    #+-                                                            +-+
    #|                  Link state advertisements                    |
    #+-                                                            +-+
    #|                              ...                              |

    def __init__(self, area=None, auth_type=0, auth_data=0, id=None, advertisements=[]):
        self.advertisements = advertisements
        ospf_header.__init__(self, ospf_header.TYPE_LINK_STATE_UPDATE, id, area, auth_type, auth_data)

    def render(self):
        ret = struct.pack("!L", len(self.advertisements))
        for i in self.advertisements:
            ret += i.render()
        return ospf_header.render(self, ret)

    def parse(self, data):
        update = ospf_header.parse(self, data)
        (num,) = struct.unpack("!L", update[:4])
        left = update[4:]
        nlist = []
        for i in xrange(num):
            if not left:
                break
            advert = ospf_link_state_advertisement_header()
            advert.parse(left)
            lsa = ospf_get_lsa_by_type(advert.ls_type) 
            left = lsa.parse(left)
            nlist.append(lsa)
        self.advertisements = nlist

class ospf_link_state_acknowledgment(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                                                               |
    #+-                                                             -+
    #|                             A                                 |
    #+-                 Link State Advertisement                    -+
    #|                           Header                              |
    #+-                                                             -+
    #|                                                               |
    #+-                                                             -+
    #|                                                               |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |


    def __init__(self, area=None, auth_type=0, auth_data=0, id=None, advertisements=[]):
        self.advertisements = advertisements
        ospf_header.__init__(self, ospf_header.TYPE_LINK_STATE_ACK, id, area, auth_type, auth_data)

    def render(self):
        ret = ""
        for i in self.advertisements:
            if type(i) == ospf_link_state_advertisement_header:
                ret += i.render()
            else:
                ret += ospf_link_state_advertisement_header.render(i, "")
        return ospf_header.render(self, ret)
        
    def parse(self, data):
        ack = self.ospf_header.parse(data)
        for i in xrange(0,len(ack),20):
            header = ospf_link_state_advertisement_header()
            header.parse(ack[i,i+20])
            self.advertisements.append(header)
            
class ospf_link_state_advertisement_header(object):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|            LS age             |    Options    |    LS type    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                        Link State ID                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     Advertising Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     LS sequence number                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|         LS checksum           |             length            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    TYPE_ROUTER_LINKS = 1
    TYPE_NETWORK_LINKS = 2
    TYPE_SUMMARY_LINK_IP = 3
    TYPE_SUMMARY_LINK_ASBR = 4
    TYPE_AS_EXTERNAL = 5

    TYPES = {   1 : "TYPE_ROUTER_LINKS",
                2 : "TYPE_NETWORK_LINKS",
                3 : "TYPE_SUMMARY_LINK_IP",
                4 : "TYPE_SUMMARY_LINK_ASBR",
                5 : "TYPE_AS_EXTERNAL"
                }
    
    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None):
        self.ls_age = ls_age
        self.options = options
        self.ls_type = ls_type
        self.ls_id = ls_id
        self.advert_router = advert_router
        self.ls_seq = ls_seq
        self.csum = None
    
    def __repr__(self):
        return "AGE:%d OPTS:%x TYPE:%s ID:%s ROUTER:%s SEQ:%d" % (self.ls_age, self.options, self.TYPES[self.ls_type], dnet.ip_ntoa(self.ls_id), dnet.ip_ntoa(self.advert_router), self.ls_seq)

    def render(self, data):
        if self.csum:
            return struct.pack("!HBB", self.ls_age, self.options, self.ls_type) + self.ls_id + self.advert_router + struct.pack("!LHH", self.ls_seq, self.csum, 20 + len(data)) + data
        else:
            ret = struct.pack("!HBB", self.ls_age, self.options, self.ls_type) + self.ls_id + self.advert_router + struct.pack("!LHH", self.ls_seq, 0, 20 + len(data)) + data
            return ret[:16] + ospf_lsa_checksum(ret) + ret[18:]

    def parse(self, data):
        (self.ls_age, self.options, self.ls_type) = struct.unpack("!HBB", data[:4])
        self.ls_id = data[4:8]
        self.advert_router = data[8:12]
        (self.ls_seq, self.csum, self.len) = struct.unpack("!LHH", data[12:20])
        return data[20:]

class ospf_router_link_advertisement(ospf_link_state_advertisement_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|    0    |V|E|B|        0      |            # links            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                             Link                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                            Link[n]                            |

    FLAG_VIRTUAL_LINK_ENDPOINT = 0x0400
    FLAG_EXTERNAL = 0x0200
    FLAG_BORDER = 0x0100

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, flags=0x0, links=[]):
        self.flags = flags
        self.links = links
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)
    
    def __repr__(self):
        return "%s, FLAGS:%x, LINKS:%s" % (ospf_link_state_advertisement_header.__repr__(self), self.flags, self.links)

    def render(self):
        ret = ""
        for i in self.links:
            ret += i.render()
        return ospf_link_state_advertisement_header.render(self, struct.pack("!HH", self.flags, len(self.links)) + ret)

    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        (self.flags, num_links) = struct.unpack("!HH", adv[:4])
        left = adv[4:]
        self.links = []
        for i in xrange(num_links):
            link = ospf_router_link_advertisement_link()
            left = link.parse(left)
            self.links.append(link)
        return left

class ospf_router_link_advertisement_link(object):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Link ID                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Link Data                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     Type      |     # TOS     |        TOS 0 metric           |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|      TOS      |        0      |            metric             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     TOS[n]    |        0      |            metric             |

    TYPE_POINT_TO_POINT = 1
    TYPE_TRANSIT_NET = 2
    TYPE_STUB_NET = 3
    TYPE_VIRTUAL = 4

    TYPES = {   1 : "TYPE_POINT_TO_POINT",
                2 : "TYPE_TRANSIT_NET",
                3 : "TYPE_STUB_NET",
                4 : "TYPE_VIRTUAL"
                }

    LINK_ID_NEIGH_ID = 1
    LINK_ID_DESEG_ADDR = 2
    LINK_ID_NET_NUMBER = 3
    LINK_ID_NEIGH_ID2 = 4
    
    IDS = {     1 : "LINK_ID_NEIGH_ID",
                2 : "LINK_ID_DESEG_ADDR",
                3 : "LINK_ID_NET_NUMBER",
                4 : "LINK_ID_NEIGH_ID2"
                }

    def __init__(self, id=None, data=None, type=None, tos_0=None, tos_n=[]):
        self.id = id
        self.data = data
        self.type = type
        self.tos_0 = tos_0
        self.tos_n = tos_n

    def __repr__(self):
        return "ID:%s, DATA:%s, TYPE:%s, TOS0:%d" % (dnet.ip_ntoa(self.id), dnet.ip_ntoa(self.data), self.TYPES[self.type], self.tos_0)

    def render(self):
        ret = self.id + self.data + struct.pack("!BBH", self.type, len(self.tos_n), self.tos_0)
        for i in self.tos_n:
            ret += i.render()
        return ret

    def parse(self, data):
        self.id = data[:4]
        self.data = data[4:8]
        (self.type, len, self.tos_0) = struct.unpack("!BBH", data[8:12])
        left = data[12:]
        for i in xrange(len):
            tos = ospf_router_link_advertisement_tos()
            left = tos.parse(left)
            self.tos_n.append(tos)
        return left

class ospf_router_link_advertisement_tos(object):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|      TOS      |        0      |            metric             |

    def __init__(self, tos=None, metric=None):
        self.tos = tos
        self.metric = metric

    def render(self):
        return struct.pack("!BxH", self.tos, self.metric)

    def parse(self, data):
        (self.tos, self.metric) = struct.unpack("!BxH", data[:4])


class ospf_network_link_advertisement(ospf_link_state_advertisement_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Network Mask                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                        Attached Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, net_mask=None, router=[]):
        self.net_mask = net_mask
        self.router = router
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        #ret = struct.pack("!L", self.net_mask)
        ret = self.net_mask
        for i in self.router:
            #ret += struct.pack("!L", i)
            ret += i
        return ospf_link_state_advertisement_header.render(self, ret)
        
    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        #(self.net_mask) = struct.unpack("!L", adv[:4])
        self.net_mask = adv[:4]
        self.router = []
        for i in xrange(4, len(adv), 4):
            #router = struct.unpack("!L", adv[i:i+4])
            #self.router.append(router)
            self.router.append(adv[i:i+4])

class ospf_summary_link_advertisement(ospf_link_state_advertisement_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Network Mask                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     TOS       |                  metric                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, net_mask=None, tos=[]):
        self.tos = tos
        self.metric = metric
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!L", self.net_mask)
        for i in self.tos:
            ret += i.render()
        return ospf_link_state_advertisement_header.render(self, ret)

    def parse(self, data):
        (self.net_mask) = struct.unpack("!L", data[:4])
        self.tos = []
        for i in xrange(4, len(data), 4):
            tos = ospf_summary_link_advertisement_tos()
            tos.parse(data[i,i+4])
            self.tos.append(tos)

class ospf_summary_link_advertisement_tos(object):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     TOS       |                  metric                       |

    def __init__(self, tos=None, metric=None):
        self.tos = tos
        self.metric = metric

    def render(self):
        return struct.pack("!B3s", self.tos, self.metric)

    def parse(self, data):
        (self.tos, self.metric) = struct.unpack("!B3s", data)

class ospf_as_external_link_advertisement(ospf_link_state_advertisement_header):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Network Mask                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|E|    TOS      |                  metric                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      Forwarding address                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      External Route Tag                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, net_mask=None, tos=None, metric=None, forward_addr=None, external_route=None):
        self.net_mask = net_mask
        self.tos = tos
        self.metric = metric
        self.forward_addr = forward_addr
        self.external_route = external_route
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!LB3sL", self.net_mask, self.tos, self.metric, self.forward_addr)
        ret += self.external_route
        return ret

    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        (self.net_mask, self.tos, self.metric, self.forward_addr) = struct.unpack("!LB3sL", adv[:12])
        self.external_route = adv[12:]
        
### OSPF_THREAD_CLASS ###

class ospf_thread(threading.Thread):
    STATE_HELLO = 1
    STATE_2WAY = 2
    STATE_EXSTART = 3
    STATE_EXCHANGE = 4
    STATE_LOADING = 5
    STATE_FULL = 6

    GLOBAL_STATE_INIT = 1
    GLOBAL_STATE_DONE = 2
    
    def __init__(self, parent):
        self.parent = parent
        self.running = True
        self.hello = False
        self.hello_count = 0
        self.state = self.GLOBAL_STATE_INIT
        threading.Thread.__init__(self)

    def send_multicast(self, data):
        ip_hdr = dpkt.ip.IP(    ttl=1,
                                p=dpkt.ip.IP_PROTO_OSPF,
                                src=self.parent.ip,
                                dst=dnet.ip_aton("224.0.0.5"),
                                data=data
                                )
        ip_hdr.len += len(ip_hdr.data)
        eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton("01:00:5e:00:00:05"),
                                            src=self.parent.mac,
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=str(ip_hdr)
                                            )
        self.parent.dnet.send(str(eth_hdr))

    def send_unicast(self, mac, ip, data):
        ip_hdr = dpkt.ip.IP(    ttl=1,
                                p=dpkt.ip.IP_PROTO_OSPF,
                                src=self.parent.ip,
                                dst=ip,
                                data=data
                                )
        ip_hdr.len += len(ip_hdr.data)
        eth_hdr = dpkt.ethernet.Ethernet(   dst=mac,
                                            src=self.parent.mac,
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=str(ip_hdr)
                                            )
        self.parent.dnet.send(str(eth_hdr))


#~ +---+                                         +---+
#~ |RT1|                                         |RT2|
#~ +---+                                         +---+
#~ 
#~ Down                                          Down
                #~ Hello(DR=0,seen=0)
           #~ ------------------------------>
             #~ Hello (DR=RT2,seen=RT1,...)      Init
           #~ <------------------------------
#~ ExStart        D-D (Seq=x,I,M,Master)
           #~ ------------------------------>
               #~ D-D (Seq=y,I,M,Master)         ExStart
           #~ <------------------------------
#~ Exchange       D-D (Seq=y,M,Slave)
           #~ ------------------------------>
               #~ D-D (Seq=y+1,M,Master)         Exchange
           #~ <------------------------------
               #~ D-D (Seq=y+1,M,Slave)
           #~ ------------------------------>
                         #~ ...
                         #~ ...
                         #~ ...
               #~ D-D (Seq=y+n, Master)
           #~ <------------------------------
               #~ D-D (Seq=y+n, Slave)
 #~ Loading   ------------------------------>
                     #~ LS Request                Full
           #~ ------------------------------>
                     #~ LS Update
           #~ <------------------------------
                     #~ LS Request
           #~ ------------------------------>
                     #~ LS Update
           #~ <------------------------------
 #~ Full        

    def run(self):
        while(self.running):
            if self.parent.dnet:
                if self.hello and len(self.parent.neighbors) > 0:
                    #Build neighbor list
                    neighbors = []
                    for id in self.parent.neighbors:
                        neighbors.append(dnet.ip_aton(id))

                    if self.state == self.GLOBAL_STATE_INIT:
                        packet = ospf_hello(    self.parent.area,
                                                self.parent.auth_type,
                                                self.parent.auth_data,
                                                self.parent.ip,
                                                self.parent.mask,
                                                self.parent.delay,
                                                ospf_hello.OPTION_TOS_CAPABILITY | (self.parent.options & ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY),
                                                1,
                                                self.parent.delay * 4,
                                                0,
                                                0,
                                                []
                                                )
                        self.state = self.GLOBAL_STATE_DONE
                        self.send_multicast(packet.render())

                    if self.hello_count >= self.parent.delay - 1:
                        self.hello_count = 0
                        #Multicast hello
                        packet = ospf_hello(    self.parent.area,
                                                self.parent.auth_type,
                                                self.parent.auth_data,
                                                self.parent.ip,
                                                self.parent.mask,
                                                self.parent.delay,
                                                ospf_hello.OPTION_TOS_CAPABILITY | (self.parent.options & ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY),
                                                1,
                                                self.parent.delay * 4,
                                                self.parent.dr,
                                                self.parent.bdr,
                                                neighbors
                                                )
                        self.send_multicast(packet.render())
                    else:
                        self.hello_count += 1
                   
                    for id in self.parent.neighbors:
                        (iter, mac, ip, dbd, lsa, state, master, seq, last_packet, adverts) = self.parent.neighbors[id]

                        if state == self.STATE_HELLO:
                            #Unicast hello
                            packet = ospf_hello(    self.parent.area,
                                                    self.parent.auth_type,
                                                    self.parent.auth_data,
                                                    self.parent.ip,
                                                    self.parent.mask,
                                                    self.parent.delay,
                                                    ospf_hello.OPTION_TOS_CAPABILITY | (self.parent.options & ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY),
                                                    1,
                                                    self.parent.delay * 4,
                                                    self.parent.dr,
                                                    self.parent.bdr,
                                                    neighbors
                                                    )
                            self.send_unicast(mac, ip, packet.render())                        
                        elif state == self.STATE_2WAY:
                            if dbd:
                                if master:
                                    packet = ospf_database_description( self.parent.area,
                                                                        self.parent.auth_type,
                                                                        self.parent.auth_data,
                                                                        self.parent.ip,
                                                                        self.parent.mtu,
                                                                        self.parent.options & ~ospf_hello.OPTION_CONTAINS_LSS | ospf_hello.OPTION_ZERO_BIT,
                                                                        ospf_database_description.FLAGS_MORE | ospf_database_description.FLAGS_MASTER_SLAVE | ospf_database_description.FLAGS_INIT,
                                                                        seq
                                                                        )
                                    self.send_unicast(mac, ip, packet.render(""))
                                    self.parent.neighbors[id] = (iter, mac, ip, dbd, lsa, state, master, seq + 1, last_packet, adverts)
                                else:
                                    #Learned DBD
                                    packet = ospf_database_description( self.parent.area,
                                                                        self.parent.auth_type,
                                                                        self.parent.auth_data,
                                                                        self.parent.ip,
                                                                        dbd.mtu,
                                                                        dbd.options & ~ospf_hello.OPTION_CONTAINS_LSS,
                                                                        dbd.flags & ~ospf_database_description.FLAGS_MASTER_SLAVE & ~ospf_database_description.FLAGS_INIT,
                                                                        dbd.sequence_number
                                                                        )
                                    self.send_unicast(mac, ip, packet.render(""))
                        #Exchange LSA State
                        elif state == self.STATE_EXSTART:
                            if master:
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    ospf_database_description.FLAGS_MASTER_SLAVE,
                                                                    seq
                                                                    )
                                self.parent.neighbors[id] = (iter, mac, ip, dbd, lsa, state, master, seq + 1, last_packet, adverts)
                            else:
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    ospf_database_description.FLAGS_MORE,
                                                                    dbd.sequence_number
                                                                    )
                            lsa = ospf_link_state_advertisement_header( 92,
                                                                        ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY,
                                                                        ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS,
                                                                        self.parent.ip,
                                                                        self.parent.ip,
                                                                        10
                                                                        )
                            l_data = lsa.render("")
                            data = packet.render(l_data)
                            self.send_unicast(mac, ip, data)
                        elif state == self.STATE_EXCHANGE:
                            if master:
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    ospf_database_description.FLAGS_MASTER_SLAVE,
                                                                    seq
                                                                    )
                                self.send_unicast(mac, ip, packet.render(""))
                                self.parent.neighbors[id] = (iter, mac, ip, dbd, lsa, state, master, seq + 1, last_packet, adverts)
                            else:
                                #Ack DBD
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    0,
                                                                    dbd.sequence_number
                                                                    )
                                self.send_unicast(mac, ip, packet.render(""))
                        elif state == self.STATE_LOADING:
                            if master:
                                for lsa in dbd.lsdb:
                                    packet = ospf_link_state_request(   self.parent.area,
                                                                        self.parent.auth_type,
                                                                        self.parent.auth_data,
                                                                        self.parent.ip,
                                                                        lsa.ls_type,
                                                                        lsa.ls_id,
                                                                        [lsa.advert_router]
                                                                        )
                                    data = packet.render()
                                    self.send_unicast(mac, ip, data)
                                    self.parent.neighbors[id] = (iter, mac, ip, dbd, [], state, False, seq, last_packet, adverts)
                            else:
                                #LSUpdate
                                ipy = IPy.IP("%s/%s" % (dnet.ip_ntoa(self.parent.ip), dnet.ip_ntoa(self.parent.mask)), make_net=True)
                                links = [ 
                                            #~ ospf_router_link_advertisement_link(  dnet.ip_aton(str(ipy.net())),
                                                                                #~ dnet.ip_aton(str(ipy.netmask())),
                                                                                #~ ospf_router_link_advertisement_link.TYPE_TRANSIT_NET,
                                                                                #~ 1
                                                                                #~ ),
                                            ospf_router_link_advertisement_link(    struct.pack("!I", self.parent.dr),
                                                                                            self.parent.ip,
                                                                                            ospf_router_link_advertisement_link.TYPE_TRANSIT_NET,
                                                                                            1
                                                                                            ) ]
                                adverts = [ ospf_router_link_advertisement( 92,
                                                                            ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY,
                                                                            ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS,
                                                                            self.parent.ip,
                                                                            self.parent.ip,
                                                                            10,
                                                                            0,
                                                                            links
                                                                            ) ]
                                packet = ospf_link_state_update(    self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    adverts,
                                                                    )
                                self.send_unicast(mac, ip, packet.render())
                        elif state == self.STATE_FULL:
                            if len(lsa):
                                ack = ospf_link_state_acknowledgment(self.parent.area, self.parent.auth_type, self.parent.auth_data, self.parent.ip, lsa)
                                self.send_unicast(mac, ip, ack.render())
                                self.parent.neighbors[id] = (iter, mac, ip, dbd, [], state, master, seq, last_packet, adverts)
                            for i in self.parent.nets:
                                (net, mask, type, active, removed) = self.parent.nets[i]
                                if active:
                                    def router_links(self, net, mask, mac, ip):
                                        links = [   
                                                    ospf_router_link_advertisement_link(    dnet.ip_aton(net),
                                                                                            dnet.ip_aton(mask),
                                                                                            ospf_router_link_advertisement_link.TYPE_STUB_NET,
                                                                                            1
                                                                                            ),
                                                    ospf_router_link_advertisement_link(    struct.pack("!I", self.parent.dr),
                                                                                            self.parent.ip,
                                                                                            ospf_router_link_advertisement_link.TYPE_TRANSIT_NET,
                                                                                            1
                                                                                            ) ]
                                        advert = [ ospf_router_link_advertisement( 92,
                                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_DEMAND_CIRCUITS,
                                                                                    ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS,
                                                                                    self.parent.ip,
                                                                                    self.parent.ip,
                                                                                    random.randint(11, 2^32),
                                                                                    0,
                                                                                    links
                                                                                    ) ]
                                        packet = ospf_link_state_update(    self.parent.area,
                                                                            self.parent.auth_type,
                                                                            self.parent.auth_data,
                                                                            self.parent.ip,
                                                                            advert,
                                                                            )
                                        self.send_unicast(mac, ip, packet.render())
                                        self.parent.log("OSPF: Sending ROUTER_LINKS LSU to %s" % (dnet.ip_ntoa(ip)))

                                    def network_links(self, net, mask, mac, ip):
                                        pass
                                        
                                    {   ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS : router_links,
                                        ospf_link_state_advertisement_header.TYPE_NETWORK_LINKS : network_links
                                        }[type](self, net, mask, mac, ip)
                                    self.parent.nets[i] = (net, mask, type, False, removed)
                                else:
                                    if removed:
                                        #send update to neigh to remove route entry !!!
                                        del self.parent.nets[i]
                                        del self.parent.network_liststore[i]
                        
            if not self.running:
                return
            time.sleep(self.parent.sleep_time)

    def quit(self):
        self.running = False

class ospf_md5bf(threading.Thread):
    def __init__(self, parent, iter, digest, data):
        self.parent = parent
        self.iter = iter
        self.digest = digest
        self.data = data
        self.obj = None
        threading.Thread.__init__(self)

    def run(self):
        if self.parent.platform == "Windows":
            import bf
        else:
            from loki_bindings import bf
        l = self.parent.parent
        self.obj = bf.ospf_md5_bf()
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
            if self.parent.neighbor_liststore.iter_is_valid(self.iter):
                src = self.parent.neighbor_liststore.get_value(self.iter, self.parent.NEIGH_IP_ROW)
                if not self.obj.pw is None:
                    self.parent.neighbor_liststore.set_value(self.iter, self.parent.NEIGH_CRACK_ROW, self.obj.pw)
                    self.parent.log("OSPF: Found password '%s' for host %s" % (self.obj.pw, src))
                else:
                    self.parent.neighbor_liststore.set_value(self.iter, self.parent.NEIGH_CRACK_ROW, "NOT FOUND")
                    self.parent.log("OSPF: No password found for host %s" % (src))
        self.obj = None
        
    def quit(self):
        if not self.obj is None:
            self.obj.stop()
            self.obj = None

### MODULE_CLASS ###

class mod_class(object):
    NEIGH_IP_ROW = 0
    NEIGH_ID_ROW = 1
    NEIGH_AREA_ROW = 2
    NEIGH_STATE_ROW = 3
    NEIGH_AUTH_ROW = 4
    NEIGH_CRACK_ROW = 5
    NEIGH_MASTER_ROW = 6

    NET_NET_ROW = 0
    NET_MASK_ROW = 1
    NET_TYPE_ROW = 2
    
    def __init__(self, parent, platform, ui):
        self.parent = parent
        self.platform = platform
        self.ui = ui
        if self.ui == 'gtk':
            import gobject as gobject_
            import gtk as gtk_
            import gtk.glade as glade_
            global gobject
            global gtk
            gobject = gobject_
            gtk = gtk_
            gtk.glade = glade_
        else:
            import urwid as urwid_
            global urwid
            urwid = urwid_
            self.neigh_tree = { "children" : [] }
            
            class NeighWidget_(urwid.TreeWidget):
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
                        return "%s %s/%s - %s" % (val['type'], val['id'], val['data'], val['link-type'])
                    elif node.get_depth() == 1:
                        return "%s ID(%s) AREA(%s) AUTH(%s) - %s" % (val['src'], val['id'], val['area'], val['auth'], val['state'])
                    else:
                        return "Neighbors:"
                
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
            self.NeighWidget = NeighWidget_

            class NeighNode_(urwid.TreeNode):
                def load_widget(self):
                    return NeighWidget_(self)
            self.NeighNode = NeighNode_

            class NeighParentNode_(urwid.ParentNode):
                def load_widget(self):
                    return NeighWidget_(self)
                
                def load_child_keys(self):
                    val = self.get_value()
                    return range(len(val["children"]))
                
                def load_child_node(self, key):
                    childdata = self.get_value()['children'][key]
                    childdepth = self.get_depth() + 1
                    if 'children' in childdata and len(childdata['children']) > 0:
                        childclass = NeighParentNode_
                    else:
                        childclass = NeighNode_
                    return childclass(childdata, parent=self, key=key, depth=childdepth)
            self.NeighParentNode = NeighParentNode_
        self.name = "ospf"
        self.group = "ROUTING"
        self.gladefile = "/modules/module_ospf.glade"
        if self.ui == 'gtk':
            self.neighbor_liststore = gtk.TreeStore(str, str, str, str, str, str, bool)
            self.network_liststore = gtk.ListStore(str, str, str)
            self.auth_type_liststore = gtk.ListStore(str, int)
            self.net_type_liststore = gtk.ListStore(str, int)
            h = ospf_header()
            for i in dir(ospf_header):
                if i.startswith("AUTH_"):
                    val = getattr(h, i)
                    self.auth_type_liststore.append([i, val])
            #~ for i in dir(ospf_link_state_advertisement_header):
            h = ospf_link_state_advertisement_header()
            for i in [ "TYPE_ROUTER_LINKS" ]:       #, "TYPE_NETWORK_LINKS"
                if i.startswith("TYPE_"):
                    val = getattr(h, i)
                    self.net_type_liststore.append([i, val])
        self.dnet = None
        self.filter = False
        self.thread = None
        self.bf = None
        self.mtu = 1500
        self.delay = 10
        self.sleep_time = 1

    def start_mod(self):
        self.thread = ospf_thread(self)
        self.area = 0
        self.auth_type = ospf_header.AUTH_CRYPT
        self.auth_data = 0
        self.neighbors = {}
        self.nets = {}
        self.lsdb = {}
        self.dr = ""
        self.bdr = ""
        self.options = ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY
        self.bf = {}
        self.thread.start()
        if self.ui == 'urw':
            self.neigh_tree["children"] = []

    def shut_mod(self):
        if self.thread:
            self.thread.quit()
        if self.filter:
            self.log("OSPF: Removing lokal packet filter for OSPF")
            if self.platform == "Linux":
                os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
            elif self.platform == "Darwin":
                os.system("ipfw -q delete 31334")
            elif self.platform == "Windows":
                os.system("netsh advfirewall firewall del rule name=ospf")
            else:
                self.fw.delete(self.ospf_filter)
            self.filter = False
        if self.bf:
            for i in self.bf:
                self.bf[i].quit()
        if self.ui == 'gtk':
            self.neighbor_liststore.clear()
            self.network_liststore.clear()
            #self.auth_type_liststore.clear()
        
    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_hello_togglebutton_toggled"     : self.on_hello_togglebutton_toggled,
                "on_bf_button_clicked"              : self.on_bf_button_clicked,
                "on_auth_type_combobox_changed"     : self.on_auth_type_combobox_changed,
                "on_add_button_clicked"             : self.on_add_button_clicked,
                "on_remove_button_clicked"          : self.on_remove_button_clicked,
                "on_show_topology_button_clicked"   : self.on_show_topology_button_clicked,
                "on_save_topology_button_clicked"   : self.on_save_topology_button_clicked,
                }
        self.glade_xml.signal_autoconnect(dic)

        self.neighbor_treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.neighbor_treeview.set_model(self.neighbor_liststore)
        self.neighbor_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_IP_ROW)
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
        column.set_title("STATE")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_STATE_ROW)
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
        column = gtk.TreeViewColumn()
        column.set_title("MASTER")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.connect('toggled', self.master_toggle_callback, self.neighbor_liststore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, "active", self.NEIGH_MASTER_ROW)
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
        column = gtk.TreeViewColumn()
        column.set_title("Type")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.network_treeview.append_column(column)

        self.hello_tooglebutton = self.glade_xml.get_widget("hello_tooglebutton")
        self.area_entry = self.glade_xml.get_widget("area_entry")
        self.auth_data_entry = self.glade_xml.get_widget("auth_data_entry")
        self.id_spinbutton = self.glade_xml.get_widget("id_spinbutton")
        self.auth_type_combobox = self.glade_xml.get_widget("auth_type_combobox")
        self.auth_type_combobox.set_model(self.auth_type_liststore)
        self.auth_type_combobox.set_active(0)

        self.network_entry = self.glade_xml.get_widget("network_entry")
        self.netmask_entry = self.glade_xml.get_widget("netmask_entry")
        self.net_type_combobox = self.glade_xml.get_widget("net_type_combobox")
        self.net_type_combobox.set_model(self.net_type_liststore)
        self.net_type_combobox.set_active(0)

        return self.glade_xml.get_widget("root")
    
    def get_urw(self):
        spoofs = urwid.LineBox(urwid.TreeListBox(urwid.TreeWalker(self.NeighParentNode(self.neigh_tree))))
        self.area_edit = urwid.Edit("Area: ")
        hello = self.parent.menu_button("Start Sending HELLOs", self.urw_hello_activated)
        bgroup = []
        authlist = []
        h = ospf_header()
        for i in dir(ospf_header):
            if i.startswith("AUTH_"):
                val = getattr(h, i)
                authlist.append(urwid.RadioButton(bgroup, i, on_state_change=self.urw_radio_changed, user_data=val))
        self.auth_data_edit = urwid.Edit("Auth Data: ")
        self.auth_id_edit = urwid.Edit("Key ID: ")
        authlist.append(self.auth_data_edit)
        authlist.append(self.auth_id_edit)
        columns = urwid.Columns([urwid.Filler(self.area_edit), urwid.ListBox(urwid.SimpleListWalker(authlist)), urwid.Filler(hello)])
        self.pile = urwid.Pile([spoofs, columns])
        return self.pile
    
    def urw_radio_changed(self, button, state, auth):
        if state:
            self.auth_type = auth
    
    def urw_update_tree(self):
        self.pile.contents[0] = (urwid.LineBox(urwid.TreeListBox(urwid.TreeWalker(self.NeighParentNode(self.neigh_tree)))), ('weight', 1))

    def urw_hello_activated(self, button):
        if not self.filter:
            self.log("OSPF: Setting lokal packet filter for OSPF")
            if self.platform == "Linux":
                os.system("iptables -A INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
            elif self.platform == "Darwin":
                os.system("ipfw -q add 31334 deny ospf from any to any")
            elif self.platform == "Windows":
                os.system("netsh advfirewall firewall add rule name=ospf dir=in protocol=%i action=block" % dpkt.ip.IP_PROTO_OSPF)
            else:
                self.fw.add(self.ospf_filter)
            self.filter = True
        self.log("OSPF: Hello thread activated")
        self.area = int(self.area_edit.get_edit_text())
        if self.auth_type == ospf_header.AUTH_NONE:
            self.auth_data = 0
        elif self.auth_type == ospf_header.AUTH_SIMPLE:
            self.auth_data = self.auth_data_edit.get_edit_text()[:8]
        elif self.auth_type == ospf_header.AUTH_CRYPT:
            key = self.auth_data_edit.get_edit_text()
            if len(key) > 16:
                key = key[:16]
            elif len(key) < 16:
                key = "%s%s" % (key, "\0" * (16 - len(key)))
            self.auth_data = ospf_crypt_auth_data(  key,
                                                    int(self.auth_id_edit.get_edit_text()),
                                                    ospf_crypt_auth_data.TYPE_MD5,
                                                    int(time.time())
                                                    )
        self.thread.hello = True
        button.set_label("Stop Sending HELLOs")
        urwid.disconnect_signal(button, 'click', self.urw_hello_activated)
        urwid.connect_signal(button, 'click', self.urw_hello_deactivated)

    def urw_hello_deactivated(self, button):
        if self.filter:
            self.log("OSPF: Removing lokal packet filter for OSPF")
            if self.platform == "Linux":
                os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
            elif self.platform == "Darwin":
                os.system("ipfw -q delete 31334")
            elif self.platform == "Windows":
                os.system("netsh advfirewall firewall del rule name=ospf")
            else:
                self.fw.delete(self.ospf_filter)
            self.filter = False
        self.log("OSPF: Hello thread deactivated")
        for id in self.neighbors:
            (iter, mac, src, org_dbd, lsa, state, master, seq, last_packet, adverts) = self.neighbors[id]
            self.neigh_tree['children'][iter]['state'] = "HELLO"
            self.neighbors[id] = (iter, mac, src, None, [], ospf_thread.STATE_HELLO, master, 1337, last_packet, adverts)
        self.urw_update_tree()
        self.thread.hello = False
        button.set_label("Start Sending HELLOs")
        urwid.disconnect_signal(button, 'click', self.urw_hello_deactivated)
        urwid.connect_signal(button, 'click', self.urw_hello_activated)

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)
        self.mask = dnet.ip_aton(mask)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    def set_fw(self, fw):
        self.fw = fw

    def set_int(self, interface):
        self.interface = interface
        self.ospf_filter = {    "device"    : self.interface,
                                "op"        : dnet.FW_OP_BLOCK,
                                "dir"       : dnet.FW_DIR_IN,
                                "proto"     : dpkt.ip.IP_PROTO_OSPF,
                                "src"       : dnet.addr("0.0.0.0/0", dnet.ADDR_TYPE_IP),
                                "dst"       : dnet.addr("0.0.0.0/0", dnet.ADDR_TYPE_IP),
                                "sport"     : [0, 0],
                                "dport"     : [0, 0]
                                }

    def get_ip_checks(self):
        return (self.check_ip, self.input_ip)

    def check_ip(self, ip):
        if ip.p == dpkt.ip.IP_PROTO_OSPF:
            return (True, False)
        return (False, False)

    def input_ip(self, eth, ip, timestamp):
        if ip.src != self.ip:
            #Multicast packet
            if ip.dst == dnet.ip_aton("224.0.0.5"):
                header = ospf_header()
                data = str(ip.data)
                header.parse(data[:24])
                id = dnet.ip_ntoa(header.id)
                if header.type == ospf_header.TYPE_HELLO:
                    hello = ospf_hello()
                    hello.parse(data)
                    (ip_int,) = struct.unpack("!I", self.ip)
                    if id not in self.neighbors:
                        #self.log("OSPF-DEBUG: %d < %d ?" % (hello.id, ip_int))
                        #if socket.ntohl(hello.id) < socket.ntohl(ip_int):
                        if hello.id < ip_int:
                            master = True
                            #self.log("OSPF-DEBUG: Yes")
                        else:
                            master = False
                            #self.log("OSPF-DEBUG: No")
                        #print "Local %s (%i) - Peer %s (%i) => Master " % (dnet.ip_ntoa(self.ip), socket.ntohl(ip_int), id, socket.ntohl(header.id)) + str(master)
                        if self.ui == 'gtk':
                            iter = self.neighbor_liststore.append(None, [dnet.ip_ntoa(ip.src), id, str(header.area), "HELLO", header.auth_to_string(), "", master])
                        elif self.ui == 'urw':
                            entry = { 'src'   : dnet.ip_ntoa(ip.src),
                                      'id'    : id,
                                      'area'  : str(header.area),
                                      'state' : "HELLO",
                                      'auth'  : header.auth_to_string(),
                                      'master': master,
                                      'children':[]
                                    }
                            self.neigh_tree['children'].append(entry)
                            iter = self.neigh_tree['children'].index(entry)
                            self.urw_update_tree()
                        #                    (iter, mac,     src,    dbd, lsa, state,                   master, seq,  last_packet, adverts)
                        self.neighbors[id] = (iter, eth.src, ip.src, None, [], ospf_thread.STATE_HELLO, master, 1337, ip.data, {})
                        self.log("OSPF: Got new peer %s" % (dnet.ip_ntoa(ip.src)))
                    elif self.thread.hello:
                        (iter, mac, src, dbd, lsa, state, master, seq, last_packet, adverts) = self.neighbors[id]
                        if state == ospf_thread.STATE_HELLO:
                            self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_2WAY, master, seq, ip.data, adverts)
                            if self.ui == 'gtk':
                                self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "2WAY")
                            elif self.ui == 'urw':
                                self.neigh_tree['children'][iter]['state'] = "2WAY"
                                self.urw_update_tree()
                    self.dr = hello.designated_router
                    self.bdr = hello.backup_designated_router
                    self.options = hello.options
                elif header.type == ospf_header.TYPE_LINK_STATE_UPDATE:
                    if id in self.neighbors:
                        (iter, mac, src, org_dbd, update, state, master, seq, ip.data, adverts) = self.neighbors[id]
                        #~ if state > ospf_thread.STATE_EXSTART:
                            #~ if state < ospf_thread.STATE_LOADING:
                                #~ pass
                        update = ospf_link_state_update()
                        update.parse(data)
                            
                        ### ADD LSA'S TO NEIGH-STORE ###
                        for lsa in update.advertisements:
                            adv_router = dnet.ip_ntoa(lsa.advert_router)
                            if adv_router not in self.lsdb:
                                self.lsdb[adv_router] = {}
                            if lsa.ls_type not in self.lsdb[adv_router]:
                                self.lsdb[adv_router][lsa.ls_type] = {}
                            ls_id = dnet.ip_ntoa(lsa.ls_id)
                            if ls_id not in self.lsdb[adv_router][lsa.ls_type]:
                                self.lsdb[adv_router][lsa.ls_type][ls_id] = { 'seq' :   None}
                            if lsa.ls_type == ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS:
                                for link in lsa.links:
                                    link_id = dnet.ip_ntoa(link.id)
                                    if link_id not in adverts:
                                        if self.ui == 'gtk':
                                            iter2 = self.neighbor_liststore.append(iter, ["TYPE_ROUTER_LINKS", link_id, dnet.ip_ntoa(link.data), ospf_router_link_advertisement_link.TYPES[link.type], "", "", None])
                                        elif self.ui == 'urw':
                                            entry = { 'type'     : "TYPE_ROUTER_LINKS",
                                                      'id'       : link_id,
                                                      'data'     : dnet.ip_ntoa(link.data),
                                                      'link-type': ospf_router_link_advertisement_link.TYPES[link.type]
                                                    }
                                            self.neigh_tree['children'][iter]['children'].append(entry)
                                            iter2 = self.neigh_tree['children'][iter]['children'].index(entry)
                                            self.urw_update_tree()
                                        adverts[link_id] = (iter2, link)
                                    else:
                                        (iter2, old_link) = adverts[link_id]
                                        if self.ui == 'gtk':
                                            self.neighbor_liststore.set(iter2, self.NEIGH_AREA_ROW, dnet.ip_ntoa(link.data), self.NEIGH_STATE_ROW, ospf_router_link_advertisement_link.TYPES[link.type])
                                        elif self.ui == 'urw':
                                            entry = { 'type'     : "TYPE_ROUTER_LINKS",
                                                      'id'       : link_id,
                                                      'data'     : dnet.ip_ntoa(link.data),
                                                      'link-type': ospf_router_link_advertisement_link.TYPES[link.type]
                                                    }
                                            self.neigh_tree['children'][iter]['children'][iter2] = entry
                                            self.urw_update_tree()
                                        adverts[link_id] = (iter2, link)
                                    
                            if self.lsdb[adv_router][lsa.ls_type][ls_id]['seq'] is None or \
                               self.lsdb[adv_router][lsa.ls_type][ls_id]['seq'] < lsa.ls_seq:
                                if self.lsdb[adv_router][lsa.ls_type][ls_id]['seq'] < lsa.ls_seq:
                                    self.log("OSPF: updating lsp %s:%d" % (adv_router, lsa.ls_type))
                                self.lsdb[adv_router][lsa.ls_type][ls_id] = {   'seq'   :   lsa.ls_seq,
                                                                                'data'  :   {} }
                                if lsa.ls_type == ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS:
                                    for link in lsa.links:
                                        link_id = dnet.ip_ntoa(link.id)
                                        self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][link_id] = {
                                                'type'  :   link.type,
                                                'data'  :   dnet.ip_ntoa(link.data),
                                                'metric':   link.tos_0
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_NETWORK_LINKS:
                                    rlist = [ dnet.ip_ntoa(i) for i in lsa.router ]
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] ={
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask),
                                                'router':   set(rlist)
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_IP:
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] = {
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask)
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_ASBR:
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] = {
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask)
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_AS_EXTERNAL:
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] = {
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask),
                                                'fwd'   :   dnet.ip_ntoa(lsa.forward_addr)
                                            }
                            self.neighbors[id] = (iter, mac, src, org_dbd, update.advertisements, state, master, seq, ip.data, adverts)
            #Unicast packet
            elif ip.dst == self.ip and self.thread.hello:
                header = ospf_header()
                data = str(ip.data)
                header.parse(data[:24])
                id = dnet.ip_ntoa(header.id)
                if id in self.neighbors:
                    (iter, mac, src, org_dbd, lsa, state, master, seq, last_packet, adverts) = self.neighbors[id]
                    if header.type == ospf_header.TYPE_HELLO:
                        hello = ospf_hello()
                        hello.parse(data)
                        if state == ospf_thread.STATE_HELLO:
                            self.neighbors[id] = (iter, eth.src, ip.src, org_dbd, lsa, ospf_thread.STATE_2WAY, master, seq, ip.data, adverts)
                            if self.ui == 'gtk':
                                self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "2WAY")
                            elif self.ui == 'urw':
                                self.neigh_tree['children'][iter]['state'] = "2WAY"
                                self.urw_update_tree()
                    elif header.type == ospf_header.TYPE_DATABESE_DESCRIPTION:
                        dbd = ospf_database_description()
                        dbd.parse(data)
                        if state == ospf_thread.STATE_2WAY:
                            if not dbd.flags & ospf_database_description.FLAGS_INIT:
                                if master:
                                    #parse lsa header and store for master role in loading state
                                    dbd.parse(data, parse_lsa=True)
                                    if dbd.lsdb != []:
                                        self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_EXSTART, master, seq, ip.data, adverts)
                                        if self.ui == 'gtk':
                                            self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "EXSTART")
                                        elif self.ui == 'urw':
                                            self.neigh_tree['children'][iter]['state'] = "EXSTART"
                                            self.urw_update_tree()
                                else:
                                    self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_EXSTART, master, seq, ip.data, adverts)
                                    if self.ui == 'gtk':
                                        self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "EXSTART")
                                    elif self.ui == 'urw':
                                        self.neigh_tree['children'][iter]['state'] = "EXSTART"
                                        self.urw_update_tree()
                            else:
                                self.neighbors[id] = (iter, mac, src, dbd, lsa, state, master, seq, ip.data, adverts)
                        elif state == ospf_thread.STATE_EXSTART:
                            if not dbd.flags & ospf_database_description.FLAGS_MORE and not master:
                                self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_EXCHANGE, master, seq, ip.data, adverts)
                                if self.ui == 'gtk':
                                    self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "EXCHANGE")
                                elif self.ui == 'urw':
                                    self.neigh_tree['children'][iter]['state'] = "EXCHANGE"
                                    self.urw_update_tree()
                            elif not dbd.flags and master:
                                self.neighbors[id] = (iter, mac, src, org_dbd, lsa, ospf_thread.STATE_LOADING, master, seq, ip.data, adverts)
                                if self.ui == 'gtk':
                                    self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "LOADING")
                                elif self.ui == 'urw':
                                    self.neigh_tree['children'][iter]['state'] = "LOADING"
                                    self.urw_update_tree()
                    elif header.type == ospf_header.TYPE_LINK_STATE_REQUEST:
                        if state == ospf_thread.STATE_EXCHANGE:
                            self.neighbors[id] = (iter, mac, src, org_dbd, lsa, ospf_thread.STATE_LOADING, master, seq, ip.data, adverts)
                            if self.ui == 'gtk':
                                self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "LOADING")
                            elif self.ui == 'urw':
                                self.neigh_tree['children'][iter]['state'] = "LOADING"
                                self.urw_update_tree()
                    elif header.type == ospf_header.TYPE_LINK_STATE_ACK:
                        if state == ospf_thread.STATE_LOADING:
                            self.neighbors[id] = (iter, mac, src, org_dbd, lsa, ospf_thread.STATE_FULL, master, seq, ip.data, adverts)
                            if self.ui == 'gtk':
                                self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "FULL")
                            elif self.ui == 'urw':
                                self.neigh_tree['children'][iter]['state'] = "FULL"
                                self.urw_update_tree()
                            self.log("OSPF: Peer %s in state FULL" % (dnet.ip_ntoa(ip.src)))
                    elif header.type == ospf_header.TYPE_LINK_STATE_UPDATE:
                        if state > ospf_thread.STATE_EXSTART:
                            if state < ospf_thread.STATE_LOADING:
                                state = ospf_thread.STATE_FULL
                                if self.ui == 'gtk':
                                    self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "FULL")
                                elif self.ui == 'urw':
                                    self.neigh_tree['children'][iter]['state'] = "FULL"
                                    self.urw_update_tree()
                                self.log("OSPF: Peer %s in state FULL" % (dnet.ip_ntoa(ip.src)))
                        update = ospf_link_state_update()
                        update.parse(data)
                            
                        ### ADD LSA'S TO NEIGH-STORE ###
                        for lsa in update.advertisements:
                            adv_router = dnet.ip_ntoa(lsa.advert_router)
                            if adv_router not in self.lsdb:
                                self.lsdb[adv_router] = {}
                            if lsa.ls_type not in self.lsdb[adv_router]:
                                self.lsdb[adv_router][lsa.ls_type] = {}
                            ls_id = dnet.ip_ntoa(lsa.ls_id)
                            if ls_id not in self.lsdb[adv_router][lsa.ls_type]:
                                self.lsdb[adv_router][lsa.ls_type][ls_id] = { 'seq' :   None}
                            if lsa.ls_type == ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS:
                                for link in lsa.links:
                                    link_id = dnet.ip_ntoa(link.id)
                                    if link_id not in adverts:
                                        if self.ui == 'gtk':
                                            iter2 = self.neighbor_liststore.append(iter, ["TYPE_ROUTER_LINKS", link_id, dnet.ip_ntoa(link.data), ospf_router_link_advertisement_link.TYPES[link.type], "", "", None])
                                        elif self.ui == 'urw':
                                            entry = { 'type'     : "TYPE_ROUTER_LINKS",
                                                      'id'       : link_id,
                                                      'data'     : dnet.ip_ntoa(link.data),
                                                      'link-type': ospf_router_link_advertisement_link.TYPES[link.type]
                                                    }
                                            self.neigh_tree['children'][iter]['children'].append(entry)
                                            iter2 = self.neigh_tree['children'][iter]['children'].index(entry)
                                            self.urw_update_tree()
                                        adverts[link_id] = (iter2, link)
                                    else:
                                        (iter2, old_link) = adverts[link_id]
                                        if self.ui == 'gtk':
                                            self.neighbor_liststore.set(iter2, self.NEIGH_AREA_ROW, dnet.ip_ntoa(link.data), self.NEIGH_STATE_ROW, ospf_router_link_advertisement_link.TYPES[link.type])
                                        elif self.ui == 'urw':
                                            entry = { 'type'     : "TYPE_ROUTER_LINKS",
                                                      'id'       : link_id,
                                                      'data'     : dnet.ip_ntoa(link.data),
                                                      'link-type': ospf_router_link_advertisement_link.TYPES[link.type]
                                                    }
                                            self.neigh_tree['children'][iter]['children'][iter2] = entry
                                            self.urw_update_tree()
                                        adverts[link_id] = (iter2, link)
                                    
                            if self.lsdb[adv_router][lsa.ls_type][ls_id]['seq'] is None or \
                               self.lsdb[adv_router][lsa.ls_type][ls_id]['seq'] < lsa.ls_seq:
                                if self.lsdb[adv_router][lsa.ls_type][ls_id]['seq'] < lsa.ls_seq:
                                    self.log("OSPF: updating lsp %s:%d" % (adv_router, lsa.ls_type))
                                self.lsdb[adv_router][lsa.ls_type][ls_id] = {   'seq'   :   lsa.ls_seq,
                                                                                'data'  :   {} }
                                if lsa.ls_type == ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS:
                                    for link in lsa.links:
                                        link_id = dnet.ip_ntoa(link.id)
                                        self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][link_id] = {
                                                'type'  :   link.type,
                                                'data'  :   dnet.ip_ntoa(link.data),
                                                'metric':   link.tos_0
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_NETWORK_LINKS:
                                    rlist = [ dnet.ip_ntoa(i) for i in lsa.router ]
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] ={
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask),
                                                'router':   set(rlist)
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_IP:
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] = {
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask)
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_ASBR:
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] = {
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask)
                                            }
                                elif lsa.ls_type == ospf_link_state_advertisement_header.TYPE_AS_EXTERNAL:
                                    self.lsdb[adv_router][lsa.ls_type][ls_id]['data'][dnet.ip_ntoa(lsa.ls_id)] = {
                                                'mask'  :   dnet.ip_ntoa(lsa.net_mask),
                                                'fwd'   :   dnet.ip_ntoa(lsa.forward_addr)
                                            }
                            self.neighbors[id] = (iter, mac, src, org_dbd, update.advertisements, state, master, seq, ip.data, adverts)

    # SIGNALS #

    def master_toggle_callback(self, cell, path, model):
        model[path][self.NEIGH_MASTER_ROW] = not model[path][self.NEIGH_MASTER_ROW]
        id = model[path][self.NEIGH_ID_ROW]
        (iter, mac, src, dbd, lsa, state, master, seq, last_packet, adverts) = self.neighbors[id]
        self.neighbors[id] = (iter, mac, src, dbd, lsa, state, model[path][self.NEIGH_MASTER_ROW], seq, last_packet, adverts)

    def on_hello_togglebutton_toggled(self, btn):
        if btn.get_active():
            self.area_entry.set_property("sensitive", False)
            self.auth_type_combobox.set_property("sensitive", False)
            self.auth_data_entry.set_property("sensitive", False)
            self.id_spinbutton.set_property("sensitive", False)
            if not self.filter:
                self.log("OSPF: Setting lokal packet filter for OSPF")
                if self.platform == "Linux":
                    os.system("iptables -A INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
                elif self.platform == "Darwin":
                    os.system("ipfw -q add 31334 deny ospf from any to any")
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall add rule name=ospf dir=in protocol=%i action=block" % dpkt.ip.IP_PROTO_OSPF)
                else:
                    self.fw.add(self.ospf_filter)
                self.filter = True
            self.lsdb = {}
            self.log("OSPF: Hello thread activated")
            self.area = int(self.area_entry.get_text())
            if self.auth_type == ospf_header.AUTH_NONE:
                self.auth_data = 0
            elif self.auth_type == ospf_header.AUTH_SIMPLE:
                self.auth_data = self.auth_data_entry.get_text()[:8]
            elif self.auth_type == ospf_header.AUTH_CRYPT:
                key = self.auth_data_entry.get_text()
                if len(key) > 16:
                    key = key[:16]
                elif len(key) < 16:
                    key = "%s%s" % (key, "\0" * (16 - len(key)))
                self.auth_data = ospf_crypt_auth_data(  key,
                                                        self.id_spinbutton.get_value_as_int(),
                                                        ospf_crypt_auth_data.TYPE_MD5,
                                                        int(time.time())
                                                        )
        else:
            self.area_entry.set_property("sensitive", True)
            self.auth_type_combobox.set_property("sensitive", True)
            if self.auth_type == ospf_header.AUTH_NONE:
                self.auth_data_entry.set_property("sensitive", False)
                self.id_spinbutton.set_property("sensitive", False)
            elif self.auth_type == ospf_header.AUTH_SIMPLE:
                self.auth_data_entry.set_property("sensitive", True)
                self.id_spinbutton.set_property("sensitive", False)
            elif self.auth_type == ospf_header.AUTH_CRYPT:
                self.auth_data_entry.set_property("sensitive", True)
                self.id_spinbutton.set_property("sensitive", True)
            if self.filter:
                self.log("OSPF: Removing lokal packet filter for OSPF")
                if self.platform == "Linux":
                    os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
                elif self.platform == "Darwin":
                    os.system("ipfw -q delete 31334")
                elif self.platform == "Windows":
                    os.system("netsh advfirewall firewall del rule name=ospf")
                else:
                    self.fw.delete(self.ospf_filter)
                self.filter = False
            self.log("OSPF: Hello thread deactivated")
            for id in self.neighbors:
                (iter, mac, src, org_dbd, lsa, state, master, seq, last_packet, adverts) = self.neighbors[id]
                self.neighbor_liststore.set_value(iter, self.NEIGH_STATE_ROW, "HELLO")
                self.neighbors[id] = (iter, mac, src, None, [], ospf_thread.STATE_HELLO, master, 1337, last_packet, adverts)
        self.thread.hello = btn.get_active()

    def on_bf_button_clicked(self, btn):
        select = self.neighbor_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            id = model.get_value(iter, self.NEIGH_ID_ROW)
            ident = "%s" % (id)
            if ident in self.bf:
                if self.bf[ident].is_alive():
                    return
            (iter, mac, src, org_dbd, lsa, state, master, seq, last_packet, adverts) = self.neighbors[id]
            type = self.neighbor_liststore.get_value(iter, self.NEIGH_AUTH_ROW)
            if not type == "CRYPT":
                self.log("OSPF: Cant crack %s, doesnt use CRYPT authentication" % ident)
                return
            packet_str = str(last_packet)
            hdr = ospf_header()
            hdr.parse(packet_str)
            digest = packet_str[hdr.len:hdr.len+16]
            data = packet_str[:12] + "\0\0" + packet_str[14:hdr.len]
            thread = ospf_md5bf(self, iter, digest, data)
            model.set_value(iter, self.NEIGH_CRACK_ROW, "RUNNING")
            thread.start()
            self.bf[ident] = thread

    def on_auth_type_combobox_changed(self, cbox):
        if self.auth_type_liststore and len(self.auth_type_liststore):
            self.auth_type = self.auth_type_liststore[self.auth_type_combobox.get_active()][1]
            if self.auth_type == ospf_header.AUTH_NONE:
                self.auth_data_entry.set_property("sensitive", False)
                self.id_spinbutton.set_property("sensitive", False)
            elif self.auth_type == ospf_header.AUTH_SIMPLE:
                self.auth_data_entry.set_property("sensitive", True)
                self.id_spinbutton.set_property("sensitive", False)
            elif self.auth_type == ospf_header.AUTH_CRYPT:
                self.auth_data_entry.set_property("sensitive", True)
                self.id_spinbutton.set_property("sensitive", True)
        
    def on_add_button_clicked(self, btn):
        net = self.network_entry.get_text()
        mask = self.netmask_entry.get_text()
        type_name = self.net_type_liststore[self.net_type_combobox.get_active()][0]
        type = self.net_type_liststore[self.net_type_combobox.get_active()][1]
        iter = self.network_liststore.append([net, mask, type_name])
        self.nets[self.network_liststore.get_string_from_iter(iter)] = (net, mask, type, True, False)
        
    def on_remove_button_clicked(self, btn):
        select = self.network_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            (net, mask, type, active, removed) = self.nets[model.get_string_from_iter(iter)]
            self.nets[model.get_string_from_iter(iter)] = (net, mask, type, False, True)
            self.network_liststore.set_value(iter, self.NET_TYPE_ROW, "REMOVED")
    
    def create_topology(self):
        try:
            import pygraphviz
        except:
            return None
        G = pygraphviz.AGraph(directed=True, overlap=False)
        
        #add router nodes
        for router in self.lsdb:
            G.add_node(router, label="ROUTER:\\n%s" % router, shape="box", fontsize=20, scale=2.0)

        #add network nodes
        for router in self.lsdb:
            if 2 in self.lsdb[router]:
                for lsid in self.lsdb[router][2]:
                    entry = self.lsdb[router][2][lsid]['data']
                    for net_id in entry:
                        net = entry[net_id]
                        ip = IPy.IP(net_id)
                        G.add_node("net_"+net_id, label="NET: %s" % ip.make_net(net['mask']), shape="diamond")
                        for r in net['router']:
                            if r == router:
                                G.add_edge(r, "net_"+net_id, color="green")
                            else:
                                G.add_edge(r, "net_"+net_id)

        #add link nodes
        for router in self.lsdb:
            G.add_node(router, label="ROUTER:\\n%s" % router, shape="box", fontsize=40, scale=2.0)
            for lsid in self.lsdb[router][1]:
                entry = self.lsdb[router][1][lsid]['data']
                for link_id in entry:
                    link = entry[link_id]
                    #~ Link type   Description       Link ID
                    #~ __________________________________________________
                    #~ 1           Point-to-point    Neighbor Router ID
                               #~ link
                    #~ 2           Link to transit   Interface address of
                               #~ network           Designated Router
                    #~ 3           Link to stub      IP network number
                               #~ network
                    #~ 4           Virtual link      Neighbor Router ID

                    if link['type'] == 1:
                        G.add_edge(router, link_id, 
                                    #label="P2P\\n%d" % link['metric'], 
                                    label="%d" % link['metric'], 
                                    weight=link['metric'], taillabel=link['data'])
                    elif link['type'] == 2:
                        G.add_edge(router, "net_"+link_id, 
                                    #label="TRANSIT\\n%d" % link['metric'],
                                    label="%d" % link['metric'],
                                    weight=link['metric'], taillabel=link['data'])
                    elif link['type'] == 3:
                        ip = IPy.IP("%s/%s" % (link_id, link['data']), make_net=True)
                        G.add_node("net_"+link_id, label="NET: %s/%d" % (link_id, ip.prefixlen()), shape="diamond")
                        G.add_edge(router, "net_"+link_id, 
                                    #label="STUB\\n%d" % link['metric'],
                                    label="%d" % link['metric'],
                                    weight=link['metric'],)
                    elif link['type'] == 4:
                        G.add_edge(router, link_id, 
                                    #label="VIRTUAL\\n%d" % link['metric'],
                                    label="%d" % link['metric'],
                                    weight=link['metric'], taillabel=link['data'])
        return G

    def on_show_topology_button_clicked(self, btn):
        try:
            import xdot
        except:
            return
        dwindow = xdot.DotWindow()
        dwindow.base_title = "OSPF Topology"
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
        return {    "delay" : { "value" : self.delay,
                                "type" : "int",
                                "min" : 1,
                                "max" : 100
                                },
                    "mtu" : {   "value" : self.mtu,
                                "type" : "int",
                                "min" : 1,
                                "max" : 10000
                                },
                    "sleep_time" : {    "value" : self.sleep_time,
                                        "type" : "int",
                                        "min" : 1,
                                        "max" : 10
                                    }
                    }

    def set_config_dict(self, dict):
        if dict:
            self.delay = dict["delay"]["value"]
            self.mtu = dict["mtu"]["value"]
            self.sleep_time = dict["sleep_time"]["value"]
