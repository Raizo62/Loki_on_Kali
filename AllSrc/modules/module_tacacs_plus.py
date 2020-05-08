#       module_tacacs_plus.py
#       
#       Copyright 2015 Daniel Mende <dmende@ernw.de>
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
import os
import struct
import tempfile
import threading
import time

import dnet
import dpkt

gobject = None
gtk = None
urwid = None

TACACS_PLUS_PORT = 49
TACACS_PLUS_VERSION_MAJOR = 0xc
TACACS_PLUS_VERSION_MINOR_DEFAULT = 0x0
TACACS_PLUS_VERSION_MINOR_ONE = 0x1

class tacacs_plus_header(object):
        #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #~ 
        #~ +----------------+----------------+----------------+----------------+
        #~ |major  | minor  |                |                |                |
        #~ |version| version|      type      |     seq_no     |   flags        |
        #~ +----------------+----------------+----------------+----------------+
        #~ |                                                                   |
        #~ |                            session_id                             |
        #~ +----------------+----------------+----------------+----------------+
        #~ |                                                                   |
        #~ |                              length                               |
        #~ +----------------+----------------+----------------+----------------+

    TYPE_AUTHEN = 0x01
    TYPE_AUTHOR = 0x02
    TYPE_ACCT   = 0x03
    
    type_to_str = { 0x01    :   "TYPE_AUTHEN",
                    0x02    :   "TYPE_AUTHOR",
                    0x03    :   "TYPE_ACCT"
                    }

    FLAGS_UNENCRYPTED = 0x01
    
    flags_to_str = {    0x00    :   "FLAGS_NONE",
                        0x01    :   "FLAGS_UNENCRYPTED"
                        }

    def __init__(self, version_minor=None, _type=None, seq_no=None, flags=None, session_id=None):
        self.version_minor = version_minor
        self._type = _type
        self.seq_no = seq_no
        self.flags = flags
        self.session_id = session_id
    
    def __repr__(self):
        try:
            return "TACACS+ Header: VERSION(%d) %s SEQNO(%x) %s SESSIONID(%x)" % \
                (self.version_minor, self.type_to_str[self._type], self.seq_no, self.flags_to_str[self.flags], self.session_id)
        except:
            return "Invalid TACACS+ Header"
    def render(self, data):
        return struct.pack("!BBBBII",   TACACS_PLUS_VERSION_MAJOR << 4 + self.version_minor,
                                        self._type,
                                        self.seq_no,
                                        self.flags,
                                        self.session_id,
                                        len(data)) + data
    
    def parse(self, data):
        (ver, self._type, self.seq_no, self.flags, self.session_id, self.length) = struct.unpack("!BBBBII", data[:12])
        self.version_minor = ver & 0x0F
        return data[12:]

class tacacs_plus_authentication_start(object):
     #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
     #~ +----------------+----------------+----------------+----------------+
     #~ |    action      |    priv_lvl    |  authen_type   |     service    |
     #~ +----------------+----------------+----------------+----------------+
     #~ |    user len    |    port len    |  rem_addr len  |    data len    |
     #~ +----------------+----------------+----------------+----------------+
     #~ |    user ...
     #~ +----------------+----------------+----------------+----------------+
     #~ |    port ...
     #~ +----------------+----------------+----------------+----------------+
     #~ |    rem_addr ...
     #~ +----------------+----------------+----------------+----------------+
     #~ |    data...
     #~ +----------------+----------------+----------------+----------------+

    ACTION_AUTHEN_LOGIN    = 0x01
    ACTION_AUTHEN_CHPASS   = 0x02
    ACTION_AUTHEN_SENDPASS = 0x03
    ACTION_AUTHEN_SENDAUTH = 0x04
    
    action_to_str = {   0x01    :   "ACTION_AUTHEN_LOGIN",
                        0x02    :   "ACTION_AUTHEN_CHPASS",
                        0x03    :   "ACTION_AUTHEN_SENDPASS",
                        0x04    :   "ACTION_AUTHEN_SENDAUTH"
                        }
    
    PRIV_LVL_MAX   = 0x0f
    PRIV_LVL_ROOT  = 0x0f
    PRIV_LVL_USER  = 0x01
    PRIV_LVL_MIN   = 0x00
    
    priv_to_str = { 0x0f    :   "PRIV_LVL_ROOT",
                    0x01    :   "PRIV_LVL_USER",
                    0x00    :   "PRIV_LVL_MIN"
                    }
    
    TYPE_ASCII      = 0x01
    TYPE_PAP        = 0x02
    TYPE_CHAP       = 0x03
    TYPE_ARAP       = 0x04
    TYPE_MSCHAP     = 0x05

    type_to_str = { 0x01    :   "TYPE_ASCII",
                    0x02    :   "TYPE_PAP",
                    0x03    :   "TYPE_CHAP",
                    0x04    :   "TYPE_ARAP",
                    0x05    :   "TYPE_MSCHAP"
                    }

    SVC_NONE        = 0x00
    SVC_LOGIN       = 0x01
    SVC_ENABLE      = 0x02
    SVC_PPP         = 0x03
    SVC_ARAP        = 0x04
    SVC_PT          = 0x05
    SVC_RCMD        = 0x06
    SVC_X25         = 0x07
    SVC_NASI        = 0x08
    SVC_FWPROXY     = 0x09

    service_to_str = {  0x00    :   "SVC_NONE",
                        0x01    :   "SVC_LOGIN",
                        0x02    :   "SVC_ENABLE",
                        0x03    :   "SVC_PPP",
                        0x04    :   "SVC_ARAP",
                        0x05    :   "SVC_PT",
                        0x06    :   "SVC_RCMD",
                        0x07    :   "SVC_X25",
                        0x08    :   "SVC_NASI",
                        0x09    :   "SVC_FWPROXY"
                        }


    def __init__(self, action=None, priv_lvl=None, authen_type=None, service=None, user=None, port=None, rem_addr=None, data=None):
        self.action = action
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = service
        self.user = user
        self.port = port
        self.rem_addr = rem_addr
        self.data = data
    
    def __repr__(self):
        try:
            ret = "TACACS+ Authentication Start: %s %s %s %s" % \
                (self.action_to_str[self.action], self.priv_to_str[self.priv_lvl], self.type_to_str[self.authen_type], self.service_to_str[self.service])
            if len(self.user) > 0:
                ret += " USER(%s)" % self.user
            if len(self.port) > 0:
                ret += " PORT(%s)" % self.port
            if len(self.rem_addr) > 0:
                ret += " ADDR(%s)" % self.rem_addr
            if len(self.data) > 0:
                ret += " DATA(%s)" % self.data
            return ret
        except:
            return "Invalid TACACS+ Body"
    
    def render(self):
        return struct.pack("!BBBBBBBB", self.action, 
                                        self.priv_lvl,
                                        self.authen_type,
                                        self.service,
                                        len(self.user),
                                        len(self.port),
                                        len(self.rem_addr),
                                        len(self.data)) + \
                                    self.user + \
                                    self.port + \
                                    self.rem_addr + \
                                    self.data
        
    def parse(self, data):
        (self.action, self.priv_lvl, self.authen_type, self.service,
         self.user_len, self.port_len, self.rem_addr_len, self.data_len) = \
            struct.unpack("!BBBBBBBB", data[:8])
        self.user = data[8:8+self.user_len]
        self.port = data[8+self.user_len:8+self.user_len+self.port_len]
        self.rem_addr = data[8+self.user_len+self.port_len:8+self.user_len+self.port_len+self.rem_addr_len]
        self.data = data[8+self.user_len+self.port_len+self.rem_addr_len:8+self.user_len+self.port_len+self.rem_addr_len+self.data_len]
        return data[8+self.user_len+self.port_len+self.rem_addr_len+self.data_len:]

class tacacs_plus_authentication_reply(object):
    #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    #~ +----------------+----------------+----------------+----------------+
    #~ |     status     |      flags     |        server_msg len           |
    #~ +----------------+----------------+----------------+----------------+
    #~ |           data len              |        server_msg ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |           data ...
    #~ +----------------+----------------+
    
    STATUS_PASS     = 0x01
    STATUS_FAIL     = 0x02
    STATUS_GETDATA  = 0x03
    STATUS_GETUSER  = 0x04
    STATUS_GETPASS  = 0x05
    STATUS_RESTART  = 0x06
    STATUS_ERROR    = 0x07
    STATUS_FOLLOW   = 0x21
    
    status_to_str = {   0x01    :   "STATUS_PASS",
                        0x02    :   "STATUS_FAIL",
                        0x03    :   "STATUS_GETDATA",
                        0x04    :   "STATUS_GETUSER",
                        0x05    :   "STATUS_GETPASS",
                        0x06    :   "STATUS_RESTART",
                        0x07    :   "STATUS_ERROR",
                        0x21    :   "STATUS_FOLLOW"
                        }
    
    FLAG_NOECHO      = 0x01
    
    flags_to_str = {    0x00    :   "FLAG_NONE",
                        0x01    :   "FLAG_NOECHO"
                        }
    
    def __init__(self, status=None, flags=None, server_msg=None, data=None):
        self.status = status
        self.flags = flags
        self.server_msg = server_msg
        self.data = data
    
    def __repr__(self):
        try:
            ret = "TACACS+ Authentication Reply: %s %s" % (self.status_to_str[self.status], self.flags_to_str[self.flags])
            if len(self.server_msg) > 0:
                ret += " MSG(%s)" % self.server_msg
            if len(self.data) > 0:
                ret += " DATA(%s)" % self.data
            return ret
        except:
            return "Invalid TACACS+ Body"
    
    def render(self):
        return struct.pack("!BBHH", self.status, self.flags, len(self.server_msg), len(self.data))
    
    def parse(self, data):
        (self.status, self.flags, self.server_msg_len, self.data_len) = struct.unpack("!BBHH", data[:6])
        self.server_msg = data[6:6+self.server_msg_len]
        self.data = data[6+self.server_msg_len:6+self.server_msg_len+self.data_len]
        return data[6+self.server_msg_len+self.data_len:]

class tacacs_plus_authentication_continue(object):
    #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    #~ +----------------+----------------+----------------+----------------+
    #~ |          user_msg len           |            data len             |
    #~ +----------------+----------------+----------------+----------------+
    #~ |     flags      |  user_msg ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |    data ...
    #~ +----------------+
    
    FLAG_ABORT    = 0x01
    
    flags_to_str = {    0x00    :   "FLAG_NONE",
                        0x01    :   "FLAG_ABORT"
                        }
    
    def __init__(self, flags=None, user_msg=None, data=None):
        self.flags = flags
        self.user_msg = user_msg
        self.data = data
    
    def __repr__(self):
        try:
            ret = "TACACS+ Authentication Continue: %s" % self.flags_to_str[self.flags]
            if len(self.user_msg) > 0:
                ret += " MSG(%s)" % self.user_msg
            if len(self.data) > 0:
                ret += " DATA(%s)" % self.data
            return ret
        except:
            return "Invalid TACACS+ Body"
        
    def render(self):
        return struct.pack("!HHB", len(self.user_msg), len(self.data), self.flags) + \
                self.user_msg + self.data
    
    def parse(self, data):
        (self.user_msg_len, self.data_len, self.flags) = struct.unpack("!HHB", data[:5])
        self.user_msg = data[5:5+self.user_msg_len]
        self.data = data[5+self.user_msg_len:5+self.user_msg_len+self.data_len]
        return data[5+self.user_msg_len+self.data_len:]

class tacacs_plus_authorization_request(object):
    #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    #~ +----------------+----------------+----------------+----------------+
    #~ |  authen_method |    priv_lvl    |  authen_type   | authen_service |
    #~ +----------------+----------------+----------------+----------------+
    #~ |    user len    |    port len    |  rem_addr len  |    arg_cnt     |
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 1 len    |   arg 2 len    |      ...       |   arg N len    |
    #~ +----------------+----------------+----------------+----------------+
    #~ |   user ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   port ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   rem_addr ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 1 ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 2 ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg N ...
    #~ +----------------+----------------+----------------+----------------+
    
    METH_NOT_SET    = 0x00
    METH_NONE       = 0x01
    METH_KRB5       = 0x02
    METH_LINE       = 0x03
    METH_ENABLE     = 0x04
    METH_LOCAL      = 0x05
    METH_TACACSPLUS = 0x06
    METH_GUEST      = 0x08
    METH_RADIUS     = 0x10
    METH_KRB4       = 0x11
    METH_RCMD       = 0x20
    
    meth_to_str = { 0x00    :   "METH_NOT_SET",
                    0x01    :   "METH_NONE",
                    0x02    :   "METH_KRB5",
                    0x03    :   "METH_LINE",
                    0x04    :   "METH_ENABLE",
                    0x05    :   "METH_LOCAL",
                    0x06    :   "METH_TACACSPLUS",
                    0x08    :   "METH_GUEST",
                    0x10    :   "METH_RADIUS",
                    0x11    :   "METH_KRB4",
                    0x20    :   "METH_RCMD"
                    }
    
    PRIV_LVL_MAX   = 0x0f
    PRIV_LVL_ROOT  = 0x0f
    PRIV_LVL_USER  = 0x01
    PRIV_LVL_MIN   = 0x00
    
    priv_to_str = { 0x0f    :   "PRIV_LVL_ROOT",
                    0x01    :   "PRIV_LVL_USER",
                    0x00    :   "PRIV_LVL_MIN"
                    }

    TYPE_ASCII      = 0x01
    TYPE_PAP        = 0x02
    TYPE_CHAP       = 0x03
    TYPE_ARAP       = 0x04
    TYPE_MSCHAP     = 0x05

    type_to_str = { 0x01    :   "TYPE_ASCII",
                    0x02    :   "TYPE_PAP",
                    0x03    :   "TYPE_CHAP",
                    0x04    :   "TYPE_ARAP",
                    0x05    :   "TYPE_MSCHAP"
                    }

    SVC_NONE        = 0x00
    SVC_LOGIN       = 0x01
    SVC_ENABLE      = 0x02
    SVC_PPP         = 0x03
    SVC_ARAP        = 0x04
    SVC_PT          = 0x05
    SVC_RCMD        = 0x06
    SVC_X25         = 0x07
    SVC_NASI        = 0x08
    SVC_FWPROXY     = 0x09

    service_to_str = {  0x00    :   "SVC_NONE",
                        0x01    :   "SVC_LOGIN",
                        0x02    :   "SVC_ENABLE",
                        0x03    :   "SVC_PPP",
                        0x04    :   "SVC_ARAP",
                        0x05    :   "SVC_PT",
                        0x06    :   "SVC_RCMD",
                        0x07    :   "SVC_X25",
                        0x08    :   "SVC_NASI",
                        0x09    :   "SVC_FWPROXY"
                        }
    
    def __init__(self, authen_method=None, priv_lvl=None, authen_type=None, authen_service=None, user=None, port=None, rem_addr=None, args=[]):
        self.authen_method = authen_method
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.authen_service = authen_service
        self.user = user
        self.port = port
        self.rem_addr = rem_addr
        self.args = args
    
    def __repr__(self):
        try:
            ret = "TACACS+ Autorization Request: %s %s %s %s" % (self.meth_to_str[self.authen_method], self.priv_to_str[self.priv_lvl], \
                self.type_to_str[self.authen_type], self.service_to_str[self.authen_service])
            if len(self.user) > 0:
                ret += " USER(%s)" % self.user
            if len(self.port) > 0:
                ret += " PORT(%s)" % self.port
            if len(self.rem_addr) > 0:
                ret += " ADDR(%s)" % self.rem_addr
            if len(self.args) > 0:
                ret += " ARGS( %s )" % self.args
            return ret
        except:
            return "Invalid TACACS+ Body"
    
    def render(self):
        ret = struct.pack("!BBBBBBBB", self.authen_method, self.priv_lvl, self.authen_type, self.authen_service, \
            len(self.user), len(self.port), len(self.rem_addr), len(self.args))
        for i in self.args:
            ret += struct.pack("!B", len(i))
        ret += self.user + self.port + self.rem_addr
        for i in self.args:
            ret += i
        return ret
    
    def parse(self, data):
        self.args_len = []
        (self.authen_method, self.priv_lvl, self.authen_type, self.authen_service, \
         self.user_len, self.port_len, self.rem_addr_len, self.arg_cnt) = \
         struct.unpack("!BBBBBBBB", data[:8])
        data = data[8:]
        for i in xrange(self.arg_cnt):
            arg_len, = struct.unpack("!B", data[:1])
            data = data[1:]
            self.args_len.append(arg_len)
        self.user = data[:self.user_len]
        self.port = data[self.user_len:self.user_len+self.port_len]
        self.rem_addr = data[self.user_len+self.port_len:self.user_len+self.port_len+self.rem_addr_len]
        data = data[self.user_len+self.port_len+self.rem_addr_len:]
        for i in self.args_len:
            self.args.append(data[:i])
            data = data[i:]
        return data

class tacacs_plus_authorization_response(object):
    #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    #~ +----------------+----------------+----------------+----------------+
    #~ |    status      |     arg_cnt    |         server_msg len          |
    #~ +----------------+----------------+----------------+----------------+
    #~ +            data len             |    arg 1 len   |    arg 2 len   |
    #~ +----------------+----------------+----------------+----------------+
    #~ |      ...       |   arg N len    |         server_msg ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   data ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 1 ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 2 ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg N ...
    #~ +----------------+----------------+----------------+----------------+
        
    STATUS_PASS_ADD  = 0x01
    STATUS_PASS_REPL = 0x02
    STATUS_FAIL      = 0x10
    STATUS_ERROR     = 0x11
    STATUS_FOLLOW    = 0x21
    
    status_to_str = { 0x01  :   "STATUS_PASS_ADD",
                      0x02  :   "STATUS_PASS_REPL",
                      0x10  :   "STATUS_FAIL",
                      0x11  :   "STATUS_ERROR",
                      0x21  :   "STATUS_FOLLOW"
                      }
    
    def __init__(self, status=None, server_msg=None, data=None, args=[]):
        self.status = status
        self.server_msg = server_msg
        self.data = data
        self.args = args
    
    def __repr__(self):
        try:
            ret = "TACACS+ Autorization Response: %s" % (self.status_to_str[self.status])
            if len(self.server_msg) > 0:
                ret += " MSG(%s)" % self.server_msg
            if len(self.data) > 0:
                ret += " DATA(%s)" % self.data
            if len(self.args) > 0:
                ret += " ARGS( %s )" % self.args
            return ret
        except:
            return "Invalid TACACS+ Body"
    
    def render(self):
        ret = struct.pack("!BBHH", self.status, len(self.args), len(self.server_msg), len(self.data))
        for i in self.args:
            ret += struct.pack("!B", len(i))
        ret += self.server_msg + self.data
        for i in self.args:
            ret += i
        return ret
    
    def parse(self, data):
        self.args_len = []
        (self.status, self.arg_cnt, self.server_msg_len, self.data_len) = struct.unpack("!BBHH", data[:6])
        data = data[6:]
        for i in xrange(self.arg_cnt):
            arg_len, = struct.unpack("!B", data[:1])
            self.args_len.append(arg_len)
            data = data[1:]
        self.server_msg = data[:self.server_msg_len]
        self.data = data[self.server_msg_len:self.server_msg_len+self.data_len]
        data = data[self.server_msg_len+self.data_len:]
        for i in self.args_len:
            self.args.append(data[:i])
            data = data[i:]
        return data

class tacacs_plus_account_request(object):
    #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    #~ +----------------+----------------+----------------+----------------+
    #~ |      flags     |  authen_method |    priv_lvl    |  authen_type   |
    #~ +----------------+----------------+----------------+----------------+
    #~ | authen_service |    user len    |    port len    |  rem_addr len  |
    #~ +----------------+----------------+----------------+----------------+
    #~ |    arg_cnt     |   arg 1 len    |   arg 2 len    |      ...       |
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg N len    |    user ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   port ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   rem_addr ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 1 ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg 2 ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |   arg N ...
    #~ +----------------+----------------+----------------+----------------+
    
    FLAG_MORE     = 0x01
    FLAG_START    = 0x02
    FLAG_STOP     = 0x04
    FLAG_WATCHDOG = 0x08
    
    def flags_to_str(self, flags):
        ret = []
        if flags & self.FLAG_MORE:
            ret.append("FLAG_MORE")
        if flags & self.FLAG_START:
            ret.append("FLAG_START")
        if flags & self.FLAG_STOP:
            ret.append("FLAG_STOP")
        if flags & self.FLAG_WATCHDOG:
            ret.append("FLAG_WATCHDOG")
        return "|".join(ret)
    
    METH_NOT_SET    = 0x00
    METH_NONE       = 0x01
    METH_KRB5       = 0x02
    METH_LINE       = 0x03
    METH_ENABLE     = 0x04
    METH_LOCAL      = 0x05
    METH_TACACSPLUS = 0x06
    METH_GUEST      = 0x08
    METH_RADIUS     = 0x10
    METH_KRB4       = 0x11
    METH_RCMD       = 0x20
    
    meth_to_str = { 0x00    :   "METH_NOT_SET",
                    0x01    :   "METH_NONE",
                    0x02    :   "METH_KRB5",
                    0x03    :   "METH_LINE",
                    0x04    :   "METH_ENABLE",
                    0x05    :   "METH_LOCAL",
                    0x06    :   "METH_TACACSPLUS",
                    0x08    :   "METH_GUEST",
                    0x10    :   "METH_RADIUS",
                    0x11    :   "METH_KRB4",
                    0x20    :   "METH_RCMD"
                    }
    
    PRIV_LVL_MAX   = 0x0f
    PRIV_LVL_ROOT  = 0x0f
    PRIV_LVL_USER  = 0x01
    PRIV_LVL_MIN   = 0x00
    
    priv_to_str = { 0x0f    :   "PRIV_LVL_ROOT",
                    0x01    :   "PRIV_LVL_USER",
                    0x00    :   "PRIV_LVL_MIN"
                    }

    TYPE_ASCII      = 0x01
    TYPE_PAP        = 0x02
    TYPE_CHAP       = 0x03
    TYPE_ARAP       = 0x04
    TYPE_MSCHAP     = 0x05

    type_to_str = { 0x01    :   "TYPE_ASCII",
                    0x02    :   "TYPE_PAP",
                    0x03    :   "TYPE_CHAP",
                    0x04    :   "TYPE_ARAP",
                    0x05    :   "TYPE_MSCHAP"
                    }

    SVC_NONE        = 0x00
    SVC_LOGIN       = 0x01
    SVC_ENABLE      = 0x02
    SVC_PPP         = 0x03
    SVC_ARAP        = 0x04
    SVC_PT          = 0x05
    SVC_RCMD        = 0x06
    SVC_X25         = 0x07
    SVC_NASI        = 0x08
    SVC_FWPROXY     = 0x09

    service_to_str = {  0x00    :   "SVC_NONE",
                        0x01    :   "SVC_LOGIN",
                        0x02    :   "SVC_ENABLE",
                        0x03    :   "SVC_PPP",
                        0x04    :   "SVC_ARAP",
                        0x05    :   "SVC_PT",
                        0x06    :   "SVC_RCMD",
                        0x07    :   "SVC_X25",
                        0x08    :   "SVC_NASI",
                        0x09    :   "SVC_FWPROXY"
                        }
    
    def __init__(self, flags=None, authen_method=None, priv_lvl=None, authen_type=None, authen_service=None, user=None, port=None, rem_addr=None, args=[]):
        self.flags = flags
        self.authen_method = authen_method
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.authen_service = authen_service
        self.user = user
        self.port = port
        self.rem_addr = rem_addr
        self.args = args
    
    def __repr__(self):
        try:
            ret = "TACACS+ Account Request: %s %s %s %s %s" % (self.flags_to_str(self.flags), self.meth_to_str[self.authen_method], \
                self.priv_to_str[self.priv_lvl], self.type_to_str[self.authen_type], self.service_to_str[self.authen_service])
            if len(self.user) > 0:
                ret += " USER(%s)" % self.user
            if len(self.port) > 0:
                ret += " PORT(%s)" % self.port
            if len(self.rem_addr) > 0:
                ret += " ADDR(%s)" % self.rem_addr
            if len(self.args) > 0:
                ret += " ARGS( %s )" % self.args
            return ret
        except:
            return "Invalid TACACS+ Body"
    
    def render(self):
        ret = struct.pack("!BBBBBBBBB", self.flags, self.authen_method, self.priv_lvl, self.authen_type, \
            self.authen_service, len(self.user), len(self.port), len(self.rem_addr), len(self.args))
        for i in self.args:
            ret += struct.pack("!B", len(i))
        ret += self.user + self.port + self.rem_addr
        for i in self.args:
            ret += i
        return ret
    
    def parse(self, data):
        self.args_len = []
        (self.flags, self.authen_method, self.priv_lvl, self.authen_type, self.authen_service, \
         self.user_len, self.port_len, self.rem_addr_len, self.arg_cnt) = \
         struct.unpack("!BBBBBBBBB", data[:9])
        data = data[9:]
        for i in xrange(self.arg_cnt):
            arg_len, = struct.unpack("!B", data[:1])
            data = data[1:]
            self.args_len.append(arg_len)
        self.user = data[:self.user_len]
        self.port = data[self.user_len:self.user_len+self.port_len]
        self.rem_addr = data[self.user_len+self.port_len:self.user_len+self.port_len+self.rem_addr_len]
        data = data[self.user_len+self.port_len+self.rem_addr_len:]
        for i in self.args_len:
            self.args.append(data[:i])
            data = data[i:]
        return data
    
class tacacs_plus_account_response(object):
    #~  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    #~ +----------------+----------------+----------------+----------------+
    #~ |         server_msg len          |            data len             |
    #~ +----------------+----------------+----------------+----------------+
    #~ |     status     |         server_msg ...
    #~ +----------------+----------------+----------------+----------------+
    #~ |     data ...
    #~ +----------------+

    STATUS_SUCCESS    = 0x01
    STATUS_ERROR      = 0x02
    STATUS_FOLLOW     = 0x21
    
    status_to_str = { 0x01  :   "STATUS_SUCCESS",
                      0x02  :   "STATUS_ERROR",
                      0x21  :   "STATUS_FOLLOW"
                      }
    
    def __init__(self, status=None, server_msg=None, data=None):
        self.status = status
        self.server_msg = server_msg
        self.data = data
    
    def __repr__(self):
        try:
            ret = "TACACS+ Account Reponse: %s" % self.status_to_str[self.status]
            if len(self.server_msg) > 0:
                ret += " MSG(%s)" % self.server_msg
            if len(self.data) > 0:
                ret += " DATA(%s)" % self.data
            return ret
        except:
            return "Invalid TACACS+ Body"
    
    
    def render(self):
        return struct.pack("!HHB", len(self.server_msg), len(self.data), self.status)
    
    def parse(self, data):
        (self.server_msg_len, self.data_len, self.status) = struct.unpack("!HHB", data[:5])
        self.server_msg = data[5:5+self.server_msg_len]
        self.data = data[5+self.server_msg_len:5+self.server_msg_len+self.data_len]
        return data[5+self.server_msg_len+self.data_len:]
        
class tacacs_plus_bf(threading.Thread):
    def __init__(self, parent, ident, header, body):
        self.parent = parent
        self._ident = ident
        self.header = header
        self.body = body
        self.obj = None
        threading.Thread.__init__(self)

    def run(self):
        predata = struct.pack("!I", self.header.session_id)
        postdata = struct.pack("!BB", TACACS_PLUS_VERSION_MAJOR << 4 + self.header.version_minor, self.header.seq_no)

        if self.parent.platform == "Windows":
            import bf
        else:
            from loki_bindings import bf
        l = self.parent.parent
        self.obj = bf.tacacs_bf()
        self.obj.num_threads = l.bruteforce_threads
        if not l.bruteforce:
            self.obj.mode = bf.MODE_WORDLIST
            self.obj.wordlist = l.wordlist
        else:
            if not l.bruteforce_full:
                self.obj.mode = bf.MODE_ALPHANUM
            else:
                self.obj.mode = bf.MODE_FULL
        self.obj.pre_data = predata
        self.obj.hash_data = postdata
        self.obj.ciphertext = self.body
        
        self.obj.start()
        while self.obj.running:
            time.sleep(0.01)
        if not self.obj.pw is None:
            if self.parent.ui == 'urw':
                self.parent.set_secret(self._ident, self.obj.pw)
            elif self.parent.ui == 'gtk':
                with gtk.gdk.lock:
                    self.parent.set_secret(self._ident, self.obj.pw)

        self.parent.peers[self._ident]['crack'] = False
        if self.parent.ui == 'urw':
            self.parent.peerlist[self.parent.peers[self._ident]['iter']].contents[1][0].set_attr_map({None : "button normal"})
        elif self.parent.ui == 'gtk':
            with gtk.gdk.lock:
                self.parent.treestore[self.parent.peers[self._ident]['iter']][self.parent.STORE_CRACK_ROW] = False
        self.obj = None
        
    def quit(self):
        if not self.obj is None:
            self.obj.stop()
            self.obj = None
    
class mod_class(object):
    STORE_CON_ROW    = 0
    STORE_CRYPT_ROW  = 1
    STORE_CRACK_ROW  = 2
    STORE_SECRET_ROW = 3
    
    def __init__(self, parent, platform, ui):
        self.parent = parent
        self.platform = platform
        self.ui = ui
        if self.ui == 'gtk':
            import gobject as gobject_
            import gtk as gtk_
            #import gtk.glade as glade_
            global gobject
            global gtk
            gobject = gobject_
            gtk = gtk_
            #gtk.glade = glade_
        else:
            import urwid as urwid_
            global urwid
            urwid = urwid_
            
            class _PopUpDialog(urwid.WidgetWrap):
                signals = ['close']
                def __init__(self, parent, ident):
                    close_button = urwid.AttrMap(urwid.Button("OK"), 'button normal', focus_map='reversed')
                    urwid.connect_signal(close_button.base_widget, 'click',
                        lambda button:self.base_widget._emit("close"))
                    pile = urwid.Pile([urwid.Edit("", "\n".join(parent.peers[ident]['log']), multiline=True), close_button])
                    fill = urwid.Filler(pile)
                    urwid.WidgetWrap.__init__(self, urwid.AttrWrap(fill, 'popbg'))
            self.PopUpDialog = _PopUpDialog

            class _PopUpButton(urwid.PopUpLauncher):
                def __init__(self, msg, parent, ident):
                    urwid.PopUpLauncher.__init__(self, urwid.AttrMap(urwid.Button(msg), 'button normal', focus_map='reversed'))
                    self.parent = parent
                    self.ident = ident
                    urwid.connect_signal(self.base_widget, 'click',
                        lambda button: self.open_pop_up())

                def create_pop_up(self):
                    pop_up = self.parent.PopUpDialog(self.parent, self.ident)
                    urwid.connect_signal(pop_up, 'close',
                        lambda button: self.close_pop_up())
                    return pop_up

                def get_pop_up_parameters(self):
                    return {'left':1, 'top':1, 'overlay_width':76, 'overlay_height':17}
            self.PopUpButton = _PopUpButton

            class _PwPopUpDialog(urwid.WidgetWrap):
                signals = ['close']
                def __init__(self, parent, ident):
                    self.parent = parent
                    self.ident = ident
                    close_button = urwid.AttrMap(urwid.Button("OK"), 'button normal', focus_map='reversed')
                    urwid.connect_signal(close_button.base_widget, 'click', self.close)
                    self.edit = urwid.Edit("TACACS+ Secret: ")
                    pile = urwid.Pile([self.edit, close_button])
                    fill = urwid.Filler(pile)
                    urwid.WidgetWrap.__init__(self, urwid.AttrWrap(fill, 'popbg'))
                
                def close(self, button):
                    self.parent.set_secret(self.ident, self.edit.get_edit_text().encode("ascii"))
                    self.base_widget._emit("close")
            self.PwPopUpDialog = _PwPopUpDialog

            class _PwPopUpButton(urwid.PopUpLauncher):
                def __init__(self, parent, ident):
                    urwid.PopUpLauncher.__init__(self, urwid.AttrMap(urwid.Button("Set Secret"), 'button normal', focus_map='reversed'))
                    self.parent = parent
                    self.ident = ident
                    urwid.connect_signal(self.base_widget, 'click',
                        lambda button: self.open_pop_up())

                def create_pop_up(self):
                    pop_up = self.parent.PwPopUpDialog(self.parent, self.ident)
                    urwid.connect_signal(pop_up, 'close',
                        lambda button: self.close_pop_up())
                    return pop_up

                def get_pop_up_parameters(self):
                    return {'left':1, 'top':1, 'overlay_width':30, 'overlay_height':4}
            self.PwPopUpButton = _PwPopUpButton
        self.name = "tacacs+"
        self.group = "AAA"
        #self.gladefile = "/modules/module_tacacs_plus.glade"
        if ui == 'gtk':
            self.treestore = gtk.TreeStore(str, bool, bool, str)
        self.thread = None

    def start_mod(self):
        self.peers = {}

    def shut_mod(self):
        if self.ui == 'gtk':
            pass
        elif self.ui == 'urw':
            for i in self.peerlist:
                self.peerlist.remove(i)
        if self.thread:
            if self.thread.is_alive():
                self.thread.quit()

    def get_root(self):
        treeview = gtk.TreeView(self.treestore)
        treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("CONNECTION")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_CON_ROW)
        treeview.append_column(column)
        
        column = gtk.TreeViewColumn()
        column.set_title("ENCRYPTED")
        render_toggle = gtk.CellRendererToggle()
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, "active", self.STORE_CRYPT_ROW)
        treeview.append_column(column)
        
        column = gtk.TreeViewColumn()
        column.set_title("CRACK")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.set_property('radio', True)
        render_toggle.connect('toggled', self.crack_toogled_callback, self.treestore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, 'active', self.STORE_CRACK_ROW)
        treeview.append_column(column)
        
        column = gtk.TreeViewColumn()
        column.set_title("SECRET")
        render_text = gtk.CellRendererText()
        render_text.set_property('editable', True)
        render_text.connect('edited', self.secret_edited_callback, self.treestore)
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.STORE_SECRET_ROW)
        treeview.append_column(column)
        
        return treeview
    
    def secret_edited_callback(self, cell, path, new_text, model):
        ident = model[path][self.STORE_CON_ROW]
        model[path][self.STORE_SECRET_ROW] = new_text
        self.set_secret(ident, new_text)
    
    def crack_toogled_callback(self, cell, path, model):
        self.crack_activated(model[path], model[path][self.STORE_CON_ROW])
    
    def get_urw(self):
        peerlist = [ urwid.AttrMap(urwid.Text("Hosts seen:"), 'header'), urwid.Divider() ]
        self.peerlist = urwid.SimpleListWalker(peerlist)
        peerlist = urwid.LineBox(urwid.ListBox(self.peerlist))
        return urwid.Pile([ peerlist ])
    
    def crack_activated(self, button, ident):
        if self.peers[ident]['crack_pkg'] is None:
            self.log("TACACS+: No suitable packet for cracking found, yet")
            return
        if not self.peers[ident]['crack']:
            (header, body) = self.peers[ident]['crack_pkg']
            self.thread = tacacs_plus_bf(self, ident, header, body)
            self.thread.start()
            self.peers[ident]['crack'] = True
            if self.ui == 'gtk':
                button[self.STORE_CRACK_ROW] = True
            elif self.ui == "urw":
                self.peerlist[self.peers[ident]['iter']].contents[1][0].set_attr_map({None : "button select"})
        else:
            self.thread.quit()
            self.peers[ident]['crack'] = False
            if self.ui == 'gtk':
                button[self.STORE_CRACK_ROW] = False
            elif self.ui == "urw":
                self.peerlist[self.peers[ident]['iter']].contents[1][0].set_attr_map({None : "button normal"})

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log
    
    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()
        
    def get_tcp_checks(self):
        return (self.check_tcp, self.input_tcp)
    
    def check_tcp(self, tcp):
        if tcp.dport == TACACS_PLUS_PORT or tcp.sport == TACACS_PLUS_PORT:
            if len(tcp.data) > 12:
                return (True, False)
        return (False, False)
    
    def input_tcp(self, eth, ip, tcp, timestamp):
        if not eth.src == self.mac:
            header = tacacs_plus_header()
            data = header.parse(str(tcp.data))
            server = tcp.sport == TACACS_PLUS_PORT
            if server:
                ident = "%s -> %s" % (dnet.ip_ntoa(ip.dst), dnet.ip_ntoa(ip.src))
            else:
                ident = "%s -> %s" % (dnet.ip_ntoa(ip.src), dnet.ip_ntoa(ip.dst))
                
            if not ident in self.peers:
                encrypt = not (header.flags & tacacs_plus_header.FLAGS_UNENCRYPTED)
                #add to gui
                if self.ui == "gtk":
                    row_iter = self.treestore.append( None, [ ident, encrypt, False, "" ] )
                elif self.ui == "urw":
                    column = [ ('weight', 3, self.PopUpButton("%s - ENCRYPTED(%s)" % (ident, str(encrypt)), self, ident)) ]
                    if not header.flags & tacacs_plus_header.FLAGS_UNENCRYPTED:
                        column.append( self.parent.menu_button("Crack", self.crack_activated, ident) )
                        column.append( self.PwPopUpButton(self, ident) )
                    column = urwid.Columns(column)
                    self.peerlist.append(column)
                    row_iter = self.peerlist.index(column)
                
                self.peers[ident] = { 'encrypt' : encrypt,
                                      'secret'  : None,
                                      'iter'    : row_iter,
                                      'packets' : [],
                                      'log'     : [],
                                      'crack'   : False,
                                      'crack_pkg' : None,
                                      }
                self.log("TACACS+: Got connection %s" % ident)
            if header.flags & tacacs_plus_header.FLAGS_UNENCRYPTED:
                #cleartext
                self.peers[ident]['log'].append(self.body_to_str(header, data))
            else:
                #crypted
                if not self.peers[ident]['secret'] is None:
                    self.peers[ident]['log'].append(self.body_to_str(header, self.decrypt(header, data, self.peers[peer]['secret']), server))
                self.peers[ident]['packets'].append((header, data, server))
                if server and header._type == tacacs_plus_header.TYPE_AUTHEN:
                    self.peers[ident]['crack_pkg'] = (header, data)
    
    def set_secret(self, ident, secret):
        self.log("TACACS+: Setting secret to '%s'" % secret)
        self.peers[ident]['secret'] = secret
        self.peers[ident]['log'] = []
        for (header, data, server) in self.peers[ident]['packets']:
            self.peers[ident]['log'].append(self.body_to_str(header, self.decrypt(header, data, secret), server))
        if self.ui == 'gtk':
            self.treestore[self.peers[ident]['iter']][self.STORE_SECRET_ROW] = secret
            child = self.treestore.iter_children(self.peers[ident]['iter'])
            while not child is None:
                self.treestore.remove(child)
                child = self.treestore.iter_children(self.peers[ident]['iter'])
            for i in self.peers[ident]['log']:
                self.treestore.insert(self.peers[ident]['iter'], len(self.peers[ident]['log']), [ i, False, False, "" ])

        
    def body_to_str(self, header, data, server):
        try:
            if header._type == tacacs_plus_header.TYPE_AUTHEN:
                if not server:
                    if header.seq_no == 1:
                        body = tacacs_plus_authentication_start()
                    else:
                        body = tacacs_plus_authentication_continue()
                else:
                    body = tacacs_plus_authentication_reply()
            elif header._type == tacacs_plus_header.TYPE_AUTHOR:
                if not server:
                    body = tacacs_plus_authorization_request()
                else:
                    body = tacacs_plus_authorization_response()
            elif header._type == tacacs_plus_header.TYPE_ACCT:
                if not server:
                    body = tacacs_plus_account_request()
                else:
                    body = tacacs_plus_account_response()
            else:
                return "%s : Unknown body type" % str(header)
            body.parse(data)
            return str(body)
        except:
            self.log("TACACS+: Can't decode decrypted packet, likely wrong secret.")
            return "Invalid packet"
    
    def decrypt(self, header, data, secret):
        md5 = hashlib.md5()
        md5.update(struct.pack("!I", header.session_id))
        md5.update(secret)
        md5.update(struct.pack("!BB", TACACS_PLUS_VERSION_MAJOR << 4 + header.version_minor, header.seq_no))
        digest = md5.digest()
        pad = digest
        while len(pad) < len(secret):
            md5 = hashlib.md5()
            md5.update(struct.pack("!I", header.session_id))
            md5.update(secret)
            md5.update(struct.pack("!BB", TACACS_PLUS_VERSION_MAJOR << 4 + header.version_minor, header.seq_no))
            md5.update(digest)
            digest = md5.digest()
            pad += digest
        return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(data, pad[:len(data)]))
