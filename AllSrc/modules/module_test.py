#       module_test.py
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

import threading

import dnet

gobject = None
gtk = None
urwid = None

class mod_class(object):
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
        self.name = "test"

    def start_mod(self):
        pass

    def shut_mod(self):
        pass

    def get_root(self):
        return gtk.Label("TEST")
    
    def get_urw(self):
        return urwid.Filler(urwid.Text("TEST", 'center'))

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    #def get_eth_checks(self):
        #return (self.some_eth_check_func, self.the_input_func)

    #def get_ip_checks(self):
        #return (self.some_ip_check_func, self.the_input_func)

    #def get_tcp_checks(self):
        #return (self.some_tcp_check_func, self.the_input_func)

    #~ def get_config_dict(self):
        #~ return {    "foo" : {   "value" : self.foo,
                                #~ "type" : "int",
                                #~ "min" : 1,
                                #~ "max" : 10
                                #~ },
                    #~ "bar" : {   "value" : self.bar,
                                #~ "type" : "str",
                                #~ "min" : 1,
                                #~ "max" : 10000
                                #~ },
                    #~ "xxf" : {  "value" : self.sleep_time,
                                #~ "type" : "float",
                                #~ "min" : 1.0,
                                #~ "max" : -23.4321
                                #~ }
                    #~ }
    #~ def set_config_dict(self, dict):
        #~ if dict:
            #~ self.foo = dict["foo"]["value"]
            #~ self.bar = dict["bar"]["value"]
            #~ self.xxf = dict["xxf"]["value"]
