#       module_snmp.py
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

import threading
import time

import gobject
import gtk
import gtk.glade

from pysnmp.entity.rfc3413.oneliner import cmdgen
import IPy

class scan_thread(threading.Thread):
    def __init__(self, scan_func, scan_args, parent):
        threading.Thread.__init__(self)
        self.scan_func = scan_func
        self.scan_args = scan_args
        self.parent = parent
        self.running = True

    def run(self):
        self.parent.scan_threads[self.scan_args] = self
        try:
            self.scan_func(self.scan_args)
        except:
            pass
        self.running = False
        del self.parent.scan_threads[self.scan_args]
    
    def quit(self):
        self.running = False

class mod_class(object):
    HOSTS_IP_ROW = 0
    HOSTS_AUTH_ROW = 1
    HOSTS_TYPE_ROW = 2
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "snmp"
        self.gladefile = "/modules/module_snmp.glade"
        self.group = "MGMT"
        self.hosts_treestore = gtk.TreeStore(str, str, str)
        self.communities = "public,private,cisco"
        self.scan_timeout = 1
        self.scan_retries = 1
        self.scan_threads_count = 20
        self.hosts = {}
        self.handle = []
        self.scan_threads = {}

    def start_mod(self):
        pass

    def shut_mod(self):
        for i in self.scan_threads:
            if i.running:
                i.running = False
                i.join()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_start_v1_scan_button_clicked" : self.on_start_v1_scan_button_clicked,
                "on_v1_advanced_target_button_clicked" : self.on_v1_advanced_target_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.hosts_treeview = self.glade_xml.get_widget("hosts_treeview")
        self.hosts_treeview.set_model(self.hosts_treestore)
        self.hosts_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_IP_ROW)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("AUTH")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_AUTH_ROW)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("TYPE")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_TYPE_ROW)
        self.hosts_treeview.append_column(column)

        self.v1_net_entry = self.glade_xml.get_widget("v1_net_entry")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.v1_net_entry.set_text(str(IPy.IP("%s/%s" % (ip, mask), make_net=True)))

    def v1_scan_cb(self, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, (ip, comm)):
        print 'sendRequestHandle =', sendRequestHandle
        print 'errorIndication =', errorIndication
        print 'errorStatus =', errorStatus
        print 'varBinds =', varBinds
        print (ip, comm)
        if not errorIndication:
            iter = self.hosts_treestore.append(None, [ip, comm, ""])
            self.hosts[ip] = {  "iter" : iter,
                                "community" : comm
                                }
            for (name, val) in varBinds:
                gtk.gdk.threads_enter()
                self.hosts_treestore.append(iter, ["", str(name), str(val)])
                
                gtk.gdk.threads_leave()

    def v1_scan_func(self, ip):
        asynCommandGenerator = cmdgen.AsynCommandGenerator()
        for j in self.communities.split(","):
            print j
            try:
                sendRequestHandle = asynCommandGenerator.asyncGetCmd(
                                        cmdgen.CommunityData('my-agent', j, 1),
                                        cmdgen.UdpTransportTarget((ip, 161), timeout=self.scan_timeout, retries=self.scan_retries), 
                                        ((1,3,6,1,2,1,1,1,0),(1,3,6,1,2,1,1,4,0),(1,3,6,1,2,1,1,5,0),(1,3,6,1,2,1,1,6,0)), 
                                        (self.v1_scan_cb, (ip, j))
                                        )
                asynCommandGenerator.snmpEngine.transportDispatcher.runDispatcher()
            except Exception, e:
                print "OOooops: " + e
    
    def on_start_v1_scan_button_clicked(self, data):        
        ip = IPy.IP(self.v1_net_entry.get_text())
        for i in ip:
            index = len(self.scan_threads)
            while len(self.scan_threads) > self.scan_threads_count:
                print len(self.scan_threads) + " waiting..."
                time.sleep(1)
            t = scan_thread(self.v1_scan_func, str(i), self)
            t.start()

    def on_v1_advanced_target_button_clicked(self, data):
        pass

    def get_config_dict(self):
        return {    "communities" : {   "value" : self.communities,
                                        "type" : "str",
                                        "min" : 1,
                                        "max" : 100000
                                        },
                    "scan_timeout" : {  "value" : self.scan_timeout,
                                        "type" : "int",
                                        "min" : 1,
                                        "max" : 100
                                        },
                    "scan_retries" : {  "value" : self.scan_retries,
                                        "type" : "str",
                                        "min" : 1,
                                        "max" : 100
                                        },
                    "scan_threads_count" : {    "value" : self.scan_threads_count,
                                                "type" : "str",
                                                "min" : 1,
                                                "max" : 1000
                                                }
                    }
                    
    def set_config_dict(self, dict):
        if dict:
            self.communities = dict["communities"]["value"]
            self.scan_timeout = dict["scan_timeout"]["value"]
            self.scan_retries = dict["scan_retries"]["value"]
            self.scan_threads_count = dict["scan_threads_count"]["value"]
            
