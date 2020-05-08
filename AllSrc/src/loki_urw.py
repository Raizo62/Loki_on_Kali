#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       loki_urw.py
#       
#       Copyright 2014 Daniel Mende <mail@c0decafe.de>
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

import base64
import copy
import hashlib
import sys
import os
import platform
import threading
import time
import traceback
import signal
import string
import struct
import itertools
import re

import ConfigParser

import dpkt
import dnet
import IPy

import loki

import urwid
import urwid.raw_display

DEBUG = loki.DEBUG

VERSION = loki.VERSION
PLATFORM = loki.PLATFORM

MODULE_PATH = loki.MODULE_PATH
CONFIG_PATH = loki.CONFIG_PATH
DATA_DIR = loki.DATA_DIR

_widget_cache = {}

def add_widget(path, widget):
    """Add the widget for a given path"""

    _widget_cache[path] = widget

def get_flagged_names():
    """Return a list of all filenames marked as flagged."""
    
    l = []
    for w in _widget_cache.values():
        if w.flagged:
            l.append(w.get_node().get_value())
    return l

_initial_cwd = []

def store_initial_cwd(name):
    """Store the initial current working directory path components."""
    
    global _initial_cwd
    _initial_cwd = name.split(dir_sep())

def starts_expanded(name):
    """Return True if directory is a parent of initial cwd."""

    if name is '/':
        return True
    
    l = name.split(dir_sep())
    if len(l) > len(_initial_cwd):
        return False
    
    if l != _initial_cwd[:len(l)]:
        return False
    
    return True
    
SPLIT_RE = re.compile(r'[a-zA-Z]+|\d+')
def alphabetize(s):
    L = []
    for isdigit, group in itertools.groupby(SPLIT_RE.findall(s), key=lambda x: x.isdigit()):
        if isdigit:
            for n in group:
                L.append(('', int(n)))
        else:
            L.append((''.join(group).lower(), 0))
    return L
    
def dir_sep():
    """Return the separator used in this os."""
    return getattr(os.path,'sep','/')

class loki_urw(loki.codename_loki):
    class FlagFileWidget(urwid.TreeWidget):
        # apply an attribute to the expand/unexpand icons
        unexpanded_icon = urwid.AttrMap(urwid.TreeWidget.unexpanded_icon,
            'dirmark')
        expanded_icon = urwid.AttrMap(urwid.TreeWidget.expanded_icon,
            'dirmark')

        def __init__(self, node):
            self.__super.__init__(node)
            # insert an extra AttrWrap for our own use
            self._w = urwid.AttrWrap(self._w, None)
            self.flagged = False
            self.update_w()

        def selectable(self):
            return True

        def keypress(self, size, key):
            """allow subclasses to intercept keystrokes"""
            key = self.__super.keypress(size, key)
            if key:
                key = self.unhandled_keys(size, key)
            return key

        def unhandled_keys(self, size, key):
            """
            Override this method to intercept keystrokes in subclasses.
            Default behavior: Toggle flagged on space, ignore other keys.
            """
            if key == " ":
                self.flagged = not self.flagged
                self.update_w()
            else:
                return key

        def update_w(self):
            """Update the attributes of self.widget based on self.flagged.
            """
            if self.flagged:
                self._w.attr = 'flagged'
                self._w.focus_attr = 'flagged focus'
            else:
                self._w.attr = 'body'
                self._w.focus_attr = 'focus'

    class FileTreeWidget(FlagFileWidget):
        """Widget for individual files."""
        def __init__(self, node):
            self.__super.__init__(node)
            path = node.get_value()
            add_widget(path, self)

        def get_display_text(self):
            return self.get_node().get_key()
        
    class EmptyWidget(urwid.TreeWidget):
        """A marker for expanded directories with no contents."""
        def get_display_text(self):
            return ('flag', '(empty directory)')

    class ErrorWidget(urwid.TreeWidget):
        """A marker for errors reading directories."""

        def get_display_text(self):
            return ('error', "(error/permission denied)")

    class DirectoryWidget(FlagFileWidget):
        """Widget for a directory."""
        def __init__(self, node):
            self.__super.__init__(node)
            path = node.get_value()
            add_widget(path, self)
            self.expanded = starts_expanded(path)
            self.update_expanded_icon()

        def get_display_text(self):
            node = self.get_node()
            if node.get_depth() == 0:
                return "/"
            else:
                return node.get_key()

    class FileNode(urwid.TreeNode):
        """Metadata storage for individual files"""

        def __init__(self, path, parent=None):
            depth = path.count(dir_sep())
            key = os.path.basename(path)
            urwid.TreeNode.__init__(self, path, key=key, parent=parent, depth=depth)

        def load_parent(self):
            parentname, myname = os.path.split(self.get_value())
            parent = loki_urw.DirectoryNode(parentname)
            parent.set_child_node(self.get_key(), self)
            return parent

        def load_widget(self):
            return loki_urw.FileTreeWidget(self)

    class EmptyNode(urwid.TreeNode):
        def load_widget(self):
            return loki_urw.EmptyWidget(self)

    class ErrorNode(urwid.TreeNode):
        def load_widget(self):
            return loki_urw.ErrorWidget(self)

    class DirectoryNode(urwid.ParentNode):
        """Metadata storage for directories"""

        def __init__(self, path, parent=None):
            if path == dir_sep():
                depth = 0
                key = None
            else:
                depth = path.count(dir_sep())
                key = os.path.basename(path)
            urwid.ParentNode.__init__(self, path, key=key, parent=parent, 
                                      depth=depth)

        def load_parent(self):
            parentname, myname = os.path.split(self.get_value())
            parent = loki_urw.DirectoryNode(parentname)
            parent.set_child_node(self.get_key(), self)
            return parent

        def load_child_keys(self):
            dirs = []
            files = []
            try:
                path = self.get_value()
                # separate dirs and files
                for a in os.listdir(path):
                    if os.path.isdir(os.path.join(path,a)):
                        dirs.append(a)
                    else:
                        files.append(a)
            except OSError, e:
                depth = self.get_depth() + 1
                self._children[None] = ErrorNode(self, parent=self, key=None, 
                                                 depth=depth)
                return [None]

            # sort dirs and files
            dirs.sort(key=alphabetize)
            files.sort(key=alphabetize)
            # store where the first file starts
            self.dir_count = len(dirs)
            # collect dirs and files together again
            keys = dirs + files
            if len(keys) == 0:
                depth=self.get_depth() + 1
                self._children[None] = EmptyNode(self, parent=self, key=None, 
                                                 depth=depth)
                keys = [None]
            return keys

        def load_child_node(self, key):
            """Return either a FileNode or DirectoryNode"""
            index = self.get_child_index(key)
            if key is None:
                return EmptyNode(None)
            else:
                path = os.path.join(self.get_value(), key)
                if index < self.dir_count:
                    return loki_urw.DirectoryNode(path, parent=self)
                else:
                    path = os.path.join(self.get_value(), key)
                    return loki_urw.FileNode(path, parent=self)

        def load_widget(self):
            return loki_urw.DirectoryWidget(self)

    class DirectoryBrowser(urwid.Frame):
        def __init__(self, callback, body, header=None, footer=None, focus_part='body'):
            urwid.Frame.__init__(self, body, header, footer, focus_part)
            self.callback = callback

        def keypress(self, size, key):
            if key in ('q','Q'):
                self.callback(get_flagged_names())
            else:
                return urwid.Frame.keypress(self, size, key)

    class CascadingBoxes(urwid.WidgetPlaceholder):
        max_box_levels = 4

        def __init__(self, parent, box):
            super(loki_urw.CascadingBoxes, self).__init__(urwid.SolidFill(u'/'))
            self.box_level = 0
            self.parent = parent
            self.open_box(box)

        def open_box(self, box):
            self.original_widget = urwid.Overlay(urwid.LineBox(box),
                self.original_widget,
                align='center', width=('relative', 80),
                valign='middle', height=('relative', 80),
                min_width=24, min_height=8,
                left=self.box_level * 3,
                right=(self.max_box_levels - self.box_level - 1) * 3,
                top=self.box_level * 2,
                bottom=(self.max_box_levels - self.box_level - 1) * 2)
            self.box_level += 1

        def keypress(self, size, key):
            if key == 'esc' and self.box_level > 1:
                self.original_widget = self.original_widget[0]
                self.box_level -= 1
            elif key == 'esc':
                self.parent.frame.set_body(self.parent.body)
            else:
                return super(loki_urw.CascadingBoxes, self).keypress(size, key)
    
    palette = [
            ('header',       'white',      'dark red',   'bold'),
            ('button normal','light gray', 'dark blue', 'standout'),
            ('button select','white',      'dark green'),
            ('button disabled','dark gray','dark blue'),
            ('edit',         'light gray', 'dark blue'),
            ('edit failure', 'light gray', 'dark red'),
            ('bigtext',      'white',      'black'),
            ('chars',        'light gray', 'black'),
            ('exit',         'white',      'dark cyan'),
            ('body', 'black', 'light gray'),
            ('flagged', 'black', 'dark green', ('bold','underline')),
            ('focus', 'light gray', 'dark blue', 'standout'),
            ('flagged focus', 'yellow', 'dark cyan', ('bold','standout','underline')),
            ('head', 'yellow', 'black', 'standout'),
            ('foot', 'light gray', 'black'),
            ('key', 'light cyan', 'black','underline'),
            ('title', 'white', 'black', 'bold'),
            ('dirmark', 'black', 'dark cyan', 'bold'),
            ('flag', 'dark gray', 'light gray'),
            ('error', 'dark red', 'light gray'),
            ]
        
    def __init__(self):
        loki.codename_loki.__init__(self)
        self.ui = 'urw'
        self.modules_ui = {}
        if PLATFORM == "Windows":
            self.logfile = "c:/temp/loki.log"
        else:
            self.logfile = "/tmp/loki.log"
        self.logfd = open(self.logfile, 'w')
    
    def main(self):
        loki.codename_loki.main(self)
        
        menu_top = self.menu('Main Menu', [
            self.sub_menu('Open', [
                self.menu_button('Interface', self.open_interface),
                self.menu_button('File', self.open_file),
            ]),
            self.sub_menu('Modules', self.modules_menu()),
            self.sub_menu('Configure', [
                self.sub_menu('Modules', self.config_modules_menu()),
                self.menu_button('Bruteforce', self.config_bruteforce)
            ]),
            self.menu_button('Overview', self.show_overview),
            self.menu_button('Quit', self.quit)
        ])
        
        self.menu = self.CascadingBoxes(self, menu_top)
        self.statusbar = urwid.Text("")
        self.body = self.overview()
        self.frame = urwid.Frame(
            self.body,
            footer=urwid.AttrMap(self.statusbar, 'chars')
            )
        
        self.mainloop = urwid.MainLoop( self.frame,
                            palette = self.palette,
                            unhandled_input = self.keyinput,
                            pop_ups=True
                            )
        self.mainloop.screen.set_terminal_properties(colors=256)
        self.mainloop.run()

    def keyinput(self, key):
        if key is 'tab':
            self.frame.set_body(self.menu)
        return key

    def menu_button(self, caption, callback=None, arg=None):
        button = urwid.Button(caption)
        if not callback is None:
            if not arg is None:
                urwid.connect_signal(button, 'click', callback, arg)
            else:
                urwid.connect_signal(button, 'click', callback)
        return urwid.AttrMap(button, 'button normal', focus_map='reversed')

    def sub_menu(self, caption, choices):
        contents = self.menu(caption, choices)
        def open_menu(button):
            return self.menu.open_box(contents)
        return self.menu_button([caption, u'...'], open_menu)

    def menu(self, title, choices):
        body = [urwid.AttrMap(urwid.Text(title), 'header'), urwid.Divider()]
        body.extend(choices)
        return urwid.ListBox(urwid.SimpleFocusListWalker(body))
    
    def item_chosen(self, button):
        response = urwid.Text([u'You chose ', button.label, u'\n'])
        done = self.menu_button(u'Ok', self.quit)
        self.log(button.label)
        self.menu.open_box(urwid.Filler(urwid.Pile([response, done])))
            
    def modules_menu(self):
        ret = []
        for i in self.modules:
            name = self.modules[i][0].name
            ret.append(self.menu_button(name, self.module_chosen, name))
        return ret
    
    def module_chosen(self, button, name):
        self.set_body(self.modules_ui[name])
        
    def config_wordlist(self, button):
        footer_text = [
            ('title', "Directory Browser"), "   ",
            ('key', "UP"), ",", ('key', "DOWN"), ",",
            ('key', "PAGE UP"), ",", ('key', "PAGE DOWN"), "  ",
            ('key', "SPACE"), "  ",
            ('key', "+"), ",",
            ('key', "-"), "  ",
            ('key', "LEFT"), "  ",
            ('key', "HOME"), "  ", 
            ('key', "END"), "  ",
            ('key', "Q"),
            ]
        cwd = os.getcwd()
        store_initial_cwd(cwd)
        header = urwid.Text("Open File")
        listbox = urwid.TreeListBox(urwid.TreeWalker(self.DirectoryNode(cwd)))
        listbox.offset_rows = 1
        footer = urwid.AttrWrap(urwid.Text(footer_text), 'foot')
        view = self.DirectoryBrowser(
            self.config_wordlist_callback,
            urwid.AttrWrap(listbox, 'body'), 
            header=urwid.AttrWrap(header, 'head'), 
            footer=footer)
        self.set_body(view)
        
    def config_wordlist_callback(self, files):
        self.set_body(self.overview())
        if len(files) > 0:
            self.wordlist = files[0]
        self.config_bruteforce(None)

    def bruteforce_checkbox_changed(self, box, state):
        self.bruteforce = state

    def bruteforce_full_checkbox_changed(self, box, state):
        self.bruteforce_full = state
    
    def bruteforce_threads_changed(self, edit, text, attr):
        try:
            val = int(text)
            assert(val >= 1)
            assert(val <= 128)
        except:
            attr.set_attr_map({None : 'edit failure'})
        else:
            attr.set_attr_map({None : 'edit'})
            self.bruteforce_threads = val

    def config_bruteforce(self, button):
        edit = urwid.Edit("Number of threads: ", str(self.bruteforce_threads))
        attr = urwid.AttrMap(edit, 'edit')
        urwid.connect_signal(edit, 'change', self.bruteforce_threads_changed, attr)
        conflist = [ urwid.AttrMap(urwid.Text("Bruteforce config"), 'header'), 
                     urwid.Divider(),
                     self.menu_button("Wordlist: %s" % self.wordlist, self.config_wordlist),
                     urwid.CheckBox("Use bruteforce", state=self.bruteforce, on_state_change=self.bruteforce_checkbox_changed),
                     urwid.CheckBox("Bruteforce full charset", state=self.bruteforce_full, on_state_change=self.bruteforce_full_checkbox_changed),
                     attr
                    ]
        box = urwid.ListBox(urwid.SimpleFocusListWalker(conflist))
        self.frame.set_body(urwid.Overlay(urwid.LineBox(box),
                            self.body,
                            align='center', width=('relative', 80),
                            valign='middle', height=('relative', 80),
                            min_width=24, min_height=8))

    def config_modules_menu(self):
        ret = []
        for i in self.modules:
            if "get_config_dict" in dir(self.modules[i][0]) and "set_config_dict" in dir(self.modules[i][0]):
                name = self.modules[i][0].name
                ret.append(self.menu_button(name, self.module_config_choosen, i))
        return ret

    def module_config_choosen(self, button, name):
        config = self.modules[name][0].get_config_dict()
        conflist = [ urwid.AttrMap(urwid.Text("%s config" % self.modules[name][0].name), 'header'), urwid.Divider() ]
        for i in config:
            if config[i]['type'] == 'str':
                ml=True
            else:
                ml=False
            edit = urwid.Edit("%s - %s (%d-%d):\n" % (i, config[i]["type"], config[i]["min"], config[i]["max"]), str(config[i]["value"]), multiline=ml)
            attr = urwid.AttrMap(edit, 'edit')
            urwid.connect_signal(edit, 'change', self.module_config_changed, (config[i], attr))
            conflist.append(attr)
        conflist.append(urwid.Divider())
        conflist.append(urwid.Columns([ self.menu_button("Done", self.module_config_done, (conflist, config, name)), self.menu_button("Save", self.module_config_save, (conflist, config, name))]))
        box = urwid.ListBox(urwid.SimpleFocusListWalker(conflist))
        self.frame.set_body(urwid.Overlay(urwid.LineBox(box),
                            self.body,
                            align='center', width=('relative', 80),
                            valign='middle', height=('relative', 80),
                            min_width=24, min_height=8))
    
    def module_config_changed(self, edit, text, (config, attr)):
        def int_(edit, new_text, config):
            try:
                val = int(new_text)
                assert(val >= config['min'])
                assert(val <= config['max'])
            except:
                attr.set_attr_map({None : 'edit failure'})
            else:
                attr.set_attr_map({None : 'edit'})
                config['value'] = val
        
        def str_(edit, new_text, config):
            try:
                assert(len(new_text) >= config['min'])
                assert(len(new_text) <= config['max'])
            except:
                attr.set_attr_map({None : 'edit failure'})
            else:
                attr.set_attr_map({None : 'edit'})
                config['value'] = new_text
        
        def float_(edit, new_text, config):
            try:
                val = float(new_text)
                assert(val >= config['min'])
                assert(val <= config['max'])
            except:
                attr.set_attr_map({None : 'edit failure'})
            else:
                attr.set_attr_map({None : 'edit'})
                config['value'] = val
        
        {   "str" : str_,
            "int" : int_,
            "float" : float_    }[config['type']](edit, text, config)
    
    def module_config_done(self, button, (conflist, config, name)):
        for i in conflist:
            if type(i) == urwid.AttrMap and i.attr_map[None] == 'edit failure':
                return
        self.modules[name][0].set_config_dict(config)
        self.set_body(self.body)
    
    def module_config_save(self, button, (conflist, config, name)):
        for i in conflist:
            if type(i) == urwid.AttrMap and i.attr_map[None] == 'edit failure':
                return
        conf = ConfigParser.RawConfigParser()
        conf.add_section(name)
        for i in config:
            if config[i]["type"] == "str":
                conf.set(name, i, base64.b64encode(config[i]["value"]))
            else:
                conf.set(name, i, config[i]["value"])
        path = CONFIG_PATH + "/"
        if not os.path.exists(path):
            os.mkdir(path, 0700)
        with open(path + name +".cfg", 'wb') as configfile:
            conf.write(configfile)
            self.log("Saved %s configuration" % name)

    def set_body(self, body):
        self.body = body
        self.frame.set_body(self.body)
        
    def open_interface(self, button):
        if self.configured or not self.filename is None:
            self.close()
        self.update_devices()
        text = urwid.AttrWrap(urwid.Text("Select the interface to use"), 'header')
        content = [text, urwid.Divider()]
        for i in self.devices:
            if PLATFORM == "Windows":
                content.append(self.menu_button(self.devices[i]["descr"], self.open_interface_callback, i))
            else:
                content.append(self.menu_button(i, self.open_interface_callback, i))
        box = urwid.ListBox(urwid.SimpleFocusListWalker(content))
        self.menu.original_widget = self.menu.original_widget[0]
        self.menu.box_level -= 1
        self.set_body(urwid.Overlay(urwid.LineBox(box),
                self.body,
                align='center', width=('relative', 80),
                valign='middle', height=('relative', 80),
                min_width=24, min_height=8))
    
    def open_interface_callback(self, button, interface):
        for i in self.devices:
            if PLATFORM == "Windows":
                self.interface = None
                for i in self.devices:
                    if self.devices[i]['descr'] == interface:
                        self.interface = i
                assert(self.interface != None)
            else:
                self.interface = interface
        self.select4()
    
    def select4(self):
        select4 = len(self.devices[self.interface]['ip4']) > 1
        if select4:
            text = urwid.AttrWrap(urwid.Text("Select the IPv4 address to use"), 'header')
            content = [text, urwid.Divider()]
            for i in self.devices[self.interface]['ip4']:
                content.append(self.menu_button("%s %s" % (i['ip'], i['mask']), self.select4_callback, self.devices[self.interface]['ip4'].index(i)))
            box = urwid.ListBox(urwid.SimpleFocusListWalker(content))
            self.set_body(urwid.Overlay(urwid.LineBox(box),
                    self.body,
                    align='center', width=('relative', 80),
                    valign='middle', height=('relative', 80),
                    min_width=24, min_height=8))
            return
        else:
            if len(self.devices[self.interface]['ip4']) > 0:
                self.ip = self.devices[self.interface]['ip4'][0]['ip']
                self.mask = self.devices[self.interface]['ip4'][0]['mask']
            else:
                self.ip = "0.0.0.0"
                self.mask ="0.0.0.0"
            self.select6()
    
    def select4_callback(self, button, index):
        self.ip = self.devices[self.interface]['ip4'][index]['ip']
        self.mask = self.devices[self.interface]['ip4'][index]['mask']
        self.select6()
    
    def select6(self):
        select6 = len([ i for i in self.devices[self.interface]['ip6'] if not i['linklocal'] ]) > 1
        v6done = False
        if select6:
            nl = 0
            ip = None
            mask = None
            for i in self.devices[self.interface]['ip6']:
                if i['linklocal']:
                    self.ip6_ll = i['ip']
                    self.mask6_ll = i['mask']
                else:
                    ip = i['ip']
                    mask = i['mask']
                    nl += 1
            if nl > 1:
                text = urwid.AttrWrap(urwid.Text("Select the IPv6 address to use"), 'header')
                content = [text, urwid.Divider()]
                for i in self.devices[self.interface]['ip6']:
                    if not i['linklocal']:
                        content.append(self.menu_button("%s %s" % (i['ip'], i['mask']), self.select6_callback, self.devices[self.interface]['ip6'].index(i)))
                box = urwid.ListBox(urwid.SimpleFocusListWalker(content))
                self.set_body(urwid.Overlay(urwid.LineBox(box),
                        self.body,
                        align='center', width=('relative', 80),
                        valign='middle', height=('relative', 80),
                        min_width=24, min_height=8))
                return
            else:
                self.ip6 = ip
                self.mask6 = mask
                self.configured = True
                self.set_body(self.overview())
                self.run_live()
        else:
            self.ip6 = "::"
            self.mask6 ="::"
            self.ip6_ll = "::"
            self.mask6_ll = "::"
            for i in self.devices[self.interface]['ip6']:
                if i['linklocal']:
                    self.ip6_ll = i['ip']
                    self.mask6_ll = i['mask']
                else:
                    self.ip6 = i['ip']
                    self.mask6 = i['mask']
            self.configured = True
            self.set_body(self.overview())
            self.run_live()
            
    def select6_callback(self, button, index):
        self.ip6 = self.devices[self.interface]['ip6'][index]['ip']
        self.mask6 = self.devices[self.interface]['ip6'][index]['mask']
        self.configured = True
        self.set_body(self.overview())
        self.run_live()

    def open_file(self, button):
        if self.configured or not self.filename is None:
            self.close()
        footer_text = [
            ('title', "Directory Browser"), "   ",
            ('key', "UP"), ",", ('key', "DOWN"), ",",
            ('key', "PAGE UP"), ",", ('key', "PAGE DOWN"), "  ",
            ('key', "SPACE"), "  ",
            ('key', "+"), ",",
            ('key', "-"), "  ",
            ('key', "LEFT"), "  ",
            ('key', "HOME"), "  ", 
            ('key', "END"), "  ",
            ('key', "Q"),
            ]
        cwd = os.getcwd()
        store_initial_cwd(cwd)
        header = urwid.Text("Open File")
        listbox = urwid.TreeListBox(urwid.TreeWalker(self.DirectoryNode(cwd)))
        listbox.offset_rows = 1
        footer = urwid.AttrWrap(urwid.Text(footer_text), 'foot')
        view = self.DirectoryBrowser(
            self.open_file_callback,
            urwid.AttrWrap(listbox, 'body'), 
            header=urwid.AttrWrap(header, 'head'), 
            footer=footer)
        self.set_body(view)
        
    def open_file_callback(self, files):
        self.set_body(self.overview())
        if len(files) > 0:
            self.filename = files[0]
            self.run_file(self.filename)
    
    def close(self):
        if self.configured:
            for i in self.modules:
                (mod, en) = self.modules[i]
                mod.shut_mod()
            if self.pcap_thread:
                self.pcap_thread.quit()
                self.pcap_thread = None
            if self.dnet_thread:
                self.dnet_thread.quit()
                self.dnet_thread = None
            self.configured = False
        elif not self.filename is None:
            for i in self.modules:
                (mod, en) = self.modules[i]
                mod.shut_mod()
            if self.pcap_thread:
                self.pcap_thread.quit()
                self.pcap_thread = None
            self.filename = None
    
    def show_overview(self, button):
        self.set_body(self.overview())
    
    def overview(self):
        text = "This is %s version %s by Daniel Mende - dmende@ernw.de\nRunning on %s" % (self.__class__.__name__, VERSION, PLATFORM)
        text = urwid.Text(text, 'center')
        text = urwid.AttrMap(text, 'header')
        text = urwid.LineBox(text)
        text = urwid.Filler(text, top=3, bottom=3)
        text = urwid.BoxAdapter(text, 7)
        text2 = "Press 'tab' for menu"
        if self.configured:      
            text2 += "\n\nUsing interface %s\n\n" % self.interface
            text2 += "IPv4:\n%s/%d\n\nIPv6:\n%s/%d" % (self.ip, len(IPy.IP(self.mask).strBin().replace("0", "")), self.ip6, len(IPy.IP(self.mask6).strBin().replace("0", "")))
            if self.ip6 != self.ip6_ll:
                text2 += "\n%s/%d" % (self.ip6_ll, len(IPy.IP(self.mask6_ll).strBin().replace("0", "")))
        elif not self.filename is None:
            text2 += "\n\nReading file %s" % self.filename
        text2 = urwid.Text(text2, 'center')
        return urwid.AttrMap(urwid.ListBox(urwid.SimpleListWalker([text, text2])), 'body')
    
    def run_live(self):
        assert(self.configured)
        self.pcap_thread = loki.pcap_thread(self, self.interface)
        self.dnet_thread = loki.dnet_thread(self.interface)
        self.log("Listening on %s" % (self.interface))
        if PLATFORM != "Linux":
            self.fw = dnet.fw()
        for i in self.modules:
            self.start_module(i)
        self.dnet_thread.start()
        self.pcap_thread.start()
    
    def run_file(self, filename):
        self.pcap_thread = loki.pcap_thread_offline(self, filename)
        self.interface = "null"
        self.ip = "0.0.0.0"
        self.mask = "0.0.0.0"
        self.ip6 = "::"
        self.mask6 = "::"
        self.ip6_ll = "::"
        self.mask6_ll = "::"
        for i in self.modules:
            self.start_module(i)
        self.pcap_thread.start()
    
    def load_all_modules(self, path=loki.DATA_DIR + loki.MODULE_PATH):
        loki.codename_loki.load_all_modules(self, path)
        for i in self.modules.keys():
            if not "get_urw" in dir(self.modules[i][0]):
                del self.modules[i]
    
    def init_module_ui(self, mod):
        self.modules_ui[mod.name] = urwid.Frame(urwid.AttrMap(mod.get_urw(), 'body'), header=urwid.AttrMap(urwid.Text(mod.name.upper(), 'center'), 'title'))

    def log(self, msg, module=None):
        msg = "[%i] %s" % (self.msg_id, msg)
        self.statusbar.set_text(msg)
        self._print(msg)
        self.msg_id += 1
    
    def _print(self, msg):
        if not self.logfd.closed:
            self.logfd.write(str(msg) + "\n")
            self.logfd.flush()

    def quit(self, button, data=None):
        self.shutdown()
        self.logfd.close()
        raise urwid.ExitMainLoop()
            
if __name__ == '__main__':
    app = loki_urw()
    loki.pcap = app.check()
    signal.signal(signal.SIGINT, app.quit)
    try:
        app.main()
    except Exception, e:
        app._print(e)
        if loki.DEBUG:
            app._print('-'*60)
            app._print(traceback.format_exc())
            app._print('-'*60)
        app.shutdown()
    except:
        app.shutdown()
