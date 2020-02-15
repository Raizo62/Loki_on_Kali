# Loki_on_Kali
Packages to install Loki on Kali Linux. Loki is a python based infrastructure pentesting tool focussing on layer 3 protocols.

# Installation

## Install needed old packages
`dpkg -i Needed_Old_Packages/*.deb`

## Install needed packages
* with apt :

```
apt install python-dpkt libdumbnet1 python-urwid python-glade2 libglade2-0
```

* with local packages :
```
dpkg -i Local_Packages/*.deb
```

## Install Loki
`dpkg -i loki_0.3.0-r502-2_amd64.deb`

## Patchs
* OSPF Bug : Ref [#2](https://github.com/Raizo62/Loki_on_Kali/issues/2)
```
sed -i '948s/10/1/' /usr/share/loki/modules/module_ospf.py
```

# Play
```
loki_gtk.py
```
or
```
loki_urw.py
```
