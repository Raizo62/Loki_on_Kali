# Loki_on_Kali
Packages to install Loki on Kali Linux / Parrot-OS. Loki is a python based infrastructure pentesting tool focussing on layer 3 protocols.

# Installation

## Install dependencies
## Install needed old packages
`dpkg -i Needed_Old_Packages/*.deb`

### With apt

* Create a temporary source list :
```
/usr/bin/cat << EOF | sudo tee /etc/apt/sources.list.d/loki_tmp_qXgv80VVlRK8.list > /dev/null
deb http://deb.debian.org/debian/ buster main
deb http://deb.debian.org/debian-security/ buster/updates main
deb http://deb.debian.org/debian/ buster-updates main

deb http://deb.debian.org/debian/ bullseye main
deb http://deb.debian.org/debian/ bullseye-updates main
EOF
```

* Update :

`sudo apt-get update`

* Install dependency :

`sudo apt-get install libdumbnet1 python-libpcap python-gtk2 python-dpkt python-dumbnet python-ipy python-glade2 python-urwid`

* Remove the temporary source list :

```
sudo rm /etc/apt/sources.list.d/loki_tmp_qXgv80VVlRK8.list
sudo apt-get update
```

* with local packages :
```
dpkg -i Local_Packages/*.deb
```

## Install Loki
`dpkg -i loki_0.3.0-r502-3_amd64.deb`

# Play
```
loki_gtk.py
```
or
```
loki_urw.py
```
