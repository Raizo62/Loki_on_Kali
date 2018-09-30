# Loki_on_Kali
Packages to install Loki on Kali Linux. Loki is a python based infrastructure pentesting tool focussing on layer 3 protocols.

# Installation

## Install needed packages
* with apt :

```
apt install multiarch-support # needed by libssl1.0.0
apt install python-libpcap python-dpkt python-dumbnet python-glade2
```

* with local packages :
```
dpkg -i Needed_Packages_For_kali-linux-2018.3-amd64/*.deb
```

## Install needed old packages
`dpkg -i Needed_Old_Packages/*.deb`

## Install Loki
`dpkg -i loki_0.2.7-2_amd64.deb`
