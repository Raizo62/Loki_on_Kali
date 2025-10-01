#/bin/bash

LOKI_FILE="loki_0.3.0-r502-5_amd64.deb"

APT_FLAGS="-q -y --no-install-recommends"
DEBIAN_FRONTEND=noninteractive

echo "* Stretch Debian : apt uses archived repository"
cat > /etc/apt/sources.list <<EOF
deb http://archive.debian.org/debian/ stretch main contrib non-free
deb http://archive.debian.org/debian/ stretch-proposed-updates main contrib non-free
deb http://archive.debian.org/debian-security stretch/updates main contrib non-free
EOF

echo "* Install dependency"
install_packages \
	libdumbnet1 python-libpcap python-gtk2 python-dpkt python-dumbnet python-ipy python-glade2 python-urwid \
	iptables ebtables bridge-utils \
	ifupdown \
	wget

echo "* Get ${LOKI_FILE}"
wget --quiet --no-check-certificate https://github.com/Raizo62/Loki_on_Kali/raw/master/${LOKI_FILE}
echo "* Install ${LOKI_FILE}"
dpkg -i ${LOKI_FILE}

echo "* Configure loki"

# used by loki :
mkdir -p /root/.local/share
mkdir -p /root/.loki

# update file with mac vendor :
wget --quiet --no-check-certificate https://github.com/wireshark/wireshark/raw/master/manuf -O mac_vendor.txt
grep --extended-regexp --ignore-case '^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}[[:space:]]' mac_vendor.txt | awk '{print $1 " " $2}' | tr ':' '-' > /usr/share/loki/modules/mac.txt
rm mac_vendor.txt

echo "* Cleaning"

# remove unnecessary :
rm ./${LOKI_FILE}
apt-get ${APT_FLAGS} purge wget

# clean :
apt-get ${APT_FLAGS} autoremove
apt-get ${APT_FLAGS} clean
rm -r /var/cache/apt/archives
find /var/log/ -type f -exec truncate -s 0 \{\} \;
# last clean :
rm $(basename $0)
