#!/bin/sh

wget -O - http://standards.ieee.org/develop/regauth/oui/oui.txt | grep "(hex)" | awk '{ $2=""; print }' > mac.txt

