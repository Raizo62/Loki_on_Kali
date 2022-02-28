#!/bin/bash

for package in $(cat list_of_ordered_packages.txt)
do
	PKG_OK=$(dpkg-query -W --showformat='${Status}\n' ${package} 2>/dev/null | grep 'install ok installed')
	if [ -z "${PKG_OK}" ]
	then
		sudo dpkg -i packages/${package}_*.deb
	fi
done
