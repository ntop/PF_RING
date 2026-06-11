#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2017 - 2025 Intel Corporation
#
# Collect system, OS, driver, and NIC details for Intel support.
# Summarizes PF/VF info, firmware, and environment for troubleshooting.
#
# typical usage is (as root):
# pf=ethX sutinfo.sh

[ -z $pf ] || pf_mod="$(ethtool -i $pf | awk '/driver/ { print $2}')"			# if $pf given take driver name from net interface
pf_mod="${pf_mod:-i40e}"								# or by default i40e&iavf
vf_mod="${vf_mod:-iavf}"
[ "$pf_mod" = 'igb' ] && vf_mod='igbvf'
[ "$pf_mod" = 'ixgbe' ] && vf_mod='ixgbevf'

distro="$(lsb_release -ds 2>/dev/null|| awk -F= '$1=="PRETTY_NAME" { print $2 ;}' /etc/os-release || uname -om)"
distro="$distro $(uname -r)"

echo "HOST: $(hostname)@$(ip route get 1 | awk '{print $7;exit}')"
echo "H/W:"
echo "  ID: $(dmidecode | grep -w UUID | sed 's/^.UUID\: //g')"
dmidecode  | grep -A2 "System Information" | tail -2 | cut -f2 | sed 's/^/  /'
free | awk '/Mem/ {  printf("  RAM: [%.0fG/%.0fG/%.0fG]\n",  $2/1048576, $3/1048576, $4/1048576); }'
echo "  CPU:$(grep 'model name' /proc/cpuinfo|head -1|cut -d: -f2) [$(getconf _NPROCESSORS_CONF)/$(getconf _NPROCESSORS_ONLN)]"
pf="${pf:-$(grep $pf_pci /sys/class/net/*/device/uevent | cut -d/ -f5)}"
if [[ "" != "$pf" ]] && [[ -f  /sys/class/net/$pf/address ]] ; then
	d="/sys/class/net/$pf/device"
	r=""
	if [ -f $d/revision ] ; then
		r="$(<$d/revision)"
	fi
	bus="$(ethtool -i $pf | awk '/^bus-info:/ { print $2; }')"
	echo "  PF bus-info: $bus $(<$d/vendor):$(<$d/device) $(<$d/subsystem_vendor):$(<$d/subsystem_device) ($r) #$(lspci -s $bus -nn| sed -e 's/Ethernet controller //')"
fi
if [[ -d /sys/class/net/$pf/device/virtfn0/net ]] ; then
	vf="${vf:-$(ls /sys/class/net/$pf/device/virtfn0/net)}"
fi
if [[ "" != "$vf" ]] && [[ -f  /sys/class/net/$vf/address ]] ; then
	d="/sys/class/net/$vf/device"
	r=""
	if [ -f $d/revision ] ; then
		r="$(<$d/revision)"
	fi
	bus="$(ethtool -i $vf | awk '/^bus-info:/ { print $2; }')"
	echo "  VF bus-info: $bus $(<$d/vendor):$(<$d/device) $(<$d/subsystem_vendor):$(<$d/subsystem_device) ($r) #$(lspci -s $bus -nn | sed -e 's/Ethernet controller //')"
fi

echo "S/W:"
echo "   OS: $distro"
echo "  CMD: $(cat /proc/cmdline)"
echo "  GCC: $((gcc --version 2>/dev/null|| echo =not installed=)|head -1)"
echo "  ETH: $((ethtool --version 2>/dev/null|| echo =not installed=)|head -1)"
echo "   TC: $(tc -V 2>/dev/null | head -1 || echo =not installed=)"
if [[ "" != "$pf" ]] && [[ -f  /sys/class/net/$pf/address ]] ; then
	echo "  FW $(ethtool -i $pf | grep ^firmware-version\:)"
	echo "  PF $(ethtool -i $pf | grep ^version\:)"
else
	echo "  FW unknown"
	echo "  PF $(modinfo $pf_mod   | grep ^version\:)"
fi

if [[ "" != "$vf" ]] && [[ -f  /sys/class/net/$vf/address ]] ; then
	echo "  VF $(ethtool -i $vf | grep ^version\:)"
else
	echo "  VF $(modinfo $vf_mod | grep ^version\:)"
fi
if modinfo auxiliary >/dev/null 2>&1 ; then
	echo "  AUX $(modinfo auxiliary | grep ^srcversion\:)"
fi

