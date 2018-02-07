#!/bin/sh

#
# Remove all installed ZC and pfring dkms modules
#
# IMPORTANT NOTE
# BEFORE running this script, make sure there are no ZC/PF_RING packages installed
#

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

dkms status | grep -e "-zc" -e "pfring" | sed -e "s/:/,/g" | sed -e "s/ //g" | awk '{split($0,a,","); print "dkms remove", a[1]"/"a[2], "--all"}' > /tmp/purge_dkms_todo.sh

#cat /tmp/purge_dkms_todo.sh

bash -x /tmp/purge_dkms_todo.sh

/bin/rm -f /tmp/purge_dkms_todo.sh

