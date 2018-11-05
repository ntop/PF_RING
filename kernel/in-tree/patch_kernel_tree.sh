#!/bin/bash

# Copy pf_ring source and headers into kernel tree
# Apply diff to relevant configuration files for in-tree builds
# Configure KDIR to your source tree and run this script


KDIR="/usr/src/linux"
DIFFDIR="$(cd $( dirname "${BASH_SOURCE[0]}") && pwd )"
echo "Patching kernel in $KDIR from $DIFFDIR"

if [[ ! -d "$KDIR" ]]; then
  echo "KDIR improperly set"
  exit 1
else
  if [[ ! -f "$KDIR/Kconfig" ]]; then
    echo "$KDIR does not appear to be a kernel tree"
    exit 1
  fi

  cd "$DIFFDIR"
  mkdir "$KDIR/net/pf_ring"
  cp ../pf_ring.c "$KDIR/net/pf_ring"
  cp ../linux/pf_ring.h "$KDIR/include/linux"
  
  cd "$KDIR"
  if [[  $(patch -p1 -i "$DIFFDIR/build-config.diff") ]]; then
    echo "Update kernel build configuration to enable PF_RING module"
    exit 0
  else
    echo "Failed to patch kernel tree, review output and PR a fix please"
    exit 1
  fi
fi

