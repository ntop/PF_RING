#!/bin/bash

PF_RING_VERSION=7.2.0-stable
COREOS_VERSION=$(cat /etc/os-release | grep VERSION= | cut -d= -f2)

echo "> Building.."

docker build \
  --build-arg COREOS_VERSION=$COREOS_VERSION \
  --build-arg PF_RING_VERSION=$PF_RING_VERSION \
  -t coreos-builder .

echo "> Running.."

docker run -v /:/rootfs --privileged=true -i -t coreos-builder

