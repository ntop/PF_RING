Using PF_RING with Docker
=========================

This guide shows how to run packet processing applications based on PF_RING or
PF_RING ZC inside Docker containers in a few simple steps.

For an overview about the Docker networking support and configuration please refer 
to the Docker documentation (https://docs.docker.com/v1.7/articles/networking/).

As first step build the Docker image using the Dockerfile below, in this example
based on Ubuntu 16.

.. code-block:: console

  sudo docker build -t ubuntu16 -f Dockerfile.ubuntu16 .

Please note the Dockerfile is running the needed steps for installing the ntop
repository, installing pfring, and setting the simple-entrypoint.sh script as
entrypoint, in order to let us commands running the Docker image from command 
line.

Dockerfile.ubuntu16

.. code-block:: console

   FROM ubuntu:16.04
   MAINTAINER ntop.org
   
   RUN apt-get update && \
       apt-get -y -q install wget lsb-release gnupg && \
       wget -q http://apt.ntop.org/16.04/all/apt-ntop.deb && dpkg -i apt-ntop.deb && \
       apt-get clean all && \
       apt-get update && \
       apt-get -y install pfring
   
   COPY simple-entrypoint.sh /tmp
   ENTRYPOINT ["/tmp/simple-entrypoint.sh"]

simple-entrypoint.sh

.. code-block:: console

   #!/bin/bash
   set -e
   exec "$@"

At this point it is possible to test pf_ring using pfcount as sample application.
Please note that the pf_ring.ko kernel module must be loaded on the host machine,
and that we need to set the proper capabilities using "--cap-add" in order to work 
with pf_ring.

.. code-block:: console

   sudo docker run ubuntu16 pfcount -i eth0

Note: since PF_RING 7.1 and kernel 3.8 "--cap-add net_admin" is no longer needed.
An application running inside a docker container is able to capture traffic from the
interfaces visible inside the container only. If you want to capture traffic from an 
interface in the host network namespace you should run docker with "--network=host".

.. code-block:: console

   sudo docker run --network=host ubuntu16 pfcount -i eth0

When working with PF_RING ZC, using for instance zbalance_ipc for forwarding traffic
to consumer applications running inside Docker containers by means of ZC queues, we
need to bind the hugetlb mountpoint inside the container using "-v" and set the
proper capabilities.

.. code-block:: console

   sudo docker run -v /dev/hugepages:/dev/hugepages --cap-add ipc_lock ubuntu16 pfcount -i zc:99@0

