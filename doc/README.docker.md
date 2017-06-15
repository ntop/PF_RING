# Using PF_RING with Docker
This guide shows how to run packet processing applications based on PF_RING or
PF_RING ZC inside Docker containers in a few simple steps.

For an overview about the Docker networking support and configuration please refer 
to the Docker documentation (https://docs.docker.com/v1.7/articles/networking/).

As first step build the Docker image using the Dockerfile below, in this example
based on Ubuntu 14.

```
sudo docker build -t ubuntu14 -f Dockerfile.ubuntu14 .
```

Please note the Dockerfile is running the needed steps for installing the ntop
repository, installing pfring, and setting the simple-entrypoint.sh script as
entrypoint, in order to let us commands running the Docker image from command 
line.

Dockerfile.ubuntu14
```
FROM ubuntu:14.04
MAINTAINER ntop.org

RUN apt-get update && \
    apt-get -y -q install wget lsb-release && \
    wget -q http://apt.ntop.org/14.04/all/apt-ntop.deb && \
    dpkg -i apt-ntop.deb && \
    rm -f apt-ntop.deb && \
    apt-get clean all && \
    apt-get update

RUN apt-get -y install pfring

COPY simple-entrypoint.sh /tmp
ENTRYPOINT ["/tmp/simple-entrypoint.sh"]
```

simple-entrypoint.sh
```
#!/bin/bash
set -e
exec "$@"
```

At this point it is possible to test pf_ring using pfcount as sample application.
Please note thet the pf_ring.ko kernel module must be loaded on the host machine,
and that we need to set the proper capabilities using "--cap-add" in order to work 
with pf_ring.

```
sudo docker run --cap-add net_raw --cap-add net_admin ubuntu14 pfcount -i eth0
```

An application running inside a docker container is able to capture traffic from the
interfaces visible inside the container only. If you want to capture traffic from an 
interface in the host system network namespace you should run socker with "--network=host".

When working with PF_RING ZC, using for instance zbalance_ipc for forwarding traffic
to consumer applications running inside Docker containers by means of ZC queues, we
need to bind the hugetlb mountpoint inside the container using "run -v" and set the
proper capabilities.

```
sudo docker run -v /dev/hugepages:/dev/hugepages --cap-add net_raw --cap-add net_admin --cap-add ipc_lock ubuntu14 pfcount -i zc:99@0
```

