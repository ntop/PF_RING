# ADQ Setup Tool

_SPDX-License-Identifier: BSD-3-Clause_  
_Copyright (c) 2022, Intel Corporation_  

**Dependencies:** _Python 2.7-3.10_

**Distro Support:**
* Redhat: _7.1-8.x_
* Fedora: _25-35_
* Ubuntu: _18.04-21.04_
* Debian: _11_
* Others: _???_


## Installation

Python Package Index (pip):

    python -m pip install adqsetup

Included with driver:

    python scripts/adqsetup/adqsetup.py install

## Configuration Parameters

### Global
- **arpfilter**: (bool) _Enable selective ARP activity_
- **bpstop**: (bool) _Channel-packet-clean-bp-stop feature_
- **bpstop-cfg**: (bool) _Channel-packet-clean-bp-stop-cfg feature_
- **busypoll**: (integer) _busy_poll value_
- **busyread**: (integer) _busy_read value_
- **cpus**: (integer list|'auto') _CPUs to use for handling 'default' 
traffic, default 'auto'_
- **numa**: (integer|'local'|'remote'|'all') _Numa node to use for 'default' 
traffic, default 'all' (prefer local)_
- **dev**: (string) _Network interface device to configure_
- **optimize**: (bool) _Channel-inspect-optimize feature_
- **priority**: ('skbedit') _Method to use for setting socket priority, default none_
- **queues**: (integer) _Number of queues in 'default' traffic class, default 2_
- **txring**: (integer) _Transmit ring buffer size_
- **txadapt**: (bool) _Adaptive transmit interrupt coalescing_
- **txusecs**: (integer) _Usecs for transmit interrupt coalescing_
- **rxring**: (integer) _Receive ring buffer size_
- **rxadapt**: (bool) _Adaptive receive interrupt coalescing_
- **rxusecs**: (integer) _Usecs for receive interrupt coalescing_

### User-defined Class (for each traffic class created)
- **mode**: ('exclusive'|'shared') _Mode for traffic class_
- **queues**: (integer) _Number of queues in traffic class_
- **pollers**: (integer) _Number of independent pollers, default 0_
- **poller-timeout**: (integer) _Independent poller timeout value, 
default 10000_
- **protocol**: ('tcp'|'udp') _IP Protocol of traffic_
- **ports**: (integer list) _Local IP ports of traffic_
- **addrs**: (string list) _Local IP address of traffic_
- **remote-ports**: (integer list) _Remote IP ports of traffic_
- **remote-addrs**: (string list) _Remote IP address of traffic_
- **cpus**: (integer list|'auto') _CPUs to use for handling traffic, 
default 'auto'_
- **numa**: (integer|'local'|'remote'|'all') _Numa node to use for traffic, 
default 'all' (prefer local)_

## Usage

The basic usage is: `adqsetup [options] <command> [parameters ...]`  

### Commands
- **help**: _Show help message_
- **examples**: _Creates an 'examples' subdirectory containing a set of 
example config files in the current directory._
- **apply**: _Apply a config file_
  - **[filename]**: (string) _Filename (relative or full path). If empty 
  or '-', read config file from stdin._
- **create**: _Create a 'quick-config' consisting of one traffic class._
  - **[name]**: (string) _User-defined name of traffic class. 
  'globals' and 'default' names are reserved and not allowed._
  - **[key]** **[value]**: (string, string) _One or more space-seperated 
  key and value pairs. See the above Class Configuration Parameter list for 
  possible keys and values._
- **reset**: _Remove ADQ traffic classes and filters. Does not reset any
global options._
- **persist**: _Persists a config file across reboots using a systemd 
service unit. One config per network interface, new configs overwrite old ones._
  - **[filename]**: (string) _Filename (relative or full path). If empty 
  or '-', read config file from stdin._
- **install**: _Installs the adqsetup script as a system-wide command 
on the PATH._

Global configuration parameters can be specified with the matching 
`--<key> <value>` command line option, and when using the `create` 
command class configuration parameters are specified with one or more 
`<key> <value>` pairs after the user-defined class name.


## Sample Usage

    adqsetup help
    adqsetup examples

    adqsetup apply memcached.conf
    adqsetup --dev=eth4 apply nginx.conf
    adqsetup --dev=eth3 persist eth3.conf

    cat memcached.conf | adqsetup apply

    adqsetup --dev=eth4 --priority=skbedit create myapp \
        queues 8 ports 11211
    adqsetup --dev=eth4 --priority=skbedit create myapp mode shared \
        queues 8 ports 11211-11218


## Sample Usage With Pipes From Bash Script

    #!/bin/bash 
    
    QUEUES=8

    for BP in {10000..50000..5000}; do 
    adqsetup --dev=eth4 apply <<EOF
        [globals]
        busypoll=$BP
        [nginx]
        queues=$QUEUES
        ports=80
    EOF
    ./run_test.sh
    done


## Common Issues

If you get a `/usr/bin/env: ‘python’: No such file or directory` error 
when you run the script, please install Python. If you have already installed 
Python, then try `whereis python` and you should see a message like: 
`python: /usr/bin/python2.7 /usr/bin/python3.6 /usr/bin/python3.6m /usr/bin/python3.9` 
on the first line of the output. Either run the version you wish to use 
manually: `python3.6 adqsetup.py help`, or create a 'python' symbolic 
link on the path: `ln -s /usr/bin/python3.6 /usr/local/bin/python`

When using the `pollers` feature, if your driver does **not** have 
independent poller support, you will see the following error:

    ** Setting independent poller **
    devlink answers: Invalid argument

## Other Issues

Please run the malfunctioning config with the command line `--debug` option, 
which should include a short stack trace at the end of the output. Send the 
configuration file (if used), full commmand line, and output to your Intel 
support contact.