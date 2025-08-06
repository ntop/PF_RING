# adqsetup

_SPDX-License-Identifier: BSD-3-Clause_  
_Copyright (c) 2022, Intel Corporation_  

**Dependencies:** _Python 2.7-3.10_

**Distro Support:**
* Redhat: _7.1-9.x_
* Fedora: _28-35_
* Ubuntu: _19.04-22.04_
* Debian: _11_

## Installation

Python Package Index (pip):

    python -m pip install adqsetup

Included with driver:

    python scripts/adqsetup/adqsetup.py install

## Usage

The basic usage is: `adqsetup [options] <command> [parameters ...]`  
Please see the output of `adqsetup help` for a complete list of 
command line options.

### Commands
- **help**: _Show help message_
- **examples**: _Create an 'examples' subdirectory_  
  The examples subdirectory - created in the current directory - 
  contains a set of sample config files
- **apply {filename}**: _Apply a config file_
  - **{filename}**: _Config file (relative or full path)_  
    If empty or '-', config file is read from stdin.
- **create { [{name}] { {key} {value} }... }...**: _Create a config from the command line_  
    Each section consisting of a bracketed name and one or more {key} {value} pairs.
    - **[{name}]**: _User-defined name of section_  
      Must be unique within a configuration, '[globals]' is reserved but can be used.
    - **{key}** **{value}**: _Configuration Parameter_  
    One or more space-seperated key and value pairs. 
    See the above Class Configuration Parameter list for possible keys and values.
- **reset**: _Remove ADQ traffic classes and filters_  
  Attempts to perform a cleanup of any ADQ-related setup. 
  Note: '--priority=skbedit' option must be included to remove the egress filters.
- **persist {filename}**: _Persist a config file across reboots_  
  Creates a systemd service unit set to run once on boot after the network is running. 
  One config per network interface, new configs overwrite old ones.
  - **{filename}**: _Config file (relative or full path)_  
    If empty or '-', config file is read from stdin.
- **install**: _Install the adqsetup script_  
  Installs the current script at /usr/local/bin

## Configuration Parameters

### Globals Section
- **arpfilter**: (bool) _Enable selective ARP activity_
- **bpstop**: (bool) _Channel-packet-clean-bp-stop feature_
- **bpstop-cfg**: (bool) _Channel-packet-clean-bp-stop-cfg feature_
- **busypoll**: (integer) _busy_poll value_
- **busyread**: (integer) _busy_read value_
- **cpus**: (integer list|'auto') _CPUs to use for handling 'default' 
traffic, default 'auto'_
- **min-rate**: (integer) _minimum rate for bandwidth shaping (in Mb/s)_
- **max-rate**: (integer) _maximum rate for bandwidth shaping (in Mb/s)_
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

### User-defined Section (for each application or traffic class)
- **addrs**: (string list) _Local IP addresses of traffic_
- **cpus**: (integer list|'auto') _CPUs to use for handling traffic, 
default 'auto'_
- **mac**: (string) _Local MAC addresses of traffic_
- **mode**: ('exclusive'|'shared') _Mode for traffic class_
- **min-rate**: (integer) _minimum rate for bandwidth shaping (in Mb/s)_
- **max-rate**: (integer) _maximum rate for bandwidth shaping (in Mb/s)_
- **numa**: (integer|'local'|'remote'|'all') _Numa node to use for traffic, 
default 'all' (prefer local)_
- **pollers**: (integer) _Number of independent pollers, default 0_
- **poller-timeout**: (integer) _Independent poller timeout value, 
default 10000_
- **ports**: (integer list) _Local IP ports of traffic_
- **protocol**: ('tcp'|'udp') _IP Protocol of traffic_
- **queues**: (integer) _Number of queues in traffic class_
- **remote-addrs**: (string list) _Remote IP addresses of traffic_
- **remote-ports**: (integer list) _Remote IP ports of traffic_

## Sample Usage

    adqsetup help
    adqsetup examples

    adqsetup apply memcached.conf
    adqsetup --dev=eth4 apply nginx.conf
    adqsetup --dev=eth3 persist eth3.conf

    cat memcached.conf | adqsetup apply

    adqsetup create [myapp] queues 4 ports 11211

    adqsetup --verbose create \
      [globals] priority skbedit \
      [myapp] queues 2 ports 11211

    adqsetup --verbose create \
      [app1] mode shared queues 4 ports 6379-6382
      [app2] queues 2 ports 11211 pollers 2

## Sample Usage Bash Script

    #!/bin/bash 
    QUEUES=8
    # this will loop through a range
    # of busy_poll values
    for BP in {10000..50000..5000}; do 
        adqsetup create [globals] busypoll $BP [nginx] queues $QUEUES ports 80
        # run test here
    done

## Sample Usage With Pipes From Bash Script

    #!/bin/bash 
    QUEUES=8
    # this will loop through a range
    # of busy_poll values
    for BP in {10000..20000..5000}; do 
    adqsetup apply <<EOF
        [globals]
        dev=eth2
        busypoll=$BP
        [nginx]
        queues=$QUEUES
        ports=80
    EOF
    # run test here
    done

## Sample Usage With Pipes From External Script

    python makeconf.py | adqsetup --json apply

### makeconf.py

    import json
    conf = {
        "globals": {
            "dev": "eth2",
            "busypull": 10000
        },
        "app1": {
            "queues": 4,
            "ports": "80,443"
        }
    }
    print(json.dumps(conf))

## Notes

* To load/use a different device driver while creating the setup, 
the `--driver` parameter may be used. Device driver path is the full path 
to the .ko file (ex: ice-1.9.x/src/ice.ko). Interface _must_ be set to 
come up automatically with an ip address (via NetworkManager or other). 
adqsetup will wait up to three seconds for this to occur before erroring out. 
Conversely, you can load the driver and setup the interface manually 
before running the adqsetup.

* The independent **pollers** argument passed to adqsetup doesn’t map directly 
to the **qps_per_poller** arguments passed to the driver. adqsetup 
allows the user to specify how many pollers for a particular TC instead of 
having to specify qps_per_poller.

* adqsetup 1.x required updated versions of the 'tc', 'ethtool', and 'devlink' 
commands to be installed on the system. With adqsetup 2.x and onward, this 
requirement has been removed.

## Common Issues

* If you get a `/usr/bin/env: ‘python’: No such file or directory` error 
when you run the script, please install Python. If you have already installed 
Python, then try `whereis python` and you should see a message like: 
`python: /usr/bin/python2.7 /usr/bin/python3.6 /usr/bin/python3.6m /usr/bin/python3.9` 
on the first line of the output. Either run the version you wish to use 
manually: `python3.6 adqsetup.py help`, or create a 'python' symbolic 
link on the path: `ln -s /usr/bin/python3.6 /usr/local/bin/python`

* Many advanced features, such as **pollers** and the per-tc flow director may 
not be supported by older versions of the driver or kernel. adqsetup 
will attempt to use an equivalent fallback feature, and if none are available 
a descriptive error will be provided. Please refer to the ADQ Config Guide for
more information.

## Other Issues

Please run the malfunctioning config with the command line `--debug` option, 
which should include a short stack trace at the end of the output. Send the 
configuration file (if used), full commmand line, and program output to your 
Intel support contact.

## JSON Support

adqsetup accepts configurations in the JSON format from either a file or stdin 
with the `--json` option. Parameters are the same as listed above, using the 
following basic structure:

    {
        "globals": {
            "dev": "eth4",
            "priority": "skbedit"
        },
        "app1": {
            "queues": 2,
            "ports": 11211
        },
        "app2": {
            "queues": 4,
            "mode": "shared",
            "ports": "6379-6382"
        }
    }

