CLI Tool
========

The nbroker-cli CLI tool can be used to setup a communication over ZMQ with the nbroker daemon in order to control it. Running nbroker-cli you get a prompt where you can issue commands in text format with autocompletion.

.. code-block:: console

   $ nbroker-cli
   tcp://127.0.0.1:5555>

Below you can find the list of supported commands, for an updated list please check the nbroker-cli help:

- default port PORT pass|drop
- set port PORT match FILTER pass|drop|steer-to [PORT]
- delete port PORT filtering|steering match FILTER
- delete port PORT filtering|steering rule ID
- clear port PORT filtering|steering
- rules port PORT filtering|steering
- gc idle-for SECONDS
- help
- quit

In general, a command is composed by an action (e.g. "set") followed by parameters. Each parameter is composed by an identifier (e.g. "match") and a value (e.g. "shost 10.0.0.1"). The parameters can appear in any order. Some parameters are mandatory, whereas others are optional.

Cammand examples:

- "default port ens9 pass" - set a pass all default
- "default port ens9 drop" - set a drop all default
- "default port 4 drop" - same as above, but using port index
- "set port ens9 match shost 10.0.0.1 drop" - set a rule to drop source host 10.0.0.1 traffic
- "set port ens9 match dport 80 steer-to enp1s0f1" - set a steering rule for traffic matching destination port 80
- "set port ens9 rule 1 match dport 80 steer-to enp1s0f1" - same as above, but provide a rule id. Possibly override existing rule
- "delete port ens9 filtering match shost 10.0.0.1" - delete a previously set filtering rule
- "delete port ens9 steering match dport 80" - delete a previously set steering rule
- "delete port ens9 steering rule 1" - delete a steering rule by using its id
- "clear port ens9 filtering" - delete all the filtering rules
- "rules port 1 filtering" - list all the active filtering rules
- "gc idle-for 60" - delete rules which have been set more than 60 seconds ago

Syntax supported by the "match" option:

- "smac 11:22:33:44:55:66" - a source MAC
- "dmac 11:22:33:44:55:66" - a destination MAC
- "shost 10.0.0.1" - a single source host
- "dhost 10.0.0.1" - a single destination host
- "shost 10.0.0.0/24" - a group of source hosts specified by the network CIDR
- "shost 10.0.0.0 netmask 255.255.255.0" - same as above, explicit netmask
- "shost 2001:db8::2:1" - IPv6 addresses are supported
- "sport 80" - source port 80
- "dport 443" - destination port 443
- "sport portrang 1-1023" - any source port in range 1-1023, *if supported*
- "vlan 1"
- "proto tcp" - L3 protocol by name
- "proto 6" - protocol by number

Multiple values can be specified into the match value to compose a logic *and* filter. 

Example:

- "set port ens9 match sport 80 dport 1234 drop" - set a rule to drop source port 80 *and* destination port 1234

When issuing a command, the result output is composed by a status code and an explanatory message, a few examples:

- 0 OK
- 4 Invalid device port
- 8 Error while setting the command on the device
