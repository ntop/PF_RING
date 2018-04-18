nBrokerd Daemon
===============

The nbrokerd daemon provides a client-server pattern to communicate with the RRC physical device. Multiple clients can connect to the daemon at the same time to set rules on the RRC device.

To overcome the limited number of rules supported by the device, the daemon is optimized to support rules deduplication.

The daemon supports two communication modes:

- text: commands are exchanged in string format, making this mode suitable for manual user interaction and debugging.
- binary: commands are exchanged in binary format.

Please note taht there is some difference in the supported features between the two modes: text mode supports a subset of the full features list.

The daemon can be started running "nbrokerd". Please note it requires root privileges to drive the RRC switch.

Basic Knowledge
---------------

The RRC device has an internal switch that can be configured to apply policies on the traffic. The switch has internal (those seen by the host OS) and external (connected to the physical cables) ports, in a typical configuration 2 external ports and 2 internal ports. It supports two kind of policies:

- egress filtering, affecting packets *going out* a switch port, with the ability to set 'pass' or 'drop' rules.
- ingress steering, affecting packets *coming in* a switch port, with the ability to set 'forward' rules for steering packets to a secondary port, either internal or external, of the switch.

In order to simulate a typical network card, upon initialization the daemon binds the internal ports to the external ports by means of default steering policies. This way, the traffic coming from or going to the physical ports can reach the host OS.

For each port, the filtering and steering rules are handled differently by the device. The tuple <port, filter_type> defines the context of a specified rule, where filter_type is of of "steering" or "filtering".

A *rule* is a simple <match, policy> tuple. It specifies what policy to apply on traffic matching the specified fields. A rule is identified, whithin the <port, filter_type> context, thorugh a rule id number. The daemon is able to handle rule ids automatically and to avoid duplicate rules, although the user has the possibility to override its behaviour using specific rule ids.

Since the rules are matched in numerical order, the rule id can be used by the user to impose a desired rule match order. The *default rule* is just a rule which is applied when no other rules matches are found.

The daemon API supports symbolic interface names to be used in place of the numerical port indexes. When symbolic names are used, the following convention is assumed:

- filtering rules are applied on the *internal* switch port, so that the bad traffic is dropped and it won't even reach the host
- steering rules are applied on the *external* switch ports, so that the traffic coming from the wire on port A will be redirected to the wire on port B without even reaching the host

This convention matches the scenario of an IDS system which is bridging traffic between the two RRC ports, dropping the unwanted traffic or steering the traffic which is known to be good for sure to reduce the cpu load. This convention can be avoided by using numeric port indexes in place of the symbolic interface names.

