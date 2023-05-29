Runtime Filtering
=================

PF_RING 8.5 or later includes native support for runtime filtering,
which is the ability to add filtering rules while the application
is running.

Filtering rules are automatically converted into hardware rules and
injected directly to the adapter, to be evaluated in hardware and
add zero overhead. This requires an adapter supporting hardware 
filtering (e.g. NVIDIA/Mellanox ConnectX).

This allows you to run a CPU intensive application (e.g. IDS/IPS)
and receive only selected traffic according to rules which are 
dinamically built and pushed as soon as an host that requires
attention is detected.
