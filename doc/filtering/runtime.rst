Runtime Filtering
=================

PF_RING 8.5 or later includes native support for runtime filtering,
which is the ability to add filtering rules while the application
is running.

Filtering rules are automatically converted into hardware rules and
injected directly to the adapter, to be evaluated in hardware and
add zero overhead. This requires an adapter supporting hardware 
filtering (e.g. NVIDIA/Mellanox ConnectX).

This allows you to run CPU bound applications (e.g. IDS/IPS) and
receive (an process) only selected traffic, according to rules which
are  dinamically built and pushed to the capture engine. In order to
achieve this the adapter is configured to discard all the traffic by
default, and forward only packets matching hosts that require attention.

Filters are pushed to the capture engine by means of a Redis queue,
and they can be added and removed by means of commands like "add host"
or "remove host".

Enabling Runtime Filtering
--------------------------

In order to enable Runtime Filtering in PF_RING, the PF_RING_RUNTIME_MANAGER
environment variable should be set, using as value the name of the Redis
queue used to push the filtering commands.

Example using pfcount:

.. code-block:: console

   PF_RING_RUNTIME_MANAGER="pfring.mlx5_0.filter.host.queue" pfcount -i mlx:mlx5_0

Pushing Filters
---------------

Filters can be programmatically or manually pushed to the Redis queue
using the "+<IP>" command to add a rule for a specific host, and the 
"-<IP>" command to remove a rule.

Example using redis-cli:

.. code-block:: console

   redis-cli RPUSH pfring.mlx5_0.filter.host.queue "+10.0.0.1" "+10.0.0.2" "+10.0.0.3"
   redis-cli RPUSH pfring.mlx5_0.filter.host.queue "-10.0.0.2"

Redis Connection Settings
-------------------------

By default, when enabling Runtime Filtering, PF_RING connects to Redis on localhost
port 6379. This can be controlled through the PF_RING_REDIS_SETTINGS environment
variable. Supported formats are:

- host:port
- host@redis_instance
- host:port@redis_instance
- host:port:password@redis_instance  

Examples:

.. code-block:: console

   PF_RING_REDIS_SETTINGS="@2"
   PF_RING_REDIS_SETTINGS="129.168.1.3"
   PF_RING_REDIS_SETTINGS="129.168.1.3:6379@3"
   PF_RING_REDIS_SETTINGS="129.168.1.3:6379:nt0pngPwD@0"
   PF_RING_REDIS_SETTINGS="/var/run/redis/redis.sock"
   PF_RING_REDIS_SETTINGS="/var/run/redis/redis.sock@2"
