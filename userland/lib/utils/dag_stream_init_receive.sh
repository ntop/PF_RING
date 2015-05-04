#!/bin/sh

echo "Loading the DAG module"

rmmod dag
rmmod dagmem
modprobe dagmem dsize=512M

sleep 1

dagload

sleep 1

echo "Configuring the DAG card (multiple queues)"

dagconfig -d0 default

sleep 1

dagconfig mem=64:0:64:0:64:0:64:0:64:0:64:0:64:0:64:0

sleep 1

dagconfig -d0 -S ipf_enable=on -S hash_encoding_from_ipf=on

dagconfig -d0 -S hash_width=3

dagconfig -d0 -S n_tuple_select=2

dagconfig -d0 -S hat_range=0-124:125-249:250-374:375-499:500-624:625-749:750-874:875-1000

dagcat-setup -d0 -m z8

#echo "Configuration done. Use dagbits -d0:X -c for testing."
echo "Configuration completed."
echo "Use -i dag:dagX:Y (e.g. dag:dag0:0) as device"