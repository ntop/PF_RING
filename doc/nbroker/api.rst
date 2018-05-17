API
===

The programmer API is defined into the nbroker_api.h header. Please refer to the API documentation at https://www.ntop.org/guides/pf_ring_api/ for detailed informations.

Please find below a sample application that is using the C API to set a "pass all" rule on the traffic, and only drop
flows matching the provided filters. This is the typical case of an application (e.g. an IDS) that wants to inspect all traffic, exception made for selected traffic. In this example, the eth1 interface is the interface from which the application reads the packets to analyse.

.. code-block:: c

   #include <arpa/inet.h>
   #include <string.h>
   
   #include "nbroker_api.h"
   
   #define INGRESS_INTERFACE   "eth1"
   #define IDLE_SECONDS        60
   
   int main() {
     int i = 0;
     nbroker_t *brk;
     nbroker_match_t match;
     u_int32_t rule_id;
     int running = 1;
     
     /* Set up the broker communication and remove all the existing rules */
     nbroker_init(&brk, 0);
     nbroker_reset_rules(brk, INGRESS_INTERFACE, NBROKER_TYPE_FILTERING);
     nbroker_reset_rules(brk, INGRESS_INTERFACE, NBROKER_TYPE_STEERING);
     
     /* Set the default policy to pass */
     nbroker_set_default_policy(brk, INGRESS_INTERFACE, NBROKER_POLICY_PASS);
     
     while (running) {
     
       /* Do something here.. */
     
       /* Set up a rule to discard unwanted traffic (this rule would change on each iteration in a real application).
        * Note: all nbroker_match_t fields are in network byte order */
       memset(&match, 0, sizeof(match));
       match.dport.low = htons(25);
       rule_id = NBROKER_AUTO_RULE_ID;
       nbroker_set_filtering_rule(brk, INGRESS_INTERFACE, &rule_id, &match, NBROKER_POLICY_DROP);
       
       if (i % 1024 == 0) {
         /* From time to time call nbroker_purge_idle_rules. 
          * This ensures that rules older then IDLE_SECONDS are removed */
         nbroker_purge_idle_rules(brk, IDLE_SECONDS);
       }
       i++;
     }
     
     nbroker_term(brk);
     return(0);
   }


All the API functions return a broker_rc_t return code, which can be used to check if the command was applied correcly.

The programmer can use the port conversion api to get the internal or external switch port index associated to the symbolic interface name. This grantes him full control over the target port for a particular rule.

The following example covers the scenario in which a user is interested in only monitoring the HTTP traffic of the host 10.0.0.1, assuming it is located on the INGRESS_INTERFACE side. All the other traffic is forwarded to the egress port.

.. code-block:: c
   
   #define INGRESS_INTERFACE "eth1"
   #define EGRESS_INTERFACE "eth2"
   
   /* initialization here */
   
   u_int8_t ingress_internal_port;
   u_int8_t ingress_external_port;
   u_int8_t egress_external_port;
   char port[3], redirect_port[3];
   
   /* Query the port numbers */
   nbroker_ifname_to_internal_port(bkr, INGRESS_INTERFACE, &ingress_internal_port);
   nbroker_ifname_to_external_port(bkr, INGRESS_INTERFACE, &ingress_external_port);
   nbroker_ifname_to_external_port(bkr, EGRESS_INTERFACE, &egress_external_port);
   
   /* Set the default policy to steer traffic to the egress interface */
   snprintf(port, sizeof(port), "%d", ingress_external_port);
   snprintf(redirect_port, sizeof(redirect_port), "%d", egress_external_port);
   nbroker_set_default_steering(bkr, port, redirect_port);
   
   /* Do the same the other way round */
   nbroker_set_default_steering(bkr, redirect_port, port);
   
   /* Set rules to receive the traffic of interest */
   memset(&match, 0, sizeof(match));
   match.sport.low = htons(80);
   mathc.shost.ip_version = 4;
   match.shost.mask.v4 = 0xFFFFFFFF;
   match.shost.host.v4 = inet_aton("10.0.0.1");
   
   snprintf(port, sizeof(port), "%d", ingress_external_port);
   snprintf(redirect_port, sizeof(redirect_port), "%d", ingress_internal_port);
   rule_id = NBROKER_AUTO_RULE_ID;
   nbroker_set_steering_rule(bkr, port, &rule_id, &match, redirect_port);
   
   /* Do the same the other way round */
   memset(&match, 0, sizeof(match));
   match.dport.low = htons(80);
   mathc.dhost.ip_version = 4;
   match.dhost.mask.v4 = 0xFFFFFFFF;
   match.dhost.host.v4 = inet_aton("10.0.0.1");
   
   snprintf(port, sizeof(port), "%d", egress_external_port);
   snprintf(redirect_port, sizeof(redirect_port), "%d", ingress_internal_port);
   rule_id = NBROKER_AUTO_RULE_ID;
   nbroker_set_steering_rule(bkr, port, &rule_id, &match, redirect_port);

The API provides the following ways to remove existing rules:

- nbroker_remove_rule_by_id removes an existing rule matching the rule id
- nbroker_remove_rule_by_match removes an existing rule matching the specified match filter
- nbroker_list_rules removes all the existing rules on the specified port. The default rules are not affected.

The rules which are currently set on the device can be retrieved by the nbroker_list_rules call like the following example demonstrates:

.. code-block:: c
   
   u_int32_t num_rules;
   nbroker_rule_t *rules_list = NULL;
   
   nbroker_list_rules(bkr, port, NBROKER_TYPE_FILTERING, &num_rules, &rules_list);
   
   if (rules_list) {
     for(u_int32_t i = 0; i < num_rules; i++) {
       /* use the rule information */
       rules_list[i].rule_id  ...
       rules_list[i].match    ...
       rules_list[i].u.policy ...
     }
   
     free(rules_list);
   }

