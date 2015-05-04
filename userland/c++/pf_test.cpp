#include "PFring.h"
#include <string.h>

/* ************************************* */

struct simple_stats {
  u_int64_t num_pkts, num_bytes;
};

/* ************************************* */

int main(int argc, char *argv[]) {
  char *device_name = (char*)"dna0";
  PFring *ring;
  int rc;
  u_int16_t rule_id = 99;
  u_int32_t num_pkts = 0;
  char stats[32];
  u_char pkt[1500];
  struct pfring_pkthdr hdr;
  bool add_rule = false;

  if(argc != 2) {
    printf("pf_test <device>\n");
    return(-1);
  } else
    device_name = argv[1];

  ring = new PFring(device_name, 128, 1);

  if(ring)
    printf("Succesfully open device %s\n", device_name);
  else {
    printf("Problems while opening device %s (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n", 
	   device_name, device_name);
    return(0);
  }

  ring->enable_ring();

  if(add_rule) {
    filtering_rule the_rule;

    ring->toggle_filtering_policy(false); /* Default to drop */
    memset(&the_rule, 0, sizeof(the_rule));

    the_rule.rule_id = rule_id;
    the_rule.rule_action = forward_packet_and_stop_rule_evaluation;
    the_rule.core_fields.proto = 1 /* icmp */;
    the_rule.plugin_action.plugin_id = 1; /* Dummy plugin */
    rc = ring->add_filtering_rule(&the_rule);

    printf("Added filtering rule %d [rc=%d]\n", rule_id, rc);
  }

  while(true) {
    hdr.len = 0;

    if(ring->get_next_packet(&hdr, pkt, sizeof(pkt)) > 0) {
      printf("Got %d bytes packet [tot: %u]\n", hdr.len, ++num_pkts);

      if(add_rule) {
	struct simple_stats *the_stats = (struct simple_stats*)stats;
	u_int len = sizeof(stats);

	rc = ring->get_filtering_rule_stats(rule_id, stats, &len);
	if(rc == sizeof(struct simple_stats))
	  printf("Got stats for filtering rule %d [pkts=%u][bytes=%u]\n",
		 rule_id,
		 (unsigned int)the_stats->num_pkts,
		 (unsigned int)the_stats->num_bytes);
      }
    } else {
      printf("Error while calling get_next_packet()\n");
      break;
    }
  }

  delete ring;

  return(0);
}
