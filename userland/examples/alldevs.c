/*
 * (C) 2003-15 - ntop 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

/* *************************************** */

int main(int argc, char* argv[]) {
  pcap_if_t *alldevs, *d;
  u_int i=0;
  char errbuf[PCAP_ERRBUF_SIZE]; 

  while(1) {
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
      fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
      exit(1);
    }
        
    /* Print the list */
    for(i=0, d=alldevs; d; d=d->next) {
      printf("%d. %s", ++i, d->name);
      if (d->description)
	printf(" (%s)\n", d->description);
      else
	printf(" (No description available)\n");
    }

    printf("\n");
    sleep(3);
  }

  return(0);
}
