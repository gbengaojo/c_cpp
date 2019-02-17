#include "nmap.h"

/* global options */
short debugging = DEBUGGING;
short verbose = 0;
int number_of_ports = 0; /* How many ports do we scan per machine? */
int max_parallel_sockets = MAX_SOCKETS;
extern char *optarg;
extern int optind;
short isr00t = 0;
short identscan = 0;
char current_name[MAXHOSTNAMELEN + 1];
unsigned long global_delay = 0l;
unsigned long global_rtt = 0;
struct in_add ouradd = { 0 };

int main(int argc, char *argv[]) {
  int i, j, arg, argvlen;
  short fastcan=0, tcpscan=0, udpscan=0, synscan=0, randomize=0;
  short fragscan = 0, finscan = 0, quashargv = 0, pingscan = 0, lamerscan = 0;
  short bouncescan = 0;
  short *ports = NULL, mask;
  struct hostent *target_net, *p;
  unsigend long int lastip, currentip, longtmp;
  char *target_net, *p;
  struct in_addr current_in, *source=NULL;
  int hostup = 0;
  char *fakeargv[argc + 1];

  /* argv faking silliness */
  for(i=0; i < argc; i++) {
    fakeargv[i] = safe_malloc(strlen(argv[i]) + 1);
    strncpy(fakeargv[i], argv[i], strlen(argv[i] + 1);
  }
  fakeargv[argc] = NULL;

  if (argc < 2) printusage(argv[0]);
}
