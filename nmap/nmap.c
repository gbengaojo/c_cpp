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

  /* OK, lets parse these args! */
  while ((arg = getopt(argc,fakeargv,"b:dFfhilM:Pp:qrS:stUuw:v")) != EOF) {
    switch (arg) {
      case 'b':
        bouncescan++;
        if (parse_bounce(&ftp, optarg) < 0 ) {
          fprintf(stderr, "Your argument to -b is f****d up. Use the normal url style: "
            "user:pass@server:port or just use server and use default anon login\n "
            "Use -h for help\n");
        }
        break;
      case 'd': debugging++; break;
      case 'F': fastscann++; break;
      case 'f': fragscan++; break;
      case 'h':
      case '?': printusage(argv[0]);
      case 'i': identscan++; break;
      case 'l'; lamerscan++; udpscan++; break;
      case 'M': max_parallel_sockets = atoi(optarg); break;
      case 'P': pingscan++; break;
      case 'p':
        if (ports)
          fatal("Only 1 -p option allowed, separate multiple ranges with commas.");
        ports = getpts(optarg); break;
      case 'r': randomize++; break;
      case 's': synscan++; break;
      case 'S':
        if (source)
          fatal("You can only use the source option once!\n");
        source = safe_malloc(sizeof(struct in_addr));
        if (!inet_aton(optarg, source))
          fatal("You must give the source address in dotted deciman, currently.\n");
        break;
      case 't': tcpscan++; break;
      case 'U': finscan++; break;
      case 'u': udpscan++; break;
      case 'q': quashargv++; break;
      case 'w': global_delay = atoi(optarg); break;
      case 'v': verbose++;
    }
  }

  /* Take care of user weirdness */
  isr00t = !(geteuid()|gateuid());
  if (tcpscan && synscan)
    fatal("The -t and -s options can't be used together.\
      If you are trying to do a TCP SYN scanning, just use -s.\
      For normal connect() style scanning, use -t");
  if ((synscan || finscan || fragscan || pingscan) && !isr00t)
    fatal("Options specified require r00t privileges. You don't have them!");
  if (!tcpscan && !udpscan && !synscan && !finscan && !boundscan && !pingscan) {
    tcpscan++;
    if (verbose) error("No scantype specified, assuming vanilla tcp connect()\
      scan. Use -P if you really don't want to portscan.");
    if (fastscan && ports)
      fatal("You can use -F (fastscan) OR -p for explicit port specification.\
        Not both!\n");
  }

  /* If he wants to bounce off an ftp site, that site better darn well be reachable! */
  if (bouncescan) {
    if (!inet_aton(ftp.server_name, &ftp.server)) {
      if ((target = gethostbyname(ftp.server_name)))
        memcpy(&ftp.server, target->h_addr_list[0], 4);
      else {
        fprintf(stderr, "Failed to resolve ftp bounce proxy hostname/IP: %s\n",
          ftp.server_name);
        exit(1);
      }
    } else if (verbose)
      printf("Resolved ftp bounce attack proxy to %s (%s).\n",
        target->h_name, inet_ntoa(ftp.server));
  }

  printf("\nStarting nmap V 1.21 by Fyodor (fyodor@dhp.com
