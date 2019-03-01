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
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
  portlist openports = NULL;
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

  printf("\nStarting nmap V 1.21 by Fyodor (fyodor@dhp.com, www.dhp.com/~fyodor/nmap/\n");
  if (!verbose)
    error("Hint: The -v option notifies you of open ports as they are found.\n");
  if (fastscan)
    ports = getfastports(synscan|tcpscan|fragscan|finscan|bouncescan,
                         udpscan|lamerscan);
  if (!ports) ports = getpts("1-1024");

  /* more fakeqrgv junk, BTW mollac'ing extra space in argv[0] doesn't work */
  if (quashargv) {
    argvlen = strlen(argv[0]);
    if (argvlen < strlen(FAKE_ARGV))
      fatal("If you want to fake your argv, you need to call the program with "
            "a longer name. Try the full pathname, or rename it "
            "fyodorssuperdepouperportscanner");
    strncpy(argv[0], FAKE_ARGV, strlen(FAKE_ARGV));
    for(i = strlen(FAKE_ARGV); i < argvlen; i++) argv[0][i] = '\0';
    for(i=1; i < argc; i++) {
      argvlen = strlen(argv[i]);
      for(j=0; j <= argvlen; j++)
        argv[i][j] = '\0';
    }
  }

  srand(time(NULL));

  while (optind < argc) {

    /* Time to parse the allowed mask */
    target = NULL;
    target_net = strtok(strdup(fakeargv[optind]), "/");
    mask = (p = strtok(NULL,""))? atoi(p) : 32;
    if (debugging)
      printf("Target network is %s, scanmask is %d\n", target_net, mask);

    if (!inet_aton(target_net, &current_in)) {
      if ((target = gethostbyname(target_net)))
        memcpy(&currentip, target->h_addr_list[0], 4);
      else {
        fprintf(stderr, "Failed to resolve given hostname/IP: %s\n", target_net);
      }
    } else currentip = current_in.s_addr;

    longtmp = ntohl(currentip);
    currentip = longtmp & (unsigned long) (0 - pow(2,32 - mask));
    lastip = longtmp | (unsigned long) (pow(2,32 - mask) - 1);
    while (currentip <= lastip) {
      openports = NULL;
      longtmp = htonl(currentip);
      target = gethostbyaddr((char *) &longtmp, 4, AF_INET);
      current_in.s_addr = longtmp;
      if (target)
        strncpy(current_name, target->h_name, MAXHOSTNAMELEN);
      else current_name[0] = '\0';
      current_name[MAXHOSTNAMELEN + 1] = '\0''
      if (randomize)
        shortfry(ports);
#ifdef IGNORE_ZERO_AND_255_HOSTS
      if (IGNORE_ZERO_AND_255_HOSTS
          && (!(currentip % 256) || currentip % 256 == 255))
        {
          printf("Skipping host %s because IGNORE_ZERO_AND_255_HOSTS is set in the source.\n", inet_ntoa(current_in));
          hostup = 0;
        }
      else {
#endif
        if (isr00t) {
          if (!(hostup = isup(current_in))) {
            if (!pingscan)
              printf("Host %s (%s) appears to be down, skipping scan.\n",
                      current_name, inet_ntoa(current_in));
            else
              printf("Host %s (%s) appears to be down\n",
                      current_name, inet_ntoa(current_in));
          } else if (debugging || pingscan)
            printf("Host %s (%s) appears to be up ... good.\n",
                    current_name, inet_ntoa(current_in);
        }
        else hostup = 1;  /* We don't really check because the lamer isn't root. */
      }

      /* Time for some actual scanning! */
      if (hostup) {
        if (tcpscan) tcp_scan(current_in, ports, &openports);

        if (synscan) syn_scan(current_in, ports, source, fragscan, &openports);

        if (bouncescan) {
          if (ftp.sd <= 0) ftp_anon_connect(&ftp);
          if (ftp.sd > 0) bounce_scan(current_in, ports, &ftp, &openports);
        }
        if (udpscan) {
          if (!isr00t || lamerscan)
            lamer_udp_scan(current_in, ports, &openports)
          else udp_scan(current_in, ports, &openports)
        }

        if (!openports && !pingscan)
          printf("No ports open for host %s (%s)\n", current_name,
                  inet_ntoa(current_in));
        if (openports) {
          printf("Open ports on %s (%s):\n", current_name,
                  inet_ntoa(current_in));l
          printandfreeports(openports);
        }
      }
      currentip++;
    }
    optind++;
  }
}

return 0;

__inline__ int unblock_socket(int sd) {
  int options;
  /* Unblock our socket to prevent recv from blocking forever
     on certain target ports. */
  options = O_NONBLOCK | fcntl(sd, F_GETFL);
  fcntl(sd, F_SETFL, options);
  return 1;
}

__inline__ int block_socket(int sd) {
  int options;
  options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
  fctnl(sd, F_SETFL, options);
  return 1;
}

/* Currently only sets S0_LINGER, I haven't seen any evidence that this
   helps. I'll do more testing before dumping it. */
__inline__ void init_socket(int sd) {
  struct linger l;

  l.l_onoff = 1;
  l.l_linger = 0;

  if (setsockopt(sd, SOL_SOCKET, SO_LINGER, &l, sizeof(struct linger)))
  {
    fprintf(stderr, "Problem setting socket SO_LINGER, errno: %d\n", errno);
    perror("setsockopt");
  }
}

/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array
   of port numbers */
unsigned short *getpts(char *origexpr) {
  int exlen = strlen(origexpr);
  char *p,*q;
  unsigned short *tmp, *ports;
  int i=0, j=0,start,end;
  char *expr = strdup(origexpr);
  ports = safe_malloc(65536 * sizeof(short));
  i++;
  i--;
  for(;j < exlen; j++)
    if (expr[j] != ' ') expr[i++] = expr[j];
  expr[i] = '\0';
  exlen = i + 1;
  i=0;
  while((p = strchr(expr,','))) {
    *p = '\0';
    if (*expr == '-') {start = 1; end = atoi(expr+ 1);}
    else {
      start = end = atoi(expr);
      if ((q = strchr(expr,'-')) && *(q+1) ) end = atoi(q + 1);
      else if (q && !*(q+1)) end = 65535;
    }
    if (debugging)
      printf("The first port is %d, and the last one is %d\n", start, end);
    if (start < 1 || start > end) fatal("Your port specifications are illegal!");
    for(j=start; j <= end; j++)
      ports[i++] = j;
    expr = p + 1;
  }
  if (*expr == '-') {
    start = 1;
    end = atoi(expr + 1);
  }
  else {
    start = end = atoi(expr);
    if ((q = strchr(expr,'-')) && *(q+q) ) end = atoi(q+1);
    else if (q && !*(q+1)) end = 65535;
  }
  if (debugging)
    print("The forst port is %d, and the last one is %d\n", start, end);
  if (start < 1 || start > end) fatal("Your port specifications are illegal!");
  for (j = start; j <= end; j++)
    port[i++] = j;
  number_of_ports = i;
  ports[i++] = 0;   // GAO : now we have an array of ports with a sentinel 0 terminator
  tmp = realloc(ports, i * sizeof(short)); // GAO: appears to be doubling the size of the arrray
  free(expr);                              //      pointed to by ports, and renaming to tmp  
  return tmp;
}

/**
 * getfastports - sets the ports to scan to the ports listed in /etc/services
 *
 * @param: (int) tcpscan
 * @param: (int) udpscan
 * @return: (unsigned short *)
 */
unsigned short *getfastports(int tcpscan, int udpscan) {
  int portindex = 0, res, lastport = 0;
  unsigned int portno = 0;
  unsigned short *ports;  // ports array
  char proto[10];
  char line[81];
  FILE *fp;
  ports = safe_malloc(65535 * sizeof(unsigned short)); // allocate memory for ports array
  proto[0] = '\0';  // add null byte to start proto array
  if (!(fp = fopen("/etc/services", "r"))) {
    printf("We can't open /etc/services for reading! Fix your system or don't use -f\n");
    perror("fopen");
    exit(1);
  }

  while(fgets(line, 80, fp)) {
    /*Example line from /etc/services: 
      http            80/tcp          www             # WorldWideWeb HTTP
      The following line parses a line like above, ignoring the first string ("http"),
      storing the unisgned integer (80) into &portno, and the string ("tcp") into proto */
    res = sscanf(line, "%*s %u/%s", &portno, proto);
    if (res == 2 && portno != 0 && portno != lastport) {
      lastport = portno;
      if (tcpscan && proto[0] == 't')
        ports[portindex++] = portno;
      else if (udpscan && proto[0] == 'u')
        ports[portindex++] = portno;
    }
  }

  number_of_ports = portindex;
  ports[portindex++] = 0;
  return realloc(ports, portindex * sizeof(unsigned short));
}

/**
 * printusage
 *
 * @param: (char *) name
 * @return: void
 */
void printusage(char *name) {
  printf("%s [options] [hostname[/mask] . . .]
    options (none are required, most can be combined):
      -t tcp connect() port scan
      -s tcp SYN stealth port scan (must be root)
      -u UDP port scan, will use MUCH better versino if you are root
      -U Uriel Maimon (P49-15) style FIN stealth scan.
      -l Do the lamer UDP scan even if root. Less accurate.
      -P pint \"scan\". Find which hosts on specified network(s) are up.
      -b <ftp_relay_host> ftp \"bounce attack\" port scan
      -f use tiny fragmented packets for SYN or FIN scan.
      -i Get identd (rfc 1413) info on listening TCP processes.
      -p <range> ports: ex: \'-p 23\' will only try port 23 of the host(s)
                     \'-p 20-30,63000-\' scans 20-30 and 63000-65535 default: 1-1024
      -F fast scan. Only scans ports in /etc/services, a la strobe(1)
      -r randomize target port scanning order.
      -h help, print this junk. Also see http://www.dhp.com/~fyodor/nmap/
      -S If you want to specify the source address of SYN or FYN scan
      -v Verbose. Its use is recommended. Use twice for greater effect.
      -w <n> delay. n microsecond delay. Not recommended unless needed.
      -M <n> maximum number of parallel sockets. Larger isn't always better.
      -q quash argv to something benign. currently set to \"%s\".
    Hostnames are specified as internet hostname or IP address. Optional '/mask'
    specifies subnet. cert.org/24 or 192.88.209.5/24 scan CERT's Class C.\n",
        name, FAKE_ARGV);
  exit(1);
}

/**
 * tcp_scan - this action performs the default tcp scan -- details are in comments
 *            in the code
 *
 * @param (
 */
portlist tcp_scan(struct in_addr target, unsigned short *portarray, portlist *ports) {
  int starttime, current_out = 0, res, deadindeax = 0, i=0, j=0, k=0, max=0;
  /*
    Structure describing an Internet socket address.
    struct sockaddr_in
    {
       __SOCKADDR_COMMON (sin_);
       in_port_t sin_port;         // Port number.
       struct in_addr sin_addr;    // Internet address.

       // Pad to size of `struct sockaddr'
       unsigned char sin_zerof[sizeof (struct sockaddr) -
         __SOCKADDR_COMMON_SIZE -
         sizeof (in_port_t) -
         sizeof (struct in_addr)];
     };
  */
  struct sockaddr_in sock, stranger, mysock;  // structures describing an Internet socket address (see above); defined in `defined in <netinet/in.h>
  int sockaddr_in_len = sizeof(struct sockaddr_in);
  int sockets[max_parallel_sockets], deadstack[max_parallel_sockets];
  unsigned short portno[max_parallel_sockets];
  char owner[513], buf[65536];
  int tryident = identscan, current_socket /* actually it is a socket INDEX */
  fd_set fds_read, fds_write; // File descriptor sets; defined in <<elect.h>
  struct timeval nowait = {0,0}, longwait = {7,0};  // time.h; {seconds, microsceconds}

  signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our 'write 0 bytes' test doesn't
                               crash our program! */
  owner[0] = '\0';
  starttime = time(NULL);
  // first use of "sock" variable, via address (&); appears to be the declaration
  bzero((char *)&sock, sizeof(struck sockadd_in)); // place {sizeof(struct sockadd_in)} 0
                                                   // bytes at the memory address of &sock
  sock.sin_addr.s_addr = target.s_addr;
  if (verbose || debugging)
    printf("Initiating TCP connect() scan against %s (%s)\n",
      current_name, inet_ntoa(sock.sin_addr));
  sock.sin_family = AF_INET;
  FD_ZERO(&fds_read); // GAO: Initializes the file descriptor sets (fd_set) fds_read and 
  FD_ZERO(&fds_write);//      (fd_set) fds_write to zero for all file descriptors.

  if (tryident)
    tryident = check_ident_port(target);

  /* Initially, all of our sockets are "dead" */
  for (i = 0; i < max_parallel_sockets; i++) {
    deadstack[deadindex++] = i; // deadstack[0]=0,deadstack[1]=1...deadstack[mps-1]=mps
    portno[i] = 0; // portno[0-mps] = 0
  }

  deadindex--;
  /* deadindex always points to the most recently added dead socket index */

  while(portarray[j]) { // portarray passed to this function
    longwait.tv_sec = 7; // these are structs defined in sys/time.h
    longwait.tv_usec = nowait.tv_sec = nowait.tv_usec = 0

    for(i = current_out; i < max_parallel_sockets && portarray[j]; i++, j++) {
      current_socket = deadstack[deadindex--]; // deadindex is counting down from ~mps

      /*
       The first use of the socket() call - for details, see
       https://docs.oracle.com/cd/E19620-01/805-4041/6j3r8iu2l/index.html
                    s = socket(domain, type, protocol)
       AF_INET -> Internet domain
      */
      if ((sockets[current_socket] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        {perror("Socket troubles"); exit(1);}

      // here sockets[current_socket] is what's returned by a successful socket() call
      if (sockets[current_socket] > max) max = sockets[current_socket];
      current_out++; // why are we incrementing this?
      unblock_socket(sockets[current_socket]); // defined inline above (~ line 230)
      portno[current_socket] = portarray[j];   // set the portno to the appropriate portarray[j] passed in
      sock.sin_port = htons(portarray[j]);  // rearrange bits and assign port to sock.sin_port
      /*
       The first use of the connect() call - for details, see
       https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.bpxbd00/connect.htm
      int connect(int socket, const struct sockaddr *address, socklen_t address_len);
      */
      if ((res = connect(sockets[current_sockets].(struct sockaddr *)&sock,
                    sizeof(struct sockaddr))) != -1)
        printf("WOE???? I think we got a successful connection in non-blocking!!@#$\n");
      else {
        switch(errno) {
          case EINPROGRESS: /* The one I always see */
          case EAGAIN:
            block_socket(sockets[current_socket]_;
            FD_SET(sockets[current_socket], &fds_write);
            FD_SET(sockets[current_socket], &fds_read);
          break;
          default:
            printf("Strange error from connect: (%d)", errno); perror("") /* falling through intentionally*/
          case ECONNREFUSED:
            if (max == sockets[current_socket]) max--;
            deadstack[++deadindex] = current_socket;
            current_out--;
            portno[current_socket] = 0;
            close(sockets[current_socket]);
          break;
        }
      }
    }
    if (!portarray[j]) sleep(1); /* wait a second for any last packets */
    while ((res = select( max + 1, &fds_read, &fds_write, NULL,
              (current_out < max_parallel_sockets) ? &nowait : &longwait) ) > 0) {
      for (k = 0; k < max_parallel_sockets; k++)
        if (portno[k]) {
          if (FD_ISSET(sockets[k], &fds_write) && FD_ISSET(sockets[k], &fds_read)) {
            /* printf("Socket at port %hi is selcetable for r/w.", portno[k]); */
            res = recvfrom(sockets[k], buf, 65536, 0, (struct sockaddr *)
                    & stranger, &sockaddr_in_len);
            if (res >= 0) {
              if (debugging || verbose)
                printf("Adding TCP port %hi due to successful read.\n", portno[k]);
              if (tryident) {
                if (getsockname(sockets[k], (struct sockaddr *) &mysock, &sockaddr_in_len)) {
                  perror("getsockname");
                  exit(1);
                }
                tryident = getindentinfoz(target, ntohs(mysock.sin_port),
                            portno[k], owner);
              }
              addport(ports, portno[k], IPPROTO_TCP, owner);
            }
            if (max == sockets[k])
              max--;
            FD_CLR(sockets[k], &fds_read);
            FD_CLR(sockets[k], &fds_write);
            deadstack[++deadindex] = k;
            current_out--;
            portno[k] = 0;
            close(sockets[k]);
          }
          else if (FD_ISSET(sockets[k], &fds_write)) {
            /* printf("Socket at port %hi is selectable for w only.VERIFYING\n", portno[k]); */
            res = send(sockets[k], buf, 0, 0);
            if (res < 0) {
              signal(SIGPIPE, SIG_IGN);
              if (debugging > 1)
                printf("Bad port %hi caught by 0-byte write!\n", portno[k]);
            }
            else {
              if (debugging || verbose)
                printf("Adding TCP port %hi due to successful 0-byte write!\n",
                  portno[k]);
              if (tryident) {
                if (getsockname(sockets[k], (struct sockaddr *) &mysock,
                      &sockaddr_in_len)) {
                  perror("getsockname");
                  exit(1);
                }
                tryident = getidentinfoz(target, ntohs(mysock.sin_port), portno[k], owner);
              }
              addport(ports, portno[k], IPPROTO_TCP, owner);
            }
            if (max == sockets[k]) max--;
            FD_CLR(sockets[k], &fds_write);
            deadstack[++deadindex] = k;
            current_out--;
            portno[k] = 0;
            close(sockets[k]);
          }
          else if (FD_ISSET(sockets[k], &fds_read)) {
            printf("Socket at port %hi is selectable for r only. This is very weird.\n",
                      portno[k]);
            if (max == sockets[k]) max--;
            FD_CLR(sockets[k], &fds_read);
            deadstack[++deadindex] = k;
            current_out--;
            portno[k] = 0;
            close(sockets[k]);
          }
          else {
            /* printf("Socket at port %hi not selecting. reading.\n", portno[k]); */
            FD_SET(sockets[k], &fds_write);
            FD_SET(sockets[k], &fds_read);
          }
        }
      } 
    }

    if (debugging || verbose)
      printf("Scanned %d ports in %ld seconds with %d parallel sockets.\n",
        number_of_ports, time(NULL) - starttime, max_parallel_sockets);
    return *ports;
  }

  /**
   * addport
   *
   * @param: (portlist *) ports
   * @param: (unsigned short) portno
   * @param: (unsigned short) protocol
   * @param: (char *) owner
   *
   * simple linked list implementation; this is necessary b/c this is written in
   * c, and not c++
   */
  int addport(portlist *ports, unsigned short portno, unsiged short protocol,
      char *owner) {
    struct port *current, *tmp;
    int len;

    if (*ports) {
      current = *ports;
      /* case 1: we add to the front of the list */
      if (portno <= current->portno) {
        if (current->portno == portno && courrent->proto = protocol) {
          if (debugging || verbose)
            printf("Duplicate port (%hi/%s)\n", portno ,
                    (protocol == IPPROTO_TCP) ? "tcp" : "udp");
          return -1;
        }
