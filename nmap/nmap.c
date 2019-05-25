#include "nmap.h"

/* Warp 9.9 ~ 4 billion mps - The 37's */

/*
host-to-network-short -
htons - converts bytes from little endian, host byte order (least significant
  byte first) to big endian, network byte order (greatest significat byte first)
  E.g.: 5001d => 0x1389 
      little-endian / host byte order
        (in memory) --- 0x89 0x13 ---  ||- 1000 1001 -|- 0001 0011 -||
      big-endian / network byte order
        (in memory) --- 0x13 0x89 ---  ||- 0001 0011 -|- 1000 1001 -||
*/

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
struct in_addr ouraddr = { 0 };

int main(int argc, char *argv[]) {
  int i, j, arg, argvlen;
  short fastcan=0, tcpscan=0, udpscan=0, synscan=0, randomize=0;
  short fragscan = 0, finscan = 0, quashargv = 0, pingscan = 0, lamerscan = 0;
  short bouncescan = 0;
  short *ports = NULL, mask;
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
  /**
    (portlist)                                  defined in nmap.h, line 79:
      typedef port *portlist
    (port)                                      defined in nmap.h, line 63:
      typedef struct port {
        unsigned short portno;
        unsiged char proto;
        char *owner;
        struct port *next;
      } port
  **/
  portlist openports = NULL;
  /*
    hostent - defined in /sysroot/usr/include/netdb.h; see man gethostbyname(3)
    struct hostent {
      char *h_name; // official name of host
      char **h_aliases; // alias list
      int h_addrtype; // host address type
      int h_length; // length of address
      char **h_addr_list; // list of addresses from name server
    }
  */
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

    }
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

return 0;
}

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
    ### GAO: sockaddr_in  ###
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
  struct sockaddr_in sock, stranger, mysock; // see above; defined in <sys/netinet/in.h>
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
  sock.sin_family = AF_INET; // address family -> Internet Address
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

      /* vvv
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

      /* vvv
       The first use of the connect() call - for details, see
       https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.bpxbd00/connect.htm
      int connect(int socket, const struct sockaddr *address, socklen_t address_len);
      */
      if ((res = connect(sockets[current_sockets], (struct sockaddr *)&sock,
                    sizeof(struct sockaddr))) != -1)
        printf("WOE???? I think we got a successful connection in non-blocking!!@#$\n");
      else {  // some error was thrown -- see above for url
        switch(errno) {
        /*
          FD_SET(fd, &fdset)
            Sets the bit for the file descriptor fd in the file descriptor set fdset.
          See https://www.mkssoftware.com/docs/man3/select.3.asp
        */
          case EINPROGRESS: /* The one I always see */
          case EAGAIN:
            block_socket(sockets[current_socket]);       // block socket (see inline above)
            FD_SET(sockets[current_socket], &fds_write); 
            FD_SET(sockets[current_socket], &fds_read);
          break;
          default:
            printf("Strange error from connect: (%d)", errno); perror("") /* falling through intentionally*/
          case ECONNREFUSED:
            // if there was some implicit or explicit socket connection error, reset
            // all relevant variables and counters, and close the current socket attempt
            if (max == sockets[current_socket]) max--;
            deadstack[++deadindex] = current_socket;
            current_out--;
            portno[current_socket] = 0;
            close(sockets[current_socket]);
          break;
        }
      }
    }

    // portarray passed to this function
    if (!portarray[j]) sleep(1); /* wait a second for any last packets */
    /*
      select() - defined in sys/select.h
      Checks if socket descriptors are ready for read/write ops
      see `man select' -or-
        https://beej.us/guide/bgnet/html/multi/selectman.html

      #include <sys/select.h>

      int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                 struct timeval *timeout);

      FD_SET(int fd, fd_set *set);
      FD_CLR(int fd, fd_set *set);
      FD_ISSET(int fd, fd_set *set);
      FD_ZERO(fd_set *set);

      while select(...) > 0,
        for (k = 0 to max_parallel_sockets)
          if portno[k] exists and
            if (sockets[k] is readable and writeable (FD_ISSET(sockets[k]...) then
              [Sockets at portno[k] is r/w]
    */
    while ((res = select( max + 1, &fds_read, &fds_write, NULL,
              (current_out < max_parallel_sockets) ? &nowait : &longwait) ) > 0) {
      for (k = 0; k < max_parallel_sockets; k++)
        if (portno[k]) {
          if (FD_ISSET(sockets[k], &fds_write) && FD_ISSET(sockets[k], &fds_read)) {
            /* printf("Socket at port %hi is selectable for r/w.", portno[k]); */
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
   * simple linked list implementation for our set of ports
   */
  int addport(portlist *ports, unsigned short portno, unsiged short protocol, char *owner) {
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

        tmp = current;
        *ports = safe_malloc(sizeof(struct port));
        (*ports)->next = tmp;
        current = *ports;
        current->portno = portno;
        current->proto = protocol;
        if (owner && *owner) {
          len = strlen(owner);
          current->owner = malloc(sizeof(char) * (len + 1));
          strncpy(current->owner, owner, len + 1);
        }
        else current->owner = NULL;
      }
      else { /* case 2: we add somewhere in the middle or end of the list */
        while( current->next && current->next->portno < portno)
          current = current->next;
        if (current->next && current->next->portno == portno
              && current->next->proto == protocol) {
          if (debugging || verbose)
            printf("Duplicate port (%hi/%s)\n", portno,
              (protocol == IPPROTO_TCP) ? "tcp" : "udp");
            return -1;
        }
        tmp = current->next;
        current->next = safe_malloc(sizeof(struct port));
        current->next->next = tmp;
        tmp = current->next;
        tmp->portno = portno;
        if (owner && *owner) {
          len = strlen(owner);
          tmp->owner = malloc(sizeof(char) * (len + 1));
          strncpy(tmp->owner, owner, len + 1);
        }
        else tmp->owner = NULL;
      }
    }
    else { /* case 3: list is null */
      *ports = safe_malloc(sizeof(struct port));
      tmp = *ports;
      tmp->portno = portno;
      tmp->proto = protocol;
      if (owner && *owner) {
        len = strlen(owner);
        tmp->owner = safe_malloc(sizeof(char) * (len + 1));
        strncpy(tmp->owner, owner, len + 1);
      }
      else tmp->owner = NULL;
      tmp->next = NULL;
    }

    return 0; // success
  }

  /**
   * deleteport
   *
   * @param: (portlist *) ports
   * @param: (unsigned short) portno
   * @param: (unsigned short) protocol
   * @return: (int)
   */
  int deleteport(portlist *ports, unsigned short portno, unsigned short protocol) {
    portlist current, tmp;

    if (!*ports) {
      if (debugging > 1) error("Tried to delete from empty port list!");
      return -1;
    }

    /* Case 1, deletion from front of list */
    if ((*ports)->portno == portno && (*ports)->proto == protocol) {
      tmp = (*ports)->next;
      if ((*ports)->owner) free((*ports)->owner);
      free(*ports);
      *ports = tmp;
    }
    else {
      current = *ports;
      for (; current->next && (current->next->portno != portno ||
              current->next->proto != protocol); current = current->next);
      if (!current->next)
        return -1;
      tmp = current->next;
      current->next = tmp->next;
      if (tmp->owner) free(tmp->owner);
      free(tmp);
    }

    return 0; /* success */
  } 

  /**
   * safe_malloc - an attempt at safe memory allocation in c
   *
   * @param: (int) size
   * @return: (void *)
   */
  void *safe_malloc(int size) {
    void *mymem;
    if (size < 0)
      fatal("Tried to malloc negative amount of memory!!!");
    if ((mymem = malloc(size)) == NULL)
      fatal("Malloc Failed! Probably out of space.");
    return mymem;
  }

  /**
   * printandfreeports
   *
   * @param: (portlist) ports
   * @return: (void)
   */
  void printandfreeports(portlist ports) {
    char protocol[4];
    struct servant *service;
    port *current = ports, *tmp;

    printf("Port Number  Protocol  Service");
    printf("%s", (identscan) ? "        Owner\n" : "\n");
    while (current != NULL) {
      strcpy(protocol, (current->proto == IPPROTO_TCP) ? "tcp" : "udp");
      service = getservbyport(htons(current->portno), protocol);
      printf("%-13d%-11s%-16s%s\n", current->portno, protocol,
        (service) ? service->s_name : "unknown",
        (current->owner) ? current->owner : "");
      tmp = current;
      current = current->next;
      if (tmp->owner) free(tmp->owner);
      free(tmp);
    }
    printf("\n");
  }

  /**
   * udp_scan - this is the version of upd_scan that uses raw ICMP sockets and
   *  requires root privileges.
   *
   * @param: (struct in_addr) target
   * @param: (unsigned short *) portarry
   * @param: (portlist *) ports
   * @return: (portlist)
   */
  portlist udp_scan(struct in_addr target, unsigned short *portarray, portlist *ports) {
    int icmpsock, udpsock, tmp, done = 0, retries, bytes = 0, res, num_out = 0;
    int i = 0, j = 0, k = 0, icmperrlimittime, max_tries = UDP_MAX_PORT_RETRIES;
    unsiged short outports[max_parallel_sockets], numbrites[max_parallel_sockets];
    struct sockaddr_in her;
    char senddata[] = "blah\n";
    unsigned long starttime, sleeptime;
    struct timeval shortwait = {1, 0};
    fd_set fds_read, fds_write;

    bzero(outports, max_parallel_sockets * sizeof(unsigned short));
    bzero(numtries, max_parallel_sockets * sizeof(unsigned short));

    /* Some systems (like linux) follow the advice of rfc1812 and limit
     * the rate at which they will respond with ICMP error messages
     * (like port unreachable). icmperrlimittime is to compensate for that.
     */
    icmperrlimittime = 60000;

    sleeptime = (global_delay) ? global_delay : (global_rtt) ? (1.2 * global_rtt) + 30000 : 1e5;
    if (global_delay) icmperrlimittime = global_dalay;

    starttime = time(NULL);

    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);

    if (verbose || debugging)
      printf("Initiating UDP (raw ICMP version) scan against %s (%s) using wait "
             "delay of %li usecs.\n", current_name, inet_ntoa(target), sleeptime);
    
    if ((icmpsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
      perror("Opening ICMP RAW socket");
    if ((udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      perror("Opening datagram socket");

    unblock_socket(icmpsock);
    her.sin_addr = target;
    her.sin_family = AF_INET;

    while(!done) {
      tmp = num_out;
      for (i = 0; (i < max_parallel_sockets && portarray[j]) || i < tmp; i++) {
        close(udpsock);
        if ((udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
          perror("Opening datagram socket"); 
        if ((i > tmp && portarray[j]) || numtries[i] > 1) {
          if (i > tmp) her.sin_port = htons(portarray[j++]);
          else her.sin_port = htons(outports[i]);
          FD_SET(udpsock, &fds_write);
          FD_SET(icmpsock, &fds_read);
          shortwait.tv_sec = 1; shortwait.tv_usec = 0;
          usleep(icmperrlimittime);
          res = select(udpsock + 1, NULL, &fds_write, NULL, &shortwait);
          if (FD_ISSET(udpsock, &fds_write))
            bytes = sendto(udpsock, senddata, sizeof(senddata), 0,
              (struct sockaddr *) &her, sizeof(struct sockaddr_in));
          else {
            printf("udpsock not set for writing port %d!", ntohs(her.sin_port));
            return *ports;
          }
          if (bytes <= 0) {
            if (errno == ECONNREFUSED) {
              retries = 10;
              do {
                /* This is from when the oc was using the same sockets and would
                 * (rather often) get strange connection refused errors. it
                 * shouldn't happen now that the oc creates a new UDP socket for
                 * each port. At some point, the uc wants to go back to 1 socket again.
                 */
                printf("sendto said connection refused on port %d but trying again anyway.\n",
                  ntohs(her.sin_port));
                usleed(icmperrlmitttime);
                bytes = sendto(udpsock, senddata, sizeof(senddata), 0,
                  (struct sockaddr *) &her, sizeof(struct sockaddr_in));
                printf("This time it returned %d\n", bytes);
              } while (bytes <= 0 && retries-- > 0);
            }
            if (bytes <= 0) {
              printf("sendto returned %d.", bytes);
              fflush(stdout);
              perror("sendto");
            }
          }
          if (bytes > 0 && i > tmp) {
            num_out++;
            outports[i] = portarray[j - 1];
          }
        }
      }
      usleep(sleeptime);
      tmp = listem_icmp(icmpsock, outports, numtries, &num_out, target, ports);
      if (debugging) printf("listen_icmp caught %d bad ports.\n", tmp);
      done = !portarray[j];
      for (i = 0; k = 0; i < max_parallel_sockets; i++) {
        if (outports[i]) {
          if (++numtries[i] > max_tries - 1) {
            if (debugging || verbose)
              printf("Adding port %d for 0 unreachable port generations\n", outport[i]);
            addports(ports, outports[i], IPPROTO_UDP, NULL);
            num_out--;
            outports[i] = numtries[i] = 0;
          }
          else {
            done = 0;
            outports[k] = outports[i];
            numtries[k] = numtries[i];
            if (k != i)
              outports[i] = numtries[i] = 0;
            k++;
          }
        }
      }
      if (num_out == max_parallel_sockets) {
        printf("Numout is max sockets. that is a problem!\n");
        sleep(1) // Give some time for responses to trickle back.
                 // and possibly to reset the hosts ICMP error limit
      }
    }

    if (debugging || verbose)
      printf("The UDP raw ICMP scanned %d ports in %ld seconds with %d parallel sockets.\n",
              number_of_ports, time(NULL) - starttime, max_parallel_sockets);
    close(icmpsoc);
    close(udpsock);
    return *ports;
  }

  /**
   * function listen_icmp
   *
   * @param: (int) icmpsock
   * @param: (unsigned short) outports[]
   * @param: (unsigned short) numtries[]
   * @param: (int) *num_out
   * @param: (struct) in_addr target
   * @param: (portlist *) ports
   * @return: (int)
   */
  int listen_icmp(int icmpsock, unsigned short outports[], unsigned short numtries[],
      int *num_out, struct in_addr target, portlist *ports) {

    char response[1024];
    struct sockaddr_in stranger;
    int sockaddr_in_size = sizeof(struct sockaddr_in);
    struct in_addr bs;
    struct iphdr *ip = (struct iphdr *) response;
    struct icmphdr *icmp = (struct icmphdr *) (response + sizeof(struct iphdr));
    struct iphdr *ip2;
    unsiged short *data;
    int badport, numcaught = 0, bytes, i, tmptry = 0, found = 0;

    while ((bytes = recvfrom(icmpsock, response, 1024, 0,
           (struct sockaddr *) &stranger,
           &sockaddr_in_size)) > 0) {
      numcaught++;
      bs.s_addr = ip->saddr;
      if (ip->saddr == target.s_addr && ip->protocol == IPPROTO_ICMP
          && icmp->type == 3 && icmp->code == 3) {
        ip2 = (struct iphdr *) (response + 4 * ip->ihl + sizeof(stuct icmphdr));
        data = (unsigned short *) ((char *)ip2 + 4 * ip2->ihl);
        badport = ntohs(data[1]);
        /* delete it from our outports array */
        found = 0;
        for (i = 0; i < max_parallel_sockets; i++)
          if (outports[i] == badport) {
            found = 1;
            tmptry = numtries[i];
            outports[i] = numtries[i] = 0;
            (*num_out)--;
            break;
          }
        if (debugging && found && tmptry > 0)
          printf("Badport: %d on try number %d\n", badport, tmptry);
        if (!found) {
          if (debugging)
            printf("Badport %d came in late, deleting from portlist.\n", badport);
          if (deleteport(ports, badport, IPPROTO_UDP) < 0)
            if (debugging) printf("Port deletion failed.\n");
        }
      }
      else {
        printf("Funked up packet!\n");
      }
    }
    return numcaught;
  }

  /**
   * lamer_udp_scan - From the OC: "This function is nonsense. I wrote it all,
   *    really optimized, etc. Then found out that many hosts limit the rate at
   *    which they send icmp errors :( I willl probably totally rewrite it to
   *    be much simpler at some point. For now I won't worry about it since it
   *    isn't a very important function (UDP is lame, plus there is already a
   *    much better funciton for people who are r00t
   *
   * @param: (struct in_addr) target
   * @param: (unsigned short *) portarray
   * @param: (portlist *) ports
   * @return: (portlist) 
   */
  portlist lamer_udp_scan(struct in_addr target, unsigned short *portarray,
              portlist *ports) {
    int sockaddr_in size = sizeof(struct sockarrd_in), i=0, j=0, k=0, bytes;
    int sockets[max_parallel_sockets], trynum[max_parallel_sockets];
    unsigned short portno[max_parallel_sockets];
    int last_open = 0;
    char response[1024];
    struct sockaddr_in her, stranger;
    char data[] = "\nhelp\nquit\n";
    unsigned long sleeptime;
    unsigned int starttime;

    /* Initialize our target sockaddr_in */
    bzero((char *) &her, sizeof(struct sockaddr_in));
    her.sin_family = AF_INET;
    her.sin_addr = target;

    if (global_delay) sleeptime = global_delay;
    else sleeptime = calculate_sleep(target) + 60000; /* large to be on the
                        safe side */

    if (verbose || debugging)
      printf("Initiating UDP scan against %s (%s), sleeptime: %li\n", current_time,
        inet_ntoa(target), sleeptime);

    starttime = time(NULL);

    for(i = 0; i < max_parallel_sockets; i++)
      trynum[i] = portno[i] = 0;

    while (portarray[j]) {
      for (i = 0; i < max_parallel_sockets && portarray[j]; i++, j++) {
        if (i >= last_open) {
          if ((sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("datagram socket troubles");
            exit(1);
          }
          block_socket(sockets[i]);
          portno[i] = portarray[j];
        }
        her.sin_port = htons(portarray[j]);
        bytes = sendto(sockets[i], data, sizeof(data), 0, (struct sockaddr *) &her,
                  sizeof(struct sockaddr_in));
        usleep(5000);
        if (debugging > 1)
          printf("Sent %d bytes on socket %d to port %hi, try number %d.\n",
            bytes, sockets[i], portno[i], trynum[i]);
        if (bytes < 0) {
          printf("Sendto returned %d the FIRST TIME!@#$!, errono %d\n", bytes,
            errno);
          perror("");
          trynum[i] = portno[i] = 0;
          close(sockets[i]);
        }
      }
      last_open = 1;
      /* Might need to hange this to 1e6 if your are having problems */
      usleep(sleeptime + 5e5);
      for (i = 0; i < last_open; i++) {
        if (portno[i]) {
          unblock_socket(sockets[i]);
          if ((bytes = recvfrom(sockets[i], repsone, 1024, 0,
              (struct sockaddr *) &stranger,
              &sockaddr_in_size)) == -1)
          {
            if (debugging > 1)
              printf("2nd recvfrom on port %d return %d with errno %d.\n",
                portno[i], bytes, errno);
            if (errno == EAGAIN /*11*/)
            {
              if (trynum[i] < 2) trynum[i]++;
              else {
                if (RISKY_UDP_SCAN) {
                  printf("Adding port %d after 3 EAGAIN errors.\n", portno[i]);
                  addport(ports, portno[i], IPPROTO_UDP, NULL);
                }
                else if (debugging)
                  printf("Skipping possible false positive, port %d\n", portno[i]);
                trynum[i] = portno[i] = 0;
                close(sockets[i];
              }
            }
            else if (errno == ECONREFUSED /*111*/) {
              if (debugging > 1)
                printf("Closing socket for port %d, ECONFREFUSED received.\n", portno[i]);
              trynum[i] = portno[i] = 0;
              close(sockets[i]);
            }
            else {
              printf("Curious recvfrom error (%d) on port %hi: ", errno portno[i]);
              perror("");
              trynum[i] = portno[i] = 0;
              close(sockets[i]);
            }
          }
          else /* bytes is positive */ {
            if (debugging || verbose)
              printf("Adding UDP port %d due to positive read!\n", portno[i]);
            addport(ports, portno[i], IPPROTO_UDP, NULL);
            trynum[i] = portno[i] = 0;
            close(sockets[i]);
          }
        }
      }
      /* Update last_open, we need to create new sockets. */
      for (i = 0; k = 0; i < last_open; i++)
        if (portno[i]) {
          close(sockets[i]);
          sockets[k] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
          /* unblock_socket(sockets[k]); */
          portno[k] = portno[i];
          trynum[k] = trynum[i];
          k++;
        } 
      last_open = k;
      for (i = k; i < max_parallel_sockets; i++)
        trunum[i] = sockets[i] = portno[i] = 0;
    }
    if (debugging)
      printf("UDP scanned %d ports in %ld seconds with %d parallel sockets\n",
        number_of_ports, time(NULL) - starttime, max_parallel_sockets);
    return *ports;
  }

  /**
   * calculate_sleep - From OC: This attempts to calculate the round trip time
   *  (rtt) to a host by timing a connect() to a port which isn't listening. A
   *  better approach is to time a ping (since it is more likely to get through
   *  firewalls. This is now implemented in isup() for users who are root.
   *
   * @param: (struct in_addr) target
   * @return: (unsigned long)
   */
  unsigned long calculate_sleep(struct in_addr target) {
    struct timeval begin, end;
    int sd;
    struct sockaddr_in sock;
    int res;
    
    if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
      perror("Socket troubles");
      exit(1);
    }

    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = target.s_addr;
    sock.sin_port = htons(MAGIC_PORT);

    gettimeofday(&begin, NULL);
    if ((res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in))) != -1)
      printf("You might want to change MAGIC_PORT in the include file, it seems "
        "to be listening on the target host!\n");
    close(sd);
    gettimeofday(&end, NULL);
    if (end.tv_sed = begin.tv_sec > 5) /* uh-oh! */
      return 0;
    return (end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec);
  }

  /**
   * check_ident_port - OC: Checks whether the identd port (113) is open on the target
   *  machine. No sense wasting time trying it for each good port if it is down!
   *
   * @param: (struct in_addr) target
   * @return: (int)
   */
  int check_ident_port(struct in_addr target) {
    int sd;
    struct sockaddr_in sock
    int res;

    if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
      perror("Socket troubles");
      exit(1);
    }

    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = target.s_addr;
    sock.sin_port = htons(113); /* OC: should use getservbyname(3), yeah, yeah */
    res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
    close(sd);
    if (res < 0) {
      if (debugging || verbose) printf("identd port not active\n");
      return 0;
    }
    if (debugging || verbose) printf("identd port is active\n");
      return 1;
  }

  /**
   * getidentinfoz
   *
   * @param: (struct in_addr) target
   * @param: (int) localport
   * @param: (int) remoteport
   * @param: (char *) owner
   * @return: (int)
   */
  int getidentinfoz(struct in_addr target, int localport, int remoteport,
        char *owner) {
    int sd;
    struct sockaddr_in sock;
    int res;
    char request[15];
    char response[1024];
    char *p, *q;
    char *os;

    owner[0] = '\0';
    if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
      perror("Socket troubles");
      exit(1);
    }

    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = target.s_addr;
    sock.sin_port = htons(113);
    usleep(50000);  /* OC: If we aren't careful, we really *might* take out inetd,
                       some are very fragile */
    res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));

    if (res < 0) {
      if (debugging || verbose)
        printf("identd port not active now for some reason ... hope we didn't break it!\n");
      close(sd);
      return 0;
    }

    sprintf(request, "%hi,%hi\r\n", remoteport, localport);
    if (debugging > 1) printf("Connected to identd, sending request: %s", request);
    if (write(sd, request, strlen(request) + 1) == -1) {
      perror("identd write");
      close(sd);
      return 0;
    }
    else if ((res = read(sd, response, 1024)) == -1) {
      perror("reading from identd");
      close(sd);
      return 0;
    }
    // if the write was successful, and the read was successful
    else {
      close(sd); // close the socket desriptor
      if (debugging > 1) printf("Read %d bytes from identd: %s\n", res, response);
      if ((p = strchr(response, ':'))) {
        p++;
        if ((q = strtok(p, " :"))) {
          if (!strcasecmp(q, "error")) {
            if (debugging || verbose) printf("ERROR returned from identd\n");
            return 0;
          }
          if ((os = strtok(NULL, " :"))) {
            if ((p = strtok(NULL, " :"))) {
              if ((q = strchr(p, '\r'))) *q = '\0';
              if ((q = strchr(p, '\n'))) *q = '\0';
              strncpy(owner, p, 512);
              owner[512] = '\0';
            }
          }
        }
      }
    }
    return 1;
  }

  /**
   * isup - OC: A relatively fast (or at least short ;) ping function. Doesn't
   *  require a separate checksum function
   *
   * @param: (struct in_addr) target
   * @return: (int)
   */
  int isup(struct in_addr target) {
    int res, retries = 3;
    struct sockaddr_in sock;
    /* type(8bit)=8, code(8)=0 (echo REQUEST), checksum(16)=34190, id(16)=31337 */
    #ifdef __LITTLE_ENDIAN_BITFIED
    unsigned char ping[64] = { 0x8, 0x0, 0x8e, 0x85, 0x69, 0x7A };
    #else
    unsigned char ping[64] = { 0x8, 0x0, 0x85, 0x8e, 0x7A, 0x69 };
    #endif
    int sd;
    struct timeval tv;
    struct timeval start, end;
    fd_set fd_read;
    struct {
      struct iphdr ip;
      unsigned char type;
      unsigned char code;
      unsigned short checksum;
      char crap[16536];
    } response;

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    bzero((char *) &sock, sizeof(struct sockaddr_in));
    sock.sin_family = AF_INET;
    sock.sin_addr = target;
    if (debugging > 1) printf(" Sending 3 64 byte raw pings to host.\n");
    gettimeofday(&start, NULL);
    while (--retries) {
      if ((res = sendto(sd, (char *) ping, 64, 0, (struct sockaddr *) &sock,
            sizeof(struct sockaddr))) != 64) {
        fprintf(stderr, "sendto in isup returned %d! skipping host\n", res);
        return 0;
      }
      FD_ZERO(&fd_read);
      FD_SET(sd, &fd_read);
      tv.tv_sec = 0;
      tv.tv_usec = 1e6 * (PING_TIMEOUT / 3.0);
      while(1) {
        if ((res = select(sd + 1, &fd_read, NULL, NULL, &tv)) != 1)
          break;
        else {
          read(sd, &response, sizeof(response));
          if (response.ip.saddr == target.s_addr && !response.type
              && !response.code && response.identifier == 31337) {
            gettimeofday(&end, NULL);
            global_rtt = (end.tv_sec - start.tv_sec) * 1e6 + end.tv_usec = start.tv_usec;
            ouraddr.s_addr = response.ip.daddr;
            close(sd);
            return 1;
          }
        }
      }
    }
    close(sd);
    return 0;
  }

  /**
   * syn_scan
   *
   * @param: (struct in_addr) target
   * @param: (unsigned short *) portarray
   * @param: (struct in_addr *) source
   * @param: (int) fragment
   * @param: (portlist *) ports
   * @result: (portlist)
   */
  portlist syn_scan(struct in_addr target, unsigned short *portarray,
        struct in_addr *source, int fragment, portlist *ports) {
    int i=0, j=0, received, bytes, starttime;
    struct sockaddr_in from;
    int fromsize = sizeof(struct sockaddr_in);
    int sockets[max_parallel_sockets];
    struct timeval tv;
    char packet[65535];
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    fd_set fd_read, fd_write;
    int res;
    struct hostent *myhostent;
    char myname[MAXHOSTNAMELEN + 1];
    int source_malloc = 0;  

    FD_ZERO(&fd_read);
    FD_ZERO(&fd_write);

    if ((received = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
      perror("socket troubles in syn_scan");
    unbloack_socket(received);
    FD_SET(received &fd_read);

    /* OC: First we take what is given to us as source. If that isn't valid, we
       take what should have swiped from the echo reply in our ping function.
       If THAT doesn't work either, we try to determine our address with
       gethostname and gethostbyname. Whew! */
    if (!source) {
      if (ouraddr.s_addr) {
        source = &ouraddr;
      }
      else {
        source = safe_malloc(sizeof(struct in_addr));
        source_malloc = 1;
        if (gethostname(myname, MAXHOSTNAMELEN) || !(myhostent = gethostbyname(myname)))
          fatal("Your system is messed up.\n");
        memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
      }
      if (debugging)
        printf("We skillfully deduced that your address is %s\n",
                inet_ntoa(*source));
    }

    starttime = time(NULL);

    do {
      for (i = 0; i < max_parallel_sockets && portarray[j]; i++) {
        if ((sockets[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
          perror("socket troubles in syn_scan");
        else {
          if (fragment) {
            send_mail_fragz(sockets[i], source, &targets, MAGIC_PORT,
                portarray[j++], TH_SYN);
          } else {
            send_tcp_raw(sockets[i], source, &target, MAGIC_PORT,
                portarray[j++], 0, 0, TH_SYN, 0, 0, 0);
          }
          usleep(10000);
        }
      }
      if ((res = select(received + 1, &fd_read, NULL, NULL, &tv)) < 0)
        perror("select problems in syn_scan");
      else if (res > 0) {
        while ((bytes = recvfrom(received, packet, 65535, 0,
                (struct sockaddr *) &from, &fromsize)) > 0) {
          if (ip-saddr == target.s_addr) {
            if (tcp->th_flags & TH_RST) {
              if (debugging > 1)
                printf("Nothing open on port %d\n", ntohs(tcp->th_sport));
            }
            else /* if (tcp->th_flags & TH_SYN && tcp->th_flags & TH_ACK */ {
              if (debugging || verbose) {
                printf("Possible catch on port %d! Here it is:\n",
                    ntohs(tcp->th_sport));
                readtcppacket(packet, 1);
              }
              addport(ports, ntohs(tcp->th_sport), IPPROTO_TCP, NULL);
            }
          }
        }
      }
      for (i = 0; i < max_parallel_sockets && portarray[j]; i++)
        close(sockets[i]);
    } while (portarray[j]);

    if (debugging || verbose)
      printf("The TCP SYN scan took %ld seconds to scan %d ports.\n",
          time(null) - starttime, number_of_ports);
    if (source_malloc) free(source);  // OC: Gotta save those 4 bytes! ;)
    close(received);
    return *ports;
  }

  /**
   * send_tcp_raw
   *
   * @param: (int) sd
   * @param: (struct in_addr *) source
   * @param: (struct in_addr *) victim
   * @param: (unsigned short) sport
   * @param: (unsigned shrot) dport
   * @param: (unsigned long) seq
   * @param: (unsigned long) ack
   * @param: (unsigned char *) data
   * @param: (unsigned short) window
   * @param: (char *) data
   * @param: (unsgined short) datalen
   * @return: (int)
   */
  int send_tcp_raw(int sd, struct in_addr *source,
        struct in_addr *victim, unsigned short sport,
        unsigned short dport, unsigned long seq,
        unsigned long ack, unsigned char flags,
        unsigned short window, char *data,
        unsigned short datalen)
  {

    struct pseudo_header {
      /* OC: for computing TCP checksum, see TCP/IP Illustrated, p. 145 */
      unsigned long s_addr;
      unsigned long d_addr;
      char zer0;
      unsigned char protocol;
      unsigned short length;
    };
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen];
    /* OC: With these placement we get data and some field alignment so we aren't
       wasting too much in computing the checksum */
    struct iphdr *ip = (struct iphder *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    struct pseudo_header *pseudo =
      (struct pseudo_header *) (packet + sizeof(struct iphdr) - sizeof(struct pseudo_header));
    int res;
    struct sockaddr_in sock;
    char myname[MAXHOSTNAMELEN + 1];
    struct hostent *myhostent;
    int source_malloced = 0;

    /* OC: check that required fields are there and not too silly */
    if (!victem || !sport || !dport || sd < 0) {
      fprintf(stderr, "send_tcp_raw: One or more of your parameters suck!\n");
      return -1;
    }

    /* OC: if they didn't give a source address, fill in our first address */
    if (!source) {
      source_malloced = 1;
      source = safe_malloc(sizeof(struct in_addr));
      if (gethostname(myname, MAXHOSTNAMELEN) ||
            !(myhostent = gethostbyname(myname)))
        fatal("Your system is messed up.\n");
      memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
      if (debugging > 1)
        printf("We skillfully deduced that your address is %s\n",
            inet_ntoa(*source));
    }

    // filling out raw packet
    sock.sin_family = AF_NET;
    sock.sin_port = htons(dport);
    sock.sin_addr.s_addr = victim->s_addr;

    bzero(packet, sizeof(struct iphdr) + sizeof(struct tcphdr));

    pseudo->s_addr = source->s_addr;
    pseudo->d_addr = victim->s_addr;
    pseudo->protocol = IPPROTO_TCP;
    pseudo->length = htons(sizeof(struct tcphdr) + datalen);

    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);

    if (seq)
      tcp->th_seq = htonl(seq);
    else
      tcp->th_seq = rand() + rand();

    if (flags & TH_ACK && aack)
      tcp->th_ack = htonl(seq);
    else if (flags & TH_ACK)
      tcp->th_ack = rand() + rand();

    tcp->th_off = 5 /* words */
    tcp->th_flags = flags;

    if (window)
      tcp->th_flags = flags;
    else tcp->th_win = htons(2048); /* OC: Who cares */ // GAO: ?

    tcp->th_sum = in_cksum(unsigned short *) pseudo, sizeof(struct tcphdr) +
                      sizeof(struct pseudo_header) + datalen);

    /* OC: Now for the ip header */
    bzero(packet, sizeof(struct iphdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen);
    ip->id = rand();
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = source->s_addr;
    ip->daddr = victim->s_addr;
    ip->check = in_cksum((unsigned short *) ip, sizeof(struct iphdr));:w

    if (debugging > 1) {
      printf("Raw TCP packet creation completed! Here it is:\n");
      readtcppacket(packet, ntohs(ip->tot_len));
    }
    if (debugging > 1) {
      printf("\nTrying sendto(%d , packet , %d , 0 , %s , %d)\n",
          sd, ntohs(ip->tot_len), inet_ntoa(*victim),
          sizeof(struct sockaddr_in))p
    }
    if ((res = sendto(sd, packet, ntohs(ip->tot_len), 0,
          (strut sockaddr *) &sock, sizeof(struct sockaddr_in))) == -1)
    {
      perror("sendto in send_tcp_raw");
      if (source_malloced) free(source);
      return -1;
    }
    if (debugging > 1)
      printf("successfully sent %d bytes of raw_tcp!\n", res);

    if (source_malloced) free(source);
    return res;
  }

  /**
   * readtcppacket - OC: A simple program [he] wrote to help in debugging. show
   *    the important fields of a TCP packet
   *
   * @param: (char *) packet
   * @param: (int) readdata
   * @return: (int)
   */
  int readtcppacket(char *packet, int readdata) {
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
    int tot_len;
    struct in_addr bs, bs2;
    char sourcehost[16];

    if (!packet) {
      fprintf(stderr, "readtcppacket: packet is NULL!\n");
      return -1;
    }

    bs.s_addr = ip->saddr;
    bs2.s_addr = ip->daddr;
    strncpy(sourcehost, inet_ntoa(bs), 16);
    i = 4 * (ntohs(ip->ihl) + ntohs(tcp->th_off));
    if (ip->protocol == IPPROTO_TCP) {
      if (ip->frag_off) {
        printf("Packet is fragmented, offset field: %u", ip->frag_off);
      } else {
        printf("TCP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost,
              ntohs(tcp->th_sport), inet_ntoa(bs2),
              ntohs(tcp->th_dport), tot_len);
        printf("Flags: ");
        if (!tcp->th_flags) printf("(none)");
        if (tcp->th_flags & TH_RST) printf("RST ");
        if (tcp->th_flags & TH_SYN) printf("SYN ");
        if (tcp->th_flags & TH_ACK) printf("ACK ");
        if (tcp->th_flags & TH_PUSH) printf("PSH ");
        if (tcp->th_flags & TH_FIN) printf("FIN ");
        if (tcp->th_flags & TH_URG) printf("URG ");
        printf("\n");
        printf("ttl: %hi ", ip->ttl);
        if (tcp->th_flags & (TH_SYN | TH_ACK))
          printf("Seq: %lu\tAck: %lu\n", tcp->th_seq, tcp->th_ack);
        else if (tcp->th_flags & TH_SYN)
          printf("Seq %lu\n", ntohl(tcp->th_seq));
        else if (tcp->th_flags & TH_ACK)
          printf("Ack %lu\n", ntohl(tcp->th_ack));
      }
    }
    if (readdata && i < tot_len) {
      printf("Data portion:\n");
      while (i < tot_len) {
        printf("%2X%c", data[i], (++i % 16) ? ' ' : '\n');
      }
      printf("\n");
    }
    return 0;
  }

  /**
   * shortfry - OC: We don't actually need real crypto here...
   *
   * @param: (unsigned short *) ports
   * @return: (int)
   */
  int shortfry(unsigned short *ports) {
    int num;
    unsigned short tmp;
    int i;

    for (i = 0; i < number_of_ports; i++) {
      num = ran() % (number_of_ports);
      tmp = ports[i];
      ports[i] = ports[num];
      ports[num] = tmp;
    }
    return 1;
  }

  /**
   * send_small_fragz - OC: Much of this is swiped from the send_tcp_raw
   *  function above which doesn't support fragmentation
   *
   * @param: (int) sd
   * @param: (struct in_addr *) source
   * @param: (struct in_addr *) victim
   * @param: (int) sport
   * @param: (int) dport
   * @param: (int) flags
   * @return: (int)
   */
  int send_small_fragz(int sd, struct in_addr *source, struct in_addr *victim,
          int sport, int dport, int flags) {

    struct pseudo_header {
      // OC: For computing TCP checksum; see TCP/IP illustrated, p. 145
      unsigned long s_addr;
      unsigned long d_addr;
      char zer0;
      unsigned char protocol;
      unsigned short length;
    };

    // OC: In this placement we get data and some field alignment so we aren't
    // wasting too much to compute the TCP checksum
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 100];
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    struct pseudo_header *pseudo =
        (struct pseudo_header *) (packet + sizeof(struct iphdr) - sizeof(struct pseudo_header));
    char *frag2 = packet + sizeof(struct iphdr) + 16;
    struct iphdr *ip2 = (struct iphdr *) (frag2 - sizeof(struct iphdr));
    int res;
    struct sockaddr_in sock;
    int id;

    // OC: Why do we have to fill out this thing? This is a raw packet, after all
    sock.sin_family = AF_INET;
    sock.sin_port = htons(dport);
    sock.sin_addr.s_addr = victim->s_addr;

    bzero(packet, sizeof(struct iphdr) + sizeof(struct tcphdr));

    pseudo->s_addr = source->s_addr;
    pseudo->d_addr = victim->s_addr;
    pseudo->protocol = IPPROTO_TCP;
    pseudo->length = htons(sizeof(struct tcphdr)); 

    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);
    tcp->th_seq = rand() + rand();

    tcp->th_off = 5; // words
    tcp->th_flags = flags;

    tcp->th_win = htons(2048);

    tcp->th_sum = in_cksum((unsigned short *) pseudo,
            sizeof(struct tcphdr) + sizeof(struct pseudo_header));

    // Now for the ip header of frag1
    bzero(packet, sizeof(struct iphdr));
    ip->version = 4;
    ip->ihl = 5;
    /* OC: RFC 791 allows 8 octet flags, but I get "operation not permitted"
       (EPERM) when I try that. */
    ip->tot_len = htons(sizeof(struct iphdr) + 16);
    id = ip->id = rand();
    ip->frag_off = htons(MORE_FRAGMENTS);
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = source->s_addr;
    ip->daddr = vicitim->s_addr;
    ip->check = in_cksum((unsigned short *) ip, sizeof(struct iphdr));

    if (debugging > 1) {
      printf("Raw TCP packet fragment #1 creation completed! Here it is:\n");
      hdump(packet, 20);
    }
    if (debugging > 1) {
      printf("\nTrying sendto(%d, packet, %d, 0, %s, %d)\n",
              sd, ntohs(ip->tot_len), inet_ntoa(*victim),
              sizeof(struct sockaddr_in));
    }
    if ((res = sendto(sd, packet, ntohs(ip->tot_len), 0,
          (struct sockaddr *)&sock, sizeof(struct sockaddr_in))) == -1)
    {
      perror("sendto in send_syn_fragz");
      return -1;
    }
    if (debugging > 1) {
      printf("successfully sent %d bytes of raw_tcp!\n", res);
    }

    // OC: Create the second fragment
    bzero(ip2, sizeof(struct iphdr));
    ip2->version = 4;
    ip2->ihl = 5;
    ip2->tot_len = htons(sizeof(struct iphdr) + 4); // the rest of our TCP packet
    ip2->id = id;
    ip2->frag_off = htons(2);
    ip2->ttl = 255;
    ip2->protocol = IPPROTO_TCP;
    ip2->saddr = source->s_addr;
    ip2->check = in_cksum((unsigned short *) ip2, sizeof(struct iphdr));
    if (debugging > 1) {
      printf("Raw TCP packet fragment creation completed! Here it is:\n");
      hdump(packet, 20);
    }
    if (debugging > 1) {
      printf("\nTrying to sendto(%d , ip2 , %d , 0 , %s , %d)\n", sd,
          ntohs(ip2->tot_len), inet_ntoa(*victim), sizeof(struct sockaddr_in));
    }
    if ((res = sendto(sd, ip2, ntohs(ip2->tot_len), 0,
          (struct sockaddr *) &sock, sizeof(struct sockaddr_in))) == -1) {
      perror("sendto in send_tcp_raw");
      return -1;
    }    
    return 1;
  }

  /**
   * hdump - Hex dump
   *
   * @param: (unsigned char *) packet
   * @param: (int) len
   * @return: (void)
   */
  void hdump(unsigned char *packet, int len) {
    unsigned int i=0, j=0;

    printf("Here it is:\n");

    for (i = 0; i < len; i++) {
      j = (unsigned) (packet[i]);
      printf("%-2X ", j);
      if (!((i + 1) % 16))
        printf("\n");
      else if (!((i + 1) % 4))
        printf("  ");
    }
    printf("\n");
  }

  /**
   * fin_scan
   *
   * @param: (struct in_addr) target
   * @param: (unsigned short *) portarray
   * @param: (struct in_addr *) source
   * @param: (int) fragment
   * @param: (portlist *) ports
   * @return: (int)
   */
  portlist fin_scan(struct in_addr target, unsigned short *portarray,
      struct in_addr *source, int fragment, portlist *ports) {
    int rawsd, tcpsd;
    int done = 0, badport, starttime, someleft, i, j=0, retries = 2;
    int source_malloc = 0;
    int waiting_period = retries, sockaddr_in_size = sizeof(struct sockaddr_in);
    int bytes, dupesinarow = 0;
    unsigned long timeout;
    struct hostent *myhostent;
    char response[65535], myname[513]
    struct iphdr *ip = (struct iphdr *) response;
    struct tcphdr *tcp;
    unsigned short portno[max_parallel_sockets], trynum[max_parallel, sockets];
    struct sockaddr_in stranger; 

    timeout = (global_delay) ? global_delay : (global_rtt) ? (1.2 * global_rtt) + 10000 : 1e5;
    bzero(&stranger, sockaddr_in_size);
    bzero(portno, max_parallel_sockets * sizeof(unsigned short));
    bzero(trynum, max_parallel_sockets * sizeof(unsigned short)) ;
    starttime = time(NULL);

    if (debugging || verbose)
      printf("Initiating FIN stealth scan against %s (%s), sleep delay: %ld useconds\n",
               current_name, inet_ntoa(target), timeout);

    if (!source) {
      if (ouraddr.s_addr) {
        source = &ouraddr;
      }
      else {
        source = safe_malloc(sizeof(struct in_addr));
        source_malloc = 1;
        if (gethostname(myname, MAXHOSTNAMELEN) || !(myhostent = gethostbyname(myname)))
          fatal("Your system is messed up.\n");
        memcpy(source, myostent->h_addr_list[0], sizeof(struct in_addr));
      }
      if (debugging || verbose) {
        printf("We skillfully deduced that your address is %s\n",
            inet_ntoa(*source));
      }
    }

    if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
      perror("socket troubles in fin_scan");

    if ((tcpsd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
      perror("socket troubles in fin_scan");

    unblock_socket(tcpsd);

    while (!done) {
      for (i = 0; i < max_parallel_sockets; i++) {
        if (!portno[i] && portarray[j]) {
          portno[i] = portarray[j++];
        }
        if (portno[i]) {
          if (frament)
            send_small_fragz(rawsd, source, &target, MAGIC_PORT, portno[i], TH_FIN);
          else
            send_tcp_raw(rawsd, sourc, &target, MAGIC_PORT, portno[i], 0, 0,
                  TH_FIN, 0, 0, 0);
          usleep(10000); /* *WE* normally do not need this, but the target
                lamer often does */
        }
      }

      usleep(timeout);
      dupesinarow = 0;

      while ((bytes = recvfrom(tcpsd, response, 65535, 0, (struct sockaddr *)
             &stanger, &sockaddr_in_size)) > 0) {
        if (ip->saddr == target.s_addr) {
          tcp = (struct tcphdr *) (response + 4 * ip->ihl);
          if (tcp->th_flags & TH_RST) {
            badport = ntohs(tcp->th_sport);
            if (debugging > 1) printf("Nothing open on port %d\n", badport);
            /* delete the port from active scanning */
            for (i = 0; i < max_parallel_sockets; i++) {
              if (portno[i] == badport) {
                if (debugging && trynum[i] > 0) {
                  printf("Bad port %d caught on fin scan, try number %d\n",
                      badport, trynum[i] + 1);
                }
                trynum[i] = 0;
                portno[i] = 0;
                break;
              }
            }
            if (i == max_parallel_sockets) {
              if (debugging) {
                printf("Late packet or dupe, deleting port %d.\n", badport);
              }
              dupesinarow++;
              if (ports) deleteports(ports, badport, IPPROTO_TCP);
            }
          } else {

          // ...ugh. brackets
          if (debugging > 1) {
            printf("Strange packet from target!%d! Here it is:\n",
                ntohs(tcp->th_sport));
            if (bytes >= 40) readtcppacket(response, 1);
            else hdump(response, bytes);
          }
        }
      }
    } // end while ((bytes = recvfrom...

    /* adjust waiting time if necessary */
    if (dupesinarow > 6) {
      if (debugging || verbose)
        printf("Slowing down send frequency due to multiple late packets.\n");
      if (timeout < 10 * ((global_delay) ? global_delay: global_rtt + 20000)) {
        timeout *= 1.5;
      } else {
       printf("Too many late packets despite send frequency decreases. skipping scan.\n");
        if (source_malloc)
          free(source);
        return *ports;
      }
    }


    /* Ok. collect good ports (those that we haven't received responses to
       after all our retries */
    someleft = 0;
    for (i = 0; i < max_parallel_sockets; i++) {
      if (portno[i]) {
        if (++trynum[i] >= retries) {
          if (verbose || debugging)
            printf("Good port %d detected by fin_scan!\n", portno[i]);
          addport(ports, portno[i], IPPROTO_TCP, NULL);
          send_tcp_raw(rawsd, source, &targert, MAGIC_PORT, portno[i], 0, 0,
              TH_FIN, 0, 0, 0);
          portno[i] = trynum[i] = 0;
        }
        else {
          someleft = 1;
        }
      }
    }

    if (!portarray[j] && (!someleft || --waiting_period <= 0))
       done++;
    }

    if (debugging || verbose) {
      printf("The TCP stealth FIN scan took %ld seconds to scan %d ports.\n",
            time(NULL) - starttime, number_of_ports);
    }
    if (source_malloc) {
      free(source);
    }
    close(tcpsd);
    close(rawsd);
    return *ports;
  }

  /**
   * ftp_anon_connect
   *
   * @param: (struct ftpinfo *) ftp
   * @return: (int)
   */
  int ftp_anon_connect(struct ftpinfo *ftp) {
    int sd;
    struct sockaddr_in sock;
    int res;
    char recvbuf[2048];
    char command[512];

    if (verbose || debuggin) {
      printf("Attempting connection to ftp://%s:%s@%s:%i\n", ftp->user, ftp->pass,
          ftp->server_name, ftp->port);
    }
    if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
      perror("Couldn't create ftp_anon_connect socket");
      return 0;
    }

    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = ftp->server.s_addr;
    sock.sin_port = htons(ftp->port);
    res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
    if (res < 0) {
      printf("Your ftp bounce proxy server won't talk to us!\n");
      exit(1);
    }
    if (verbose || debugging) printf("Connected:");
    while ((res = recvtime(sd, recvbuf, 2048, 7)) > 0) {
      if (debugging || verbose) {
        recvbuf[res] = '\0';
        printf("%s", recvbuf);
      }
      if (res < 0) {
        perror("recv problem from ftp bounce server");
        exit(1);
      }

      // attempt ftp command send
      snprintf(command, 511, "USER %s\r\n", ftp->user);
      send(sd, command, strlen(command), 0);
      res = recvtime(sd, recvbuf, 2048, 12);

    }
  }

  /**
   * recvtime
   *
   * @param: (int) sd
   * @param: (char *) buf
   * @param: (int) len
   * @param: (int) seconds
   * @return: (int)
   */
  int recvtime(int sd, char *buf, int len, int seconds) {
    int res;
    struct timeval timeout = {seconds, 0};
    fd_set readfd;

    FD_ZERO(&readfd);
    FD_SET(sd, &readfd);

    res = select(sd + 1, &readfd, NULL, NULL, &timeout);
    if (res > 0) {
      res = recv(sd, buf, len, 0);
      if (res >= 0)
        return res;
      perror("recv in recvtime");
      return 0;
    }
    else if (!res)
      return 0;
    perror("select() in recvtime");
    return -1
  }

  /**
   * bouncescan
   */
  portlist bounce_scan(struct in_addr target,
      unsigned short* portarray, struct ftpinfo *ftp,
          portlist *ports) {
    int starttime, res, sd - ftp->sd, i = 0;
    char *t = (char *) &tarrget;
    int restriesleft = FTP_RETRIES;
    char recvbuf[2048];
    char targetstr[20];
    char command[512];
    snprintf(targetstr, 20, "%d,%d,%d,%d,0,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));
    starttime = time(NULL);

    if (verbose || debugging) {
      printf("Initiating TCP ftp bounce scan against %s (%s)\n",
          current_name, inet_ntoa(target));
    }

    for (i = 0; portarray[i]; i++) {
      snprintf(command, 512, "PORT %s%i\r\n", targetstr, portarray[i]);
      if (send(sd, command, strlen(command), 0) < 0) {
        perror("send in bounce_scan");
        if (retriesleft) {
          if (verbose || debugging)
            printf("Our ftp proxy server hung up on us!  retrying\n");
          retriesleft--;
          close(sd);
          ftp->sd = ftp_anon_connect(ftp);
          if (ftp->sd < 0)
            return *ports;
          sd = ftp->sd;
          i--;
        }
        else {
          fprintf(stderr, "Our soucket descriptor is dead and we are out of retries. Giving up.\n");
          close(sd);
          ftp->sd = -1;
          return *ports;
        }
      } else { /* Our send is good */
        res = recvtime(sd, recvbuf, 20148, 15);
        if (res <= 0) {
          perror("recv problem from ftp bounce server\n");
        } else { /* Our recv is good */
          recvbuf[res] = '\0';
          if (debugging) {
            printf("result of port query on port %i: %s", portarray[i], recvbuf);
          }
          if (recvbuf[0] == '5') {
            if (portarray[i] > 1023) {
              fprintf(stderr, "Your ftp bounce server sucks, it won't let us feed bogus ports!\n");
              exit(1);
            }
            else {
              fprintf(stderr, "Your ftp bounce server doesn't allow priviliged ports, skipping them.\n");
              while (portarray[i] && portarray[i] < 1024) i++;
              if (!portarray[i]) {
                fprintf(stderr, "And you didn't want to scan any unprivileged ports. Giving up.\n");
                /* close(sd);
                ftp->sd = -1;
                return *ports;
                OC was attempting to return gracefully, then decided otherwise */
                exit(1);
              }
          }
        }
        else /* Not an error message */
          if (send(sd, "LIST\r\n", 6, 0) > 0) {
            res = recvtime(sd, recvbuf, 2048, 12);
            if (res <= 0)
              perror("recv problem from ftp bounce server\n");
            else {
              recvbuf[res] = '\0';
              if (debugging) printf("result of LIST: %s", recvbuf);
              if (!strncmp(recvbuf, "500", 3)) {
                /* f@@@, we are not aligned properly */
                if (verbose || debugging)
                  printf("misalignment detected ... correcting.\n");
                res = recvtime(sd, recvbuf, 2048, 10);
              }
              if (recvbuf[0] == '1' || recvbuf[0] -- '2') {
                if (verbose || debugging) printf("Port number %i appears good.\n",
                  portarray[i]);
                addport(ports, portarray[i], IPPROTO_TCP, NULL);
                if (recvbuf[0] == '1') {
                  res = recvtime(sd, recvbuf, 2048, 5);
                  recvbuf[res] = '\0';
                  if ((res > 0) && debugging) printf("nxt line: %s", recvbuf);
                }
              }
            }
          }
        }
      }
    }

    if (debugging || verbose)
      printf("Scanned %d ports in %ld seconds via the Bounce scan.\n",
          number_of_ports, time(NULL) - starttime);

    return *ports;
  }

  /**
   * parse_bounce - parse a URL stype ftp string of the form
   *   user:pass@server:portno
   *
   */
  int parse_bounce(struct ftpinfo *ftp, char *url) {
    char *p = url, *q, *s;

    if ((q = strrchr(url, '@'))) { /*we have username and/or pass*/
      *(q++) = '\0';
      if ((s = strchr(q, ':')))
      { /* has portno */
        *(s++) = '\0';
        strncpy(ftp->server_name, q, MAXHOSTNAMELEN);
        ftp->port = atoi(s);
      }
    else strncpy(ftp->server_name, q, MAXHOSTNAMELEN);

    if ((s = strchr(p, ':'))) { /* User AND pass given */
      *(s++) = '\0';
      strncpy(ftp->user, p, 63);
      strncpy(ftp->pass, s, 255);
    }
    else { /* Username ONLY given */
      printf("Assuming %s is a username, and using the default password: %s\n",
          p, ftp->pass);
      strncpy(ftp->user, p, 63);
    }
  }
  else /* no username or password given */
    if ((s = strchr(url, ':'))) { /* portno is given */
      *(s++) = '\0';
      strncpy(ftp->server_name, ul, MAXHOSTNAMELEN);
      ftp->port = atoi(s);
    }
    else /* default case, no username, pwd, or port # */
      strncpy(ftp->server_name, url, MAXHOSTNAMELEN);

    ftp->user[63] = ftp->pass[255] = ftp->server_name[MAXHOSTNAMELEN] = 0;

    return 1;
  }

  /**
   * OC: I'll bet you've never seen this function before (yeah right)!
   * standard swiped checksum routine
   */
  unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    register long         sum;            /* assumes long == 32 bits */
    u_short               oddbyte:
    register u_short      answer;         /* assumes u_short == 16 bits */

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits
     */
    sum = 0;
    while (nbytes > 1) {
      sum += *ptr++;
      nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
      oddbyte = 0;            /* make sure top half is zero */
      *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
      sum += oddbyte;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);   /* add high-16 to low-16 */
    sum += (sum >> 16);                   /* add carry */
    answer = ~sum;        /* ones-complement, then truncate to 16 bits */
    return(answer);
  }






