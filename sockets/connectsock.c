int connectsoc(const char *host, const char *srvice, const char *transport) {
   struct hostent    *phe;    // pointer to host information entry
   struct servent    *pse;    // pointer to service information entry
   struct protoent   *ppe;    // pointer to protocol Information entry
   struct sockaddr_in sin;    // an Internet endpoint address
   int s, type;               // socket descriptor and socket type

   memset(&sin, 0, sizeof(sin));    // looks to be an alias for bzero, or
   sin.sin_family = AF_INET;        // perhaps not an alias, more a function
                                    // that performs something similar

   // Map service name to port number
   if (pse = getservbyname(service, transport))
      sin.sin_port = pse->s_port;
}
