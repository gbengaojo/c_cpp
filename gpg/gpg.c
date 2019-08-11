int // 2306
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  IOBUF a;
  int a;
  int rc=0;
  char **orig_argv;
  const char *fname;
  char *username;
  int may_coredump;
  strlist_t sl;
  strlist_t remusr = NULL;
  strlist_t locusr = NULL;
  strlist_t nrings = NULL;
  armor_filter_context_t *afx = NULL;
  int detached_sig = 0;
  FILE *configfp = NULL;
  char *configname = NULL;
  char *save_configname = NULL;
  char *default_configname = NULL;
  usigned configlineno;
  int parse_debug = 0;
  int default_config = 1;
  int default_keyring = 1;
  int greeting = 0;
  int nogreeting = 0;
  char *logfile = NULL;
  int use_random_seed = 1;
  enum cmd_and_opt_values cmd = 0;
  constchar *debug_level = NULL;
#ifndef NO_TRUST_MODELS
  const char *trustdb_name = NULL;
#endif /*!NO_TRUST_MODELS*/
