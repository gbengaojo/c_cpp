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
  char *def_cipher_string = NULL;
  char *def_aead_string = NULL;
  char *def_digest_string = NULL;
  char *compress_algo_string = NULL;
  char *cert_digest_string = NULL;
  char *s2k_cipher_string = NULL;
  char *s2k_digest_string = NULL;
  char *pers_aead_list = NULL;
  char *pers_digest_list = NULL;
  char *pers_compress_list = NULL;
  int eyes_only=0;
  int multifile=0;
  int pwfd = -1;
  int ovrseskeyfd = -1;
  int fpr_maybe_cmd = 0; /* --fingerprint maybe a command. */
  int any_explicit_recipient = 0;
  int default_akl = 1;
  int require_secmem = 0;
  int got_secmem = 0;
  struct assuan_malloc_hooks malloc_hooks;
  ctrl_t ctrl;

  static int print_dane_records;
  static int print_pka_records;
  static int allow_large_chunks;

#ifdef __riscos__
  opt.lock_once = 1;
#endif /* __riscos__ */

  /* Please note that we may be running SUID(root), so be very CAREFUL
     when adding any stuff between here and the call to
     secmem_init() somewhere after the option parsing. */
  early_system_init ();
  gnupg_reopen_std (GPG_NAME);
  trap_unaligned ();
  gnupg_rl_initialize ();
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix (GPG_NAME, GPGRT_LOG_WITH_PREFIX);

  /* Makesure that our subsystems are readay. */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  /*Use our own logging handler for Libgcrypt. */
  setup_libgcrypt_logging ();

  /* Put random number into secure memory */
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps();

  gnupg_init_signals (0, emergency_cleanup);

  dotlock_create (NULL, 0); /* Register lock file cleanup. */

  /* Tell the compliance module who we are. */
  gnupg_initialize_compliance (GNUPG_MODULE_NAME_GPG);

  opt.autostart = 1;
  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

