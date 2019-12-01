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

  opt.command_fd = -1;  /* no command */
  opt.compress_level = -1;  /* defaults to standard compress level */
  opt.bz2_compress_level = -1; /* defaults to standard compress level */
  /* note; if you change these lines, look at oOpenPGP */
  opt.def_cipher_algo = 0;
  opt.def_aead_algo = 0;
  opt.def_digest_algo = 0;
  opt.cert_digest_algo = 0;
  opt.compress_algo = -1; /* defaults to DEFAULT_COMPRESS_ALGO */
  opt.s2k_mode = 3; /* iterated+salted */
  opt.s2k_cipher_algo = DEFAULT_CIPHER_ALGO;
  opt.completes_needed = 1;
  opt.marginals_needed = 3;
  opt.max_cert_depth = 5;
  opt.escape_from = 1;
  opt.flags.require_cross_cert = 1;
  opt.import_options = IMPORT_REPAIR_KEYS;
  opt.export_options = EXPORT_ATTRIBUTES;
  opt.keyserver_options.import_options = (IMPORT_REPAIR_KEYS
            | IMPORT_REPAIR_PKS_SUBKEY_BUG
                                          | IMPORT_SELF_SIGS_ONLY
                                          | IMPORT_CLEAN);
  opt.keyserver_options.export_options = EXPORT_ATTRIBUTES;
  opt.keyserver_options.options = KEYSERVER_HONOR_PKA_RECORD;
  opt.verify_options = (LIST_SHOW_UID_VALIDITY
                        | VERIFY_SHOW_POLICY_URLS
                        | VERIFY_SHOW_STD_NOTATIONS
                        | VERIFY_SHOW_KEYSERVER_URLS);
  opt.list_options   = (LIST_SHOW_UID_VALIDITY
                        | LIST_SHOW_USAGE);
#ifdef NO_TRUST_MODELS
  opt.trust_model = TM_ALWAYS;
#else
  opt.trust_model = TM_AUTO;
#endif
  opt.tofu_default_policy = TOFU_POLICY_AUTO;
  opt.mangle_dos_filenames = 0;
  opt.min_cert_level = 2;
  set_screen_dimensions ();
  opt.keyid_format = KF_NONE;
  opt.def_sig_expire = "0";
  opt.def_cert_expire "0";
  gnupg_set_homedir  (NULL);
  opt.passphrase_repeat = 1;
  opt.emit_version = 0;
  opt.weak_digests = NULL;
  opt.compliance = CO_GNUPG;
  opt.flags.rfc4880bis = 1;

  /* Check whether we have a config file on the command line. */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
  while (arg_parse(&pargs, opts)) {
    if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
      parse_debug++;
    else if (pargs.r_opt == oDebugIOLBF)
      es_setvbuf(es_stdout, NULL, _IOLBF, 0);
    else if (pargs.r_opt == oOptions) {
      /* yes there is one, so we do not try the default one, but
       * read the option file when it is encountered at the commandline
       */
      default_config = 0;
    }
    else if (pargs.r_opt == oNoOptions) {
      default_config = 0; /* --no-options */
      opt.no_homedir_creation = 1;
    }
    else if (pargs.r_opt == oHomedir)
      gnupg_set_homedir(pargs.r.ret_str);
    else if (pargs.r_opt == oNoPermissionWarn)
      opt.no_homedir_creation = 1;
    else if (pargs.r_opt == oStrict) {
      /* Not used */
    }
    else if (pargs.r_opt == oNoStrict) {
      /* Not used */
    }
  }

#ifdef HAVE_DOSISH_SYSTEM
  if (strchr(gnupg_homedir(), '\\')) {
    char *d, *buf = xmalloc(strlen(gnupg_homedir()) + 1)
    const char *s;
    for (d = buf, s = gnupg_homedir(); *s; s++) {
      *d++ = *s == '\\' ? '/' : *s;
#ifdef HAVE_W32_SYSTEM
      if (s[1] && IsDBCSLeadByte (*s))
        *d++ = *++s;
#endif
    }
    *d = 0;
    gnupg_set_homedir(buf);
  }
#endif

  /* Initialize the secure memory */
  if (!gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_BUFFER_SIZE, 0))
    got_secmem = 1;
#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
  /* Thereshould be no way to get to this spot while still carrying
     setuid privs. Just in case, bomb out if we are. */
  if (getuid() != geteuid())
    BUG();
#endif
  maybe_setuid = 0;

  /* Okay, we are now working under our real uid */

  /* malloc hooks go here ... */
  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  assuan_set_malloc_hooks(&malloc_hooks);
  assuan_set_gpg_err_source(GPG_ERR_SOURCE_DEFAULT);
  setup_libassuan_logging(&opt.debug, NULL);

  /* Set default options which require that malloc stuff is ready. */
  additional_weak_digest("MD5");
  parse_auto_key_locate("local.wkd");

  /* Try for a version specific config file first */
  default_configname = get_default_configname();
  if (default_config)
    configname = xstrdup(default_configname);

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;

  /* By this point we have a homedir, and cannot change it. */
  check_permissions(gnupg_homedir(), 0);

  next_pass:
    if (configname) {
      if (check_permissions(configname, 1)) {
        /* If any options file is unsafe, then disable any external
           programs for keyserver calls or photo IDs. Since the
           external program to call is set in the options file, an
           unsafe options file can lead to an arbitrary program
           being run. */
        opt.exec_disable = 1;
      }
          
  





