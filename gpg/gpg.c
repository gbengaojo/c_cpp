static ARGPARSE_OPTS opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aSign, "sign", N_("make a signature")),
  ARGPARSE_c (aClearsign, "clear-sign", N_("make a clear text signature")),
  ARGPARSE_c (aClearsign, "clearsign", "@"),
  ARGPARSE_c (aDetachedSign, "detach-sign", N_("make a detached signature")),
  ARGPARSE_c (aEncr, "encrypt",   N_("encrypt data")),
  ARGPARSE_c (aEncrFiles, "encrypt-files", "@"),
  ARGPARSE_c (aSym, "symmetric", N_("encryption only with symmetric cipher")),
  ARGPARSE_c (aStore, "store",     "@"),
  ARGPARSE_c (aDecrypt, "decrypt",   N_("decrypt data (default)")),
  ARGPARSE_c (aDecryptFiles, "decrypt-files", "@"),
  ARGPARSE_c (aVerify, "verify"   , N_("verify a signature")),
  ARGPARSE_c (aVerifyFiles, "verify-files" , "@" ),
  ARGPARSE_c (aListKeys, "list-keys", N_("list keys")),
  ARGPARSE_c (aListKeys, "list-public-keys", "@" ),
  ARGPARSE_c (aListSigs, "list-signatures", N_("list keys and signatures")),
  ARGPARSE_c (aListSigs, "list-sigs", "@"),
  ARGPARSE_c (aCheckKeys, "check-signatures",
	      N_("list and check key signatures")),
  ARGPARSE_c (aCheckKeys, "check-sigs", "@"),
  ARGPARSE_c (oFingerprint, "fingerprint", N_("list keys and fingerprints")),
  ARGPARSE_c (aListSecretKeys, "list-secret-keys", N_("list secret keys")),
  ARGPARSE_c (aKeygen,	    "generate-key",
              N_("generate a new key pair")),
  ARGPARSE_c (aKeygen,	    "gen-key", "@"),
  ARGPARSE_c (aQuickKeygen, "quick-generate-key" ,
              N_("quickly generate a new key pair")),
  ARGPARSE_c (aQuickKeygen, "quick-gen-key", "@"),
  ARGPARSE_c (aQuickAddUid,  "quick-add-uid",
              N_("quickly add a new user-id")),
  ARGPARSE_c (aQuickAddUid,  "quick-adduid", "@"),
  ARGPARSE_c (aQuickAddKey,  "quick-add-key", "@"),
  ARGPARSE_c (aQuickAddKey,  "quick-addkey", "@"),
  ARGPARSE_c (aQuickRevUid,  "quick-revoke-uid",
              N_("quickly revoke a user-id")),
  ARGPARSE_c (aQuickRevUid,  "quick-revuid", "@"),
  ARGPARSE_c (aQuickSetExpire,  "quick-set-expire",
              N_("quickly set a new expiration date")),
  ARGPARSE_c (aQuickSetPrimaryUid,  "quick-set-primary-uid", "@"),
  ARGPARSE_c (aFullKeygen,  "full-generate-key" ,
              N_("full featured key pair generation")),
  ARGPARSE_c (aFullKeygen,  "full-gen-key", "@"),
  ARGPARSE_c (aGenRevoke, "generate-revocation",
	      N_("generate a revocation certificate")),
  ARGPARSE_c (aGenRevoke, "gen-revoke", "@"),
  ARGPARSE_c (aDeleteKeys,"delete-keys",
              N_("remove keys from the public keyring")),
  ARGPARSE_c (aDeleteSecretKeys, "delete-secret-keys",
              N_("remove keys from the secret keyring")),
  ARGPARSE_c (aQuickSignKey,  "quick-sign-key" ,
              N_("quickly sign a key")),
  ARGPARSE_c (aQuickLSignKey, "quick-lsign-key",
              N_("quickly sign a key locally")),
  ARGPARSE_c (aSignKey,  "sign-key"   ,N_("sign a key")),
  ARGPARSE_c (aLSignKey, "lsign-key"  ,N_("sign a key locally")),
  ARGPARSE_c (aEditKey,  "edit-key"   ,N_("sign or edit a key")),
  ARGPARSE_c (aEditKey,  "key-edit"   ,"@"),
  ARGPARSE_c (aPasswd,   "change-passphrase", N_("change a passphrase")),
  ARGPARSE_c (aPasswd,   "passwd", "@"),
  ARGPARSE_c (aDesigRevoke, "generate-designated-revocation", "@"),
  ARGPARSE_c (aDesigRevoke, "desig-revoke","@" ),
  ARGPARSE_c (aExport, "export"           , N_("export keys") ),
  ARGPARSE_c (aSendKeys, "send-keys"     , N_("export keys to a keyserver") ),
  ARGPARSE_c (aRecvKeys, "receive-keys" , N_("import keys from a keyserver") ),
  ARGPARSE_c (aRecvKeys, "recv-keys"     , "@"),
  ARGPARSE_c (aSearchKeys, "search-keys" ,
              N_("search for keys on a keyserver") ),
  ARGPARSE_c (aRefreshKeys, "refresh-keys",
              N_("update all keys from a keyserver")),
  ARGPARSE_c (aLocateKeys, "locate-keys", "@"),
  ARGPARSE_c (aLocateExtKeys, "locate-external-keys", "@"),
  ARGPARSE_c (aFetchKeys, "fetch-keys" , "@" ),
  ARGPARSE_c (aShowKeys, "show-keys" , "@" ),
  ARGPARSE_c (aExportSecret, "export-secret-keys" , "@" ),
  ARGPARSE_c (aExportSecretSub, "export-secret-subkeys" , "@" ),
  ARGPARSE_c (aExportSshKey, "export-ssh-key", "@" ),
  ARGPARSE_c (aImport, "import", N_("import/merge keys")),
  ARGPARSE_c (aFastImport, "fast-import", "@"),
#ifdef ENABLE_CARD_SUPPORT
  ARGPARSE_c (aCardStatus,  "card-status", N_("print the card status")),
  ARGPARSE_c (aCardEdit,   "edit-card",  N_("change data on a card")),
  ARGPARSE_c (aCardEdit,   "card-edit", "@"),
  ARGPARSE_c (aChangePIN,  "change-pin", N_("change a card's PIN")),
#endif
  ARGPARSE_c (aListConfig, "list-config", "@"),
  ARGPARSE_c (aListGcryptConfig, "list-gcrypt-config", "@"),
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@" ),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@" ),
  ARGPARSE_c (aListPackets, "list-packets","@"),

#ifndef NO_TRUST_MODELS
  ARGPARSE_c (aExportOwnerTrust, "export-ownertrust", "@"),
  ARGPARSE_c (aImportOwnerTrust, "import-ownertrust", "@"),
  ARGPARSE_c (aUpdateTrustDB,"update-trustdb",
              N_("update the trust database")),
  ARGPARSE_c (aCheckTrustDB, "check-trustdb", "@"),
  ARGPARSE_c (aFixTrustDB, "fix-trustdb", "@"),
#endif

  ARGPARSE_c (aDeArmor, "dearmor", "@"),
  ARGPARSE_c (aDeArmor, "dearmour", "@"),
  ARGPARSE_c (aEnArmor, "enarmor", "@"),
  ARGPARSE_c (aEnArmor, "enarmour", "@"),
  ARGPARSE_c (aPrintMD, "print-md", N_("print message digests")),
  ARGPARSE_c (aPrimegen, "gen-prime", "@" ),
  ARGPARSE_c (aGenRandom,"gen-random", "@" ),
  ARGPARSE_c (aServer,   "server",  N_("run in server mode")),
  ARGPARSE_c (aTOFUPolicy, "tofu-policy",
	      N_("|VALUE|set the TOFU policy for a key")),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oArmor, "armor", N_("create ascii armored output")),
  ARGPARSE_s_n (oArmor, "armour", "@"),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oHiddenRecipient, "hidden-recipient", "@"),
  ARGPARSE_s_s (oRecipientFile, "recipient-file", "@"),
  ARGPARSE_s_s (oHiddenRecipientFile, "hidden-recipient-file", "@"),
  ARGPARSE_s_s (oRecipient, "remote-user", "@"),  /* (old option name) */
  ARGPARSE_s_s (oDefRecipient, "default-recipient", "@"),
  ARGPARSE_s_n (oDefRecipientSelf,  "default-recipient-self", "@"),
  ARGPARSE_s_n (oNoDefRecipient, "no-default-recipient", "@"),

  ARGPARSE_s_s (oTempDir,  "temp-directory", "@"),
  ARGPARSE_s_s (oExecPath, "exec-path", "@"),
  ARGPARSE_s_s (oEncryptTo,      "encrypt-to", "@"),
  ARGPARSE_s_n (oNoEncryptTo, "no-encrypt-to", "@"),
  ARGPARSE_s_s (oHiddenEncryptTo, "hidden-encrypt-to", "@"),
  ARGPARSE_s_n (oEncryptToDefaultKey, "encrypt-to-default-key", "@"),
  ARGPARSE_s_s (oLocalUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),
  ARGPARSE_s_s (oSender, "sender", "@"),

  ARGPARSE_s_s (oTrySecretKey, "try-secret-key", "@"),

  ARGPARSE_s_i (oCompress, NULL,
                N_("|N|set compress level to N (0 disables)")),
  ARGPARSE_s_i (oCompressLevel, "compress-level", "@"),
  ARGPARSE_s_i (oBZ2CompressLevel, "bzip2-compress-level", "@"),
  ARGPARSE_s_n (oBZ2DecompressLowmem, "bzip2-decompress-lowmem", "@"),

  ARGPARSE_s_n (oMimemode, "mimemode", "@"),
  ARGPARSE_s_n (oTextmodeShort, NULL, "@"),
  ARGPARSE_s_n (oTextmode,   "textmode", N_("use canonical text mode")),
  ARGPARSE_s_n (oNoTextmode, "no-textmode", "@"),

  ARGPARSE_s_n (oExpert,      "expert", "@"),
  ARGPARSE_s_n (oNoExpert, "no-expert", "@"),

  ARGPARSE_s_s (oDefSigExpire, "default-sig-expire", "@"),
  ARGPARSE_s_n (oAskSigExpire,      "ask-sig-expire", "@"),
  ARGPARSE_s_n (oNoAskSigExpire, "no-ask-sig-expire", "@"),
  ARGPARSE_s_s (oDefCertExpire, "default-cert-expire", "@"),
  ARGPARSE_s_n (oAskCertExpire,      "ask-cert-expire", "@"),
  ARGPARSE_s_n (oNoAskCertExpire, "no-ask-cert-expire", "@"),
  ARGPARSE_s_i (oDefCertLevel, "default-cert-level", "@"),
  ARGPARSE_s_i (oMinCertLevel, "min-cert-level", "@"),
  ARGPARSE_s_n (oAskCertLevel,      "ask-cert-level", "@"),
  ARGPARSE_s_n (oNoAskCertLevel, "no-ask-cert-level", "@"),

  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_p_u (oMaxOutput, "max-output", "@"),
  ARGPARSE_s_s (oInputSizeHint, "input-size-hint", "@"),
  ARGPARSE_s_i (oChunkSize, "chunk-size", "@"),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	  "quiet",   "@"),
  ARGPARSE_s_n (oNoTTY,   "no-tty",  "@"),

  ARGPARSE_s_n (oForceAEAD, "force-aead", "@"),

  ARGPARSE_s_n (oDisableSignerUID, "disable-signer-uid", "@"),

  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),
  ARGPARSE_s_n (oInteractive, "interactive", N_("prompt before overwriting")),

  ARGPARSE_s_n (oBatch, "batch", "@"),
  ARGPARSE_s_n (oAnswerYes, "yes", "@"),
  ARGPARSE_s_n (oAnswerNo, "no", "@"),
  ARGPARSE_s_s (oKeyring, "keyring", "@"),
  ARGPARSE_s_s (oPrimaryKeyring, "primary-keyring", "@"),
  ARGPARSE_s_s (oSecretKeyring, "secret-keyring", "@"),
  ARGPARSE_s_n (oShowKeyring, "show-keyring", "@"),
  ARGPARSE_s_s (oDefaultKey, "default-key", "@"),

  ARGPARSE_s_s (oKeyServer, "keyserver", "@"),
  ARGPARSE_s_s (oKeyServerOptions, "keyserver-options", "@"),
  ARGPARSE_s_s (oKeyOrigin, "key-origin", "@"),
  ARGPARSE_s_s (oImportOptions, "import-options", "@"),
  ARGPARSE_s_s (oImportFilter,  "import-filter", "@"),
  ARGPARSE_s_s (oExportOptions, "export-options", "@"),
  ARGPARSE_s_s (oExportFilter,  "export-filter", "@"),
  ARGPARSE_s_s (oListOptions,   "list-options", "@"),
  ARGPARSE_s_s (oVerifyOptions, "verify-options", "@"),

  ARGPARSE_s_s (oDisplayCharset, "display-charset", "@"),
  ARGPARSE_s_s (oDisplayCharset, "charset", "@"),
  ARGPARSE_s_s (oOptions, "options", "@"),

  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level", "@"),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugIOLBF, "debug-iolbf", "@"),
  ARGPARSE_s_u (oDebugSetIobufSize, "debug-set-iobuf-size", "@"),
  ARGPARSE_s_u (oDebugAllowLargeChunks, "debug-allow-large-chunks", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", "@"),
  ARGPARSE_s_s (oStatusFile, "status-file", "@"),
  ARGPARSE_s_i (oAttributeFD, "attribute-fd", "@"),
  ARGPARSE_s_s (oAttributeFile, "attribute-file", "@"),

  ARGPARSE_s_i (oCompletesNeeded, "completes-needed", "@"),
  ARGPARSE_s_i (oMarginalsNeeded, "marginals-needed", "@"),
  ARGPARSE_s_i (oMaxCertDepth,	"max-cert-depth", "@" ),
  ARGPARSE_s_s (oTrustedKey, "trusted-key", "@"),

  ARGPARSE_s_s (oLoadExtension, "load-extension", "@"),  /* Dummy.  */

  ARGPARSE_s_s (oCompliance, "compliance",   "@"),
  ARGPARSE_s_n (oGnuPG, "gnupg",   "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp2", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp6", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp7", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp8", "@"),
  ARGPARSE_s_n (oRFC2440, "rfc2440", "@"),
  ARGPARSE_s_n (oRFC4880, "rfc4880", "@"),
  ARGPARSE_s_n (oRFC4880bis, "rfc4880bis", "@"),
  ARGPARSE_s_n (oOpenPGP, "openpgp", N_("use strict OpenPGP behavior")),
  ARGPARSE_s_n (oPGP7, "pgp6", "@"),
  ARGPARSE_s_n (oPGP7, "pgp7", "@"),
  ARGPARSE_s_n (oPGP8, "pgp8", "@"),

  ARGPARSE_s_n (oRFC2440Text,      "rfc2440-text", "@"),
  ARGPARSE_s_n (oNoRFC2440Text, "no-rfc2440-text", "@"),
  ARGPARSE_s_i (oS2KMode, "s2k-mode", "@"),
  ARGPARSE_s_s (oS2KDigest, "s2k-digest-algo", "@"),
  ARGPARSE_s_s (oS2KCipher, "s2k-cipher-algo", "@"),
  ARGPARSE_s_i (oS2KCount, "s2k-count", "@"),
  ARGPARSE_s_s (oCipherAlgo, "cipher-algo", "@"),
  ARGPARSE_s_s (oAEADAlgo,   "aead-algo", "@"),
  ARGPARSE_s_s (oDigestAlgo, "digest-algo", "@"),
  ARGPARSE_s_s (oCertDigestAlgo, "cert-digest-algo", "@"),
  ARGPARSE_s_s (oCompressAlgo,"compress-algo", "@"),
  ARGPARSE_s_s (oCompressAlgo, "compression-algo", "@"), /* Alias */
  ARGPARSE_s_n (oThrowKeyids, "throw-keyids", "@"),
  ARGPARSE_s_n (oNoThrowKeyids, "no-throw-keyids", "@"),
  ARGPARSE_s_n (oShowPhotos,   "show-photos", "@"),
  ARGPARSE_s_n (oNoShowPhotos, "no-show-photos", "@"),
  ARGPARSE_s_s (oPhotoViewer,  "photo-viewer", "@"),
  ARGPARSE_s_s (oSetNotation,  "set-notation", "@"),
  ARGPARSE_s_s (oSigNotation,  "sig-notation", "@"),
  ARGPARSE_s_s (oCertNotation, "cert-notation", "@"),
  ARGPARSE_s_s (oKnownNotation, "known-notation", "@"),

  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
		      )),

  ARGPARSE_group (303, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " --clear-sign [file]        make a clear text signature\n"
    " --detach-sign [file]       make a detached signature\n"
    " --list-keys [names]        show keys\n"
    " --fingerprint [names]      show fingerprints\n")),

  /* More hidden commands and options. */
  ARGPARSE_c (aPrintMDs, "print-mds", "@"), /* old */
#ifndef NO_TRUST_MODELS
  ARGPARSE_c (aListTrustDB, "list-trustdb", "@"),
#endif

  /* Not yet used:
     ARGPARSE_c (aListTrustPath, "list-trust-path", "@"), */
  ARGPARSE_c (aDeleteSecretAndPublicKeys,
              "delete-secret-and-public-keys", "@"),
  ARGPARSE_c (aRebuildKeydbCaches, "rebuild-keydb-caches", "@"),

  ARGPARSE_o_s (oPassphrase,      "passphrase", "@"),
  ARGPARSE_s_i (oPassphraseFD,    "passphrase-fd", "@"),
  ARGPARSE_s_s (oPassphraseFile,  "passphrase-file", "@"),
  ARGPARSE_s_i (oPassphraseRepeat,"passphrase-repeat", "@"),
  ARGPARSE_s_s (oPinentryMode,    "pinentry-mode", "@"),
  ARGPARSE_s_s (oRequestOrigin,   "request-origin", "@"),
  ARGPARSE_s_i (oCommandFD, "command-fd", "@"),
  ARGPARSE_s_s (oCommandFile, "command-file", "@"),
  ARGPARSE_s_n (oQuickRandom, "debug-quick-random", "@"),
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),

#ifndef NO_TRUST_MODELS
  ARGPARSE_s_s (oTrustDBName, "trustdb-name", "@"),
  ARGPARSE_s_n (oAutoCheckTrustDB, "auto-check-trustdb", "@"),
  ARGPARSE_s_n (oNoAutoCheckTrustDB, "no-auto-check-trustdb", "@"),
  ARGPARSE_s_s (oForceOwnertrust, "force-ownertrust", "@"),
#endif

  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),
  ARGPARSE_s_n (oRequireSecmem, "require-secmem", "@"),
  ARGPARSE_s_n (oNoRequireSecmem, "no-require-secmem", "@"),
  ARGPARSE_s_n (oNoPermissionWarn, "no-permission-warning", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armor", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armour", "@"),
  ARGPARSE_s_n (oNoDefKeyring, "no-default-keyring", "@"),
  ARGPARSE_s_n (oNoKeyring, "no-keyring", "@"),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_s_n (oNoOptions, "no-options", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_n (oNoBatch, "no-batch", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oWithTofuInfo,"with-tofu-info", "@"),
  ARGPARSE_s_n (oWithKeyData,"with-key-data", "@"),
  ARGPARSE_s_n (oWithSigList,"with-sig-list", "@"),
  ARGPARSE_s_n (oWithSigCheck,"with-sig-check", "@"),
  ARGPARSE_c (aListKeys, "list-key", "@"),   /* alias */
  ARGPARSE_c (aListSigs, "list-sig", "@"),   /* alias */
  ARGPARSE_c (aCheckKeys, "check-sig", "@"), /* alias */
  ARGPARSE_c (aShowKeys,  "show-key", "@"), /* alias */
  ARGPARSE_s_n (oSkipVerify, "skip-verify", "@"),
  ARGPARSE_s_n (oSkipHiddenRecipients, "skip-hidden-recipients", "@"),
  ARGPARSE_s_n (oNoSkipHiddenRecipients, "no-skip-hidden-recipients", "@"),
  ARGPARSE_s_i (oDefCertLevel, "default-cert-check-level", "@"), /* old */
#ifndef NO_TRUST_MODELS
  ARGPARSE_s_n (oAlwaysTrust, "always-trust", "@"),
#endif
  ARGPARSE_s_s (oTrustModel, "trust-model", "@"),
  ARGPARSE_s_s (oTOFUDefaultPolicy, "tofu-default-policy", "@"),
  ARGPARSE_s_s (oSetFilename, "set-filename", "@"),
  ARGPARSE_s_n (oForYourEyesOnly, "for-your-eyes-only", "@"),
  ARGPARSE_s_n (oNoForYourEyesOnly, "no-for-your-eyes-only", "@"),
  ARGPARSE_s_s (oSetPolicyURL,  "set-policy-url", "@"),
  ARGPARSE_s_s (oSigPolicyURL,  "sig-policy-url", "@"),
  ARGPARSE_s_s (oCertPolicyURL, "cert-policy-url", "@"),
  ARGPARSE_s_n (oShowPolicyURL,      "show-policy-url", "@"),
  ARGPARSE_s_n (oNoShowPolicyURL, "no-show-policy-url", "@"),
  ARGPARSE_s_s (oSigKeyserverURL, "sig-keyserver-url", "@"),
  ARGPARSE_s_n (oShowNotation,      "show-notation", "@"),
  ARGPARSE_s_n (oNoShowNotation, "no-show-notation", "@"),
  ARGPARSE_s_s (oComment, "comment", "@"),
  ARGPARSE_s_n (oDefaultComment, "default-comment", "@"),
  ARGPARSE_s_n (oNoComments, "no-comments", "@"),
  ARGPARSE_s_n (oEmitVersion,      "emit-version", "@"),
  ARGPARSE_s_n (oNoEmitVersion, "no-emit-version", "@"),
  ARGPARSE_s_n (oNoEmitVersion, "no-version", "@"), /* alias */
  ARGPARSE_s_n (oNotDashEscaped, "not-dash-escaped", "@"),
  ARGPARSE_s_n (oEscapeFrom,      "escape-from-lines", "@"),
  ARGPARSE_s_n (oNoEscapeFrom, "no-escape-from-lines", "@"),
  ARGPARSE_s_n (oLockOnce,     "lock-once", "@"),
  ARGPARSE_s_n (oLockMultiple, "lock-multiple", "@"),
  ARGPARSE_s_n (oLockNever,    "lock-never", "@"),
  ARGPARSE_s_i (oLoggerFD,   "logger-fd", "@"),
  ARGPARSE_s_s (oLoggerFile, "log-file", "@"),
  ARGPARSE_s_s (oLoggerFile, "logger-file", "@"),  /* 1.4 compatibility.  */
  ARGPARSE_s_n (oUseEmbeddedFilename,      "use-embedded-filename", "@"),
  ARGPARSE_s_n (oNoUseEmbeddedFilename, "no-use-embedded-filename", "@"),
  ARGPARSE_s_n (oUtf8Strings,      "utf8-strings", "@"),
  ARGPARSE_s_n (oNoUtf8Strings, "no-utf8-strings", "@"),
  ARGPARSE_s_n (oWithFingerprint, "with-fingerprint", "@"),
  ARGPARSE_s_n (oWithSubkeyFingerprint, "with-subkey-fingerprint", "@"),
  ARGPARSE_s_n (oWithSubkeyFingerprint, "with-subkey-fingerprints", "@"),
  ARGPARSE_s_n (oWithICAOSpelling, "with-icao-spelling", "@"),
  ARGPARSE_s_n (oWithKeygrip,     "with-keygrip", "@"),
  ARGPARSE_s_n (oWithKeyScreening,"with-key-screening", "@"),
  ARGPARSE_s_n (oWithSecret,      "with-secret", "@"),
  ARGPARSE_s_n (oWithWKDHash,     "with-wkd-hash", "@"),
  ARGPARSE_s_n (oWithKeyOrigin,   "with-key-origin", "@"),
  ARGPARSE_s_s (oDisableCipherAlgo,  "disable-cipher-algo", "@"),
  ARGPARSE_s_s (oDisablePubkeyAlgo,  "disable-pubkey-algo", "@"),
  ARGPARSE_s_n (oAllowNonSelfsignedUID,      "allow-non-selfsigned-uid", "@"),
  ARGPARSE_s_n (oNoAllowNonSelfsignedUID, "no-allow-non-selfsigned-uid", "@"),
  ARGPARSE_s_n (oAllowFreeformUID,      "allow-freeform-uid", "@"),
  ARGPARSE_s_n (oNoAllowFreeformUID, "no-allow-freeform-uid", "@"),
  ARGPARSE_s_n (oNoLiteral, "no-literal", "@"),
  ARGPARSE_p_u (oSetFilesize, "set-filesize", "@"),
  ARGPARSE_s_n (oFastListMode, "fast-list-mode", "@"),
  ARGPARSE_s_n (oFixedListMode, "fixed-list-mode", "@"),
  ARGPARSE_s_n (oLegacyListMode, "legacy-list-mode", "@"),
  ARGPARSE_s_n (oListOnly, "list-only", "@"),
  ARGPARSE_s_n (oPrintPKARecords, "print-pka-records", "@"),
  ARGPARSE_s_n (oPrintDANERecords, "print-dane-records", "@"),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict", "@"),
  ARGPARSE_s_n (oIgnoreValidFrom,    "ignore-valid-from", "@"),
  ARGPARSE_s_n (oIgnoreCrcError, "ignore-crc-error", "@"),
  ARGPARSE_s_n (oIgnoreMDCError, "ignore-mdc-error", "@"),
  ARGPARSE_s_n (oShowSessionKey, "show-session-key", "@"),
  ARGPARSE_s_s (oOverrideSessionKey, "override-session-key", "@"),
  ARGPARSE_s_i (oOverrideSessionKeyFD, "override-session-key-fd", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),
  ARGPARSE_s_n (oAutoKeyRetrieve, "auto-key-retrieve", "@"),
  ARGPARSE_s_n (oNoAutoKeyRetrieve, "no-auto-key-retrieve", "@"),
  ARGPARSE_s_n (oNoSigCache,         "no-sig-cache", "@"),
  ARGPARSE_s_n (oMergeOnly,	  "merge-only", "@" ),
  ARGPARSE_s_n (oAllowSecretKeyImport, "allow-secret-key-import", "@"),
  ARGPARSE_s_n (oTryAllSecrets,  "try-all-secrets", "@"),
  ARGPARSE_s_n (oEnableSpecialFilenames, "enable-special-filenames", "@"),
  ARGPARSE_s_n (oNoExpensiveTrustChecks, "no-expensive-trust-checks", "@"),
  ARGPARSE_s_n (oPreservePermissions, "preserve-permissions", "@"),
  ARGPARSE_s_s (oDefaultPreferenceList,  "default-preference-list", "@"),
  ARGPARSE_s_s (oDefaultKeyserverURL,  "default-keyserver-url", "@"),
  ARGPARSE_s_s (oPersonalCipherPreferences, "personal-cipher-preferences","@"),
  ARGPARSE_s_s (oPersonalAEADPreferences, "personal-aead-preferences","@"),
  ARGPARSE_s_s (oPersonalDigestPreferences, "personal-digest-preferences","@"),
  ARGPARSE_s_s (oPersonalCompressPreferences,
                                         "personal-compress-preferences", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_s (oWeakDigest, "weak-digest","@"),
  ARGPARSE_s_n (oUnwrap, "unwrap", "@"),
  ARGPARSE_s_n (oOnlySignTextIDs, "only-sign-text-ids", "@"),

  /* Aliases.  I constantly mistype these, and assume other people do
     as well. */
  ARGPARSE_s_s (oPersonalCipherPreferences, "personal-cipher-prefs", "@"),
  ARGPARSE_s_s (oPersonalAEADPreferences,   "personal-aead-prefs", "@"),
  ARGPARSE_s_s (oPersonalDigestPreferences, "personal-digest-prefs", "@"),
  ARGPARSE_s_s (oPersonalCompressPreferences, "personal-compress-prefs", "@"),

  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDirmngrProgram, "dirmngr-program", "@"),
  ARGPARSE_s_n (oDisableDirmngr, "disable-dirmngr", "@"),
  ARGPARSE_s_s (oDisplay,    "display",    "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname",    "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype",    "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",   "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages","@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oGroup,      "group",      "@"),
  ARGPARSE_s_s (oUnGroup,    "ungroup",    "@"),
  ARGPARSE_s_n (oNoGroups,   "no-groups",  "@"),
  ARGPARSE_s_n (oStrict,     "strict",     "@"),
  ARGPARSE_s_n (oNoStrict,   "no-strict",  "@"),
  ARGPARSE_s_n (oMangleDosFilenames,      "mangle-dos-filenames", "@"),
  ARGPARSE_s_n (oNoMangleDosFilenames, "no-mangle-dos-filenames", "@"),
  ARGPARSE_s_n (oEnableProgressFilter, "enable-progress-filter", "@"),
  ARGPARSE_s_n (oMultifile, "multifile", "@"),
  ARGPARSE_s_s (oKeyidFormat, "keyid-format", "@"),
  ARGPARSE_s_n (oExitOnStatusWriteError, "exit-on-status-write-error", "@"),
  ARGPARSE_s_i (oLimitCardInsertTries, "limit-card-insert-tries", "@"),

  ARGPARSE_s_n (oEnableLargeRSA, "enable-large-rsa", "@"),
  ARGPARSE_s_n (oDisableLargeRSA, "disable-large-rsa", "@"),
  ARGPARSE_s_n (oEnableDSA2, "enable-dsa2", "@"),
  ARGPARSE_s_n (oDisableDSA2, "disable-dsa2", "@"),
  ARGPARSE_s_n (oAllowWeakDigestAlgos, "allow-weak-digest-algos", "@"),

  ARGPARSE_s_s (oDefaultNewKeyAlgo, "default-new-key-algo", "@"),

  /* These two are aliases to help users of the PGP command line
     product use gpg with minimal pain.  Many commands are common
     already as they seem to have borrowed commands from us.  Now I'm
     returning the favor. */
  ARGPARSE_s_s (oLocalUser, "sign-with", "@"),
  ARGPARSE_s_s (oRecipient, "user", "@"),

  ARGPARSE_s_n (oRequireCrossCert, "require-backsigs", "@"),
  ARGPARSE_s_n (oRequireCrossCert, "require-cross-certification", "@"),
  ARGPARSE_s_n (oNoRequireCrossCert, "no-require-backsigs", "@"),
  ARGPARSE_s_n (oNoRequireCrossCert, "no-require-cross-certification", "@"),

  /* New options.  Fixme: Should go more to the top.  */
  ARGPARSE_s_s (oAutoKeyLocate, "auto-key-locate", "@"),
  ARGPARSE_s_n (oNoAutoKeyLocate, "no-auto-key-locate", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_n (oNoSymkeyCache, "no-symkey-cache", "@"),

  /* Dummy options with warnings.  */
  ARGPARSE_s_n (oUseAgent,      "use-agent", "@"),
  ARGPARSE_s_n (oNoUseAgent, "no-use-agent", "@"),
  ARGPARSE_s_s (oGpgAgentInfo, "gpg-agent-info", "@"),
  ARGPARSE_s_s (oReaderPort, "reader-port", "@"),
  ARGPARSE_s_s (octapiDriver, "ctapi-driver", "@"),
  ARGPARSE_s_s (opcscDriver, "pcsc-driver", "@"),
  ARGPARSE_s_n (oDisableCCID, "disable-ccid", "@"),
  ARGPARSE_s_n (oHonorHttpProxy, "honor-http-proxy", "@"),
  ARGPARSE_s_s (oTOFUDBFormat, "tofu-db-format", "@"),

  /* Dummy options.  */
  ARGPARSE_s_n (oNoop, "sk-comments", "@"),
  ARGPARSE_s_n (oNoop, "no-sk-comments", "@"),
  ARGPARSE_s_n (oNoop, "compress-keys", "@"),
  ARGPARSE_s_n (oNoop, "compress-sigs", "@"),
  ARGPARSE_s_n (oNoop, "force-v3-sigs", "@"),
  ARGPARSE_s_n (oNoop, "no-force-v3-sigs", "@"),
  ARGPARSE_s_n (oNoop, "force-v4-certs", "@"),
  ARGPARSE_s_n (oNoop, "no-force-v4-certs", "@"),
  ARGPARSE_s_n (oNoop, "no-mdc-warning", "@"),
  ARGPARSE_s_n (oNoop, "force-mdc", "@"),
  ARGPARSE_s_n (oNoop, "no-force-mdc", "@"),
  ARGPARSE_s_n (oNoop, "disable-mdc", "@"),
  ARGPARSE_s_n (oNoop, "no-disable-mdc", "@"),
  ARGPARSE_s_n (oNoop, "allow-multisig-verification", "@"),
  ARGPARSE_s_n (oNoop, "allow-multiple-messages", "@"),
  ARGPARSE_s_n (oNoop, "no-allow-multiple-messages", "@"),

  ARGPARSE_end ()
};

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

      configlineno = 0;
      configfp = fopen( configname, "r");
            if (configfp && is_secured_file (fileno(configfp)))
            {
              fclose(configfp);
              configfp = null;
              gpg_err_set_errno(EPERM);
            }
      if (!configfp) {
        if (default_config) {
          if (parse_debug)
            log_info(_("Note: no default option file '%s'\n"),
                        configname);
        }
        else {
          log_error(_("option file '%s': %s\n"),
                configname, stterror(errno) );
          g10_exit(2);
        }
        xfree(configname); configname = NULL;
      }
      if (parse_debug && configname)
        log_info(_("reading options from '%s'\n"), configname);
      default_config = 0;
    }

    while (optfile_parse(configfp, configname, &configlineno, &pargs, opts))
    {
      switch(pargs.r_opt)
      {
        case aListConfig:
        case aListGcryptConfig:
        case aGPGConfigList:
        case aGPGConfTest:
          set_cmd(&cmd, pargs.r_opt);
          /* Do not register a keyring for these commands. */
          default_keyring = -1;
          break;

        case aCheckKeys:
        case aListPackets:
        case aImport:
        case aFastImport:
        case aSendKeys:
        case aRecvKeys:
        case aSearchKeys:
        case aRefreshKeys:
        case aFetchKeys:
        case aExport:
#ifdef ENABLE_CARD_SUPPORT
              case aCardStatus:
              case aCardEdit:
              case aChangePIN:
#endif /* ENABLE_CARD_SUPPORT*/
        case aListKeys:
        case aLocateKeys:
        case aLocateExtKeys:
        case aListSigs:
        case aExportSecret:
        case aExportSecretSub:
        case aExportSshKey:
        case aSym:
        case aClearsign:
        case aGenRevoke:
        case aDesigRevoke:
        case aPrimegen:
        case aGenRandom:
        case aPrintMD:
        case aPrintMDs:
        case aListTrustDB:
        case aCheckTrustDB:
        case aUpdateTrustDB:
        case aFixTrustDB:
        case aListTrustPath:
        case aDeArmor:
        case aEnArmor:
        case aSign:
        case aQuickSignKey:
        case aQuickLSignKey:
        case aSignKey:
        case aLSignKey:
        case aStore:
        case aQuickKeygen:
        case aQuickAddUid:
        case aQuickAddKey:
        case aQuickRevUid:
        case aQuickSetExpire:
        case aQuickSetPrimaryUid:
        case aExportOwnerTrust:
        case aImportOwnerTrust:
        case aRebuildKeydbCaches:
            set_cmd (&cmd, pargs.r_opt);
        break;

        case aKeygen:
        case aFullKeygen:
        case aEditKey:
        case aDeleteSecretKeys:
        case aDeleteSecretAndPublicKeys:
        case aDeleteKeys:
        case aPasswd:
            set_cmd (&cmd, pargs.r_opt);
            greeting=1;
        break;

        case aShowKeys:
            /* opts is defined as `static ARGPARSE_OPTS opts[] = { ... } above */
            set_cmd (&cmd, pargs.r_opt);
            opt.import_options |= IMPORT_SHOW;
            opt.import_options |= IMPORT_DRY_RUN;
            opt.import_options &= ~IMPORT_REPAIR_KEYS;
            opt.list_options |= LIST_SHOW_UNUSABLE_UIDS;
            opt.list_options |= LIST_SHOW_UNUSABLE_SUBKEYS;
            opt.list_options |= LIST_SHOW_NOTATIONS;
            opt.list_options |= LIST_SHOW_POLICY_URLS;
        break;

        case aDetachedSign: detached_sig = 1; set_cmd(&cmd, aSign); break;

        case aDecryptFiles: multifile = 1;  /* fall through */
        case aDecrypt: set_cmd(&cmd, aEncr);

        case aVerifyFiles: multifile = 1; /* fall through */
        case aVerify: set_cmd(&cmd, aVerify); break;

        case aServer:
          set_cmd(&cmd, pargs.r_opt);
          opt.batch = 1;
        break;

        case aTOFUPolicy:
          set_cmd(&cmd, pargs.r_opt);
        break;

        case oArmor: opt.armor = 1; opt.no_armor = 0; break;
        case oOutput: opt.outfile = pargs.r.ret_str; break;

        case oMaxOutput: opt.max_output = pargs.r.ret_ulong; break;

        case oInputSizeHint:
          opt.input_size_hint = string_to_u64(pargs.r.ret_str);
        break;

        case oChunkSize:
          opt.chunk_size = pargs.r.ret_int;
        break;

        case oQuiet: opt.quiet = 1; break;
        case oNoTTY: tty_no_terminal(1); break;
        case oDryRun: opt.dry_run = 1; break;
        case oInteractive: opt.interactive = 1; break;
        case oVerbose:
          opt.verbose++;
          gcry_control(GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          opt.list_options |= LIST_SHOW_UNUSABLE_UIDS;
          opt.list_options |= LIST_SHOW_UNUSABLE_SUBKEYS;
        break;

        case oBatch:
          opt.batch = 1;
          nogreeting = 1;
        break;

        case oUseAgent: /* Dummy */
        break;

        case oNoUseAgent:
          obsolelete_option(configname, configfileno, "no-use-agent");
        break;
        case oGpgAgentInfo:
	        obsolete_option (configname, configlineno, "gpg-agent-info");
        break;
        case oReaderPort:
          obsolete_scdaemon_option (configname, configlineno, "reader-port");
        break;
        case octapiDriver:
          obsolete_scdaemon_option (configname, configlineno, "ctapi-driver");
        break;
        case opcscDriver:
          obsolete_scdaemon_option (configname, configlineno, "pcsc-driver");
        break;
        case oDisableCCID:
          obsolete_scdaemon_option (configname, configlineno, "disable-ccid");
        break;
        case oHonorHttpProxy:
          obsolete_option (configname, configlineno, "honor-http-proxy");
        break;

        case oAnswerYes:
          opt.answer_yes = 1;
        break;
        case oAnswerNo:
          opt.answer_no = 1;
        break;
        case oKeyring:
          append_to_strlist(&nrings, pargs.r.ret_str);
        break;
        case oPrimaryKeyring:
          sl = append_to_strlist(&nrings, pargs.r.ret_str);
          sl->flags = KEYDB_RESOURCE_FLAG_PRIMARY;
        break
        case oShowKeyring:
          deprected_warning(configname, configlineno, "--show-keyring",
                "--list-options", "show-keyring");
          opt.list_options|=LIST_SHOW_KEYRING;
        break;

        case oDebug:
          if (parse_debug_flag(pargs.r.ret_str, &opt.debug, debug_flags))
          {
            pargs.r_opt = ARGPARSE_INVALID_ARG;
            pargs.err = ARGPARSE_PRINT_ERROR;
          }
        break;

        case oDebugAll: opt.debug = ~0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugIOLBF: break; /* Already set in pre-parse step. */
        case oDebugSetIobufSize:
          opt_set_iobuf_size = pargs.r.ret_ulong;
          opt_set_iobuf_size_used = 1;
        break;
        case oDebugAllowLargeChunks:
          allow_large_chunks = 1;
        break;  




    
