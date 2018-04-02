#ifndef __GLOBALS_H_
#define __GLOBALS_H_

#include "common.h"
#include "crypt.h"

static TCHAR APP_USAGE[10*100] = {
	"pwdump.exe <options>\r\n"
	"Options : \r\n"
	"-dhl  --dump-hash-local\r\n"
	"\r\nExample: pwdump.exe --dump-hash-local\r\n"
};

/* CLI option */
static BOOL OPT_DUMP_HASH_LOCAL = FALSE;
static BOOL OPT_WITH_HISTORY = FALSE;
static BOOL OPT_OUT_STDOUT = TRUE;
static TCHAR OPT_OUTPUT_FILENAME[MAX_PATH+1];
static NT_DUMP_TYPE OPT_NT_DUMP_TYPE = NTDUMP_JOHN;

/* Account and crypto struct */
static ll_localAccountInfo localAccountDatabase = NULL;

static s_NTLM_pek_ciphered PEK_ciphered;
static s_NTLM_pek PEK;
static s_SYSKEY SYSKEY;
static s_BOOTKEY_ciphered BOOTKEY_ciphered;
static s_BOOTKEY BOOTKEY;
static s_LSAKEY_ciphered LSAKEY_ciphered;
static s_LSAKEY LSAKEY;
static s_NLKM_ciphered NLKM_ciphered;
static s_NLKM NLKM;

#endif
