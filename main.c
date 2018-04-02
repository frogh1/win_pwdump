
#include "common.h"
#include "crypt.h"
#include "samparser.h"
#include "globals.h"
#include "utils.h"

void PrintUsage() {
	puts(APP_USAGE);
}



int main(int argc,char *argv[])
{
	int ret_code;
	if(argc<2)
	{
		PrintUsage();
		return 0;
	}

	if((!strcmp(argv[1],"--dump-hash-local")) || (!strcmp(argv[1],"-dhl")))
	{
		OPT_DUMP_HASH_LOCAL = TRUE;
	}
	else{
		PrintUsage();
	}

	if(OPT_DUMP_HASH_LOCAL) {
		printf("[+] Setting BACKUP and RESTORE privileges...");
		if (!SetSeRestorePrivilege() || !SetSeBackupPrivilege()) {
			puts("ERROR: are you admin?");
			return -1;
		}
		else {
			puts("[OK]");
			printf("[+] Parsing SAM registry hive...");

			ret_code = SAM_ParseLocalDatabase(&localAccountDatabase, &BOOTKEY_ciphered, OPT_WITH_HISTORY);
			if (ret_code == SAM_REG_ERROR) {
				puts("ERROR: Registry error");
				return -1;
			}
			else if (ret_code == SAM_MOUNT_ERROR) {
				puts("ERROR: Can't mount previously saved SAM registry hive");
				return -1;
			}
			else if (ret_code == SAM_MEM_ERROR) {
				puts("ERROR: Fatal, not enough memory!");
				return -1;
			}
			else if (ret_code == SAM_NO_ACCOUNT) {
				puts("\n\nNo account found");
				return -1;
			}
			else {
				puts("[OK]");

				printf("[+] BOOTKEY retrieving...");
				ret_code = CRYPT_BootkeyGetValue(&BOOTKEY_ciphered, &BOOTKEY);
				if (ret_code == SYSKEY_SUCCESS) {
					puts("[OK]");
					BOOTKEY_Dump(&BOOTKEY);
					CRYPT_SAM_DecipherAllLocalAccount(localAccountDatabase, &BOOTKEY);
					SAM_NTLM_DumpAll(localAccountDatabase, OPT_NT_DUMP_TYPE, OPT_OUT_STDOUT, OPT_OUTPUT_FILENAME);
				}
				else {
					if (ret_code == SYSKEY_REGISTRY_ERROR)
						puts("[ERR] Registry error, are you admin?");
					else
						puts("[ERR] SYSKEY is not stored locally, not supported yet");
				}
			}
			if (localAccountDatabase)
				localAccountInfoFreeAll(localAccountDatabase);
		}
	}

	return 0;
}