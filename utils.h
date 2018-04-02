#ifndef _UTIL_H_
#define _UTIL_H_

#include "common.h"

#define swapu32(n)   ((((n) & 0xff000000) >> 24) | (((n) & 0x000000ff) << 24) | (((n) & 0x00ff0000) >> 8) | (((n) & 0x0000ff00) << 8))

/* Dumping tools */
#define SZ_DUMP_BEGIN "\n--------------------------------------------- BEGIN DUMP --------------------------------------------"
#define SZ_DUMP_END   "---------------------------------------------- END DUMP ---------------------------------------------"

#define SAM_EMPTY_LM "AAD3B435B51404EEAAD3B435B51404EE"
static BYTE SAM_EMPTY_LM_BYTES[16] = {0xAA,0xD3,0xB4,0x35,0xB5,0x14,0x04,0xEE,0xAA,0xD3,0xB4,0x35,0xB5,0x14,0x04,0xEE};
#define SAM_EMPTY_NT "31D6CFE0D16AE931B73C59D7E0C089C0"

/* NT/LM hash struct */
#define WIN_NTLM_HASH_SIZE 16
typedef enum{LM_HASH,NT_HASH,NT_NO_HASH}NT_HASH_TYPE;

typedef struct {
	NT_HASH_TYPE hash_type;
	BYTE LM_hash[WIN_NTLM_HASH_SIZE];
	BYTE NT_hash[WIN_NTLM_HASH_SIZE];
}s_NTLM_Hash;

#pragma pack(push)
#pragma pack(1)

	/* NTDS ciphered NT/LM hash struct */
	typedef struct {
		BYTE marker[8];
		BYTE decipher_key[16];
		BYTE ciphered_hash[WIN_NTLM_HASH_SIZE];
	}s_NTLM_hash_ciphered;

	/* NTDS deciphered PEK struct */
	typedef struct{
		BYTE marker2[36];
		BYTE decipher_key2[16];
	}s_NTLM_pek;

	/* NTDS ciphered PEK struct */
	typedef struct{
		BYTE marker[8];
		BYTE decipher_key1[16];
		BYTE marker2[36];
		BYTE decipher_key2_ciphered[16];
	}s_NTLM_pek_ciphered;
#pragma pack(pop)



typedef struct {
	TCHAR szSAMAccountName[UNLEN+1];
	DWORD rid;
	LPBYTE V;							/* Ciphered hash & history */
	DWORD dwVSize;
	UINT nbHistoryEntries;

	s_NTLM_Hash NTLM_hash;
	s_NTLM_Hash *NTLM_hash_history;
}s_localAccountInfo;


typedef struct l_localAccountInfo
{
    s_localAccountInfo info;
    struct l_localAccountInfo *next;
}l_localAccountInfo;

typedef l_localAccountInfo* ll_localAccountInfo;

/* Text dump strcuture */
typedef enum{NTDUMP_JOHN,NTDUMP_LC}NT_DUMP_TYPE;


BYTE HexDigitToByte(TCHAR digit);
void BytesToHex(LPVOID data,size_t data_size,LPSTR out_str);


/* Privileges setting */
BOOL SetSeRestorePrivilege();
BOOL SetSeBackupPrivilege();
BOOL SetPrivilege();


/* Windows registry overlay */
BOOL RegGetValueEx(HKEY hKeyReg,LPSTR keyName,LPSTR valueName,LPDWORD type,LPVOID val,DWORD valSize,LPDWORD outValSize);


/* Linked list handling for accounts (username, hash, sid,...) */

ll_localAccountInfo localAccountInfoNew(ll_localAccountInfo *localAccountInfo,s_localAccountInfo *localAccountEntry);
BOOL localAccountInfoFreeAll(ll_localAccountInfo localAccountInfo);

/* Debug / text functions */
void PEK_cipheredDump(s_NTLM_pek_ciphered *pek_ciphered);
void PEK_Dump(s_NTLM_pek *pek);

BOOL SAM_NTLM_DumpAll(ll_localAccountInfo localAccountInfo,NT_DUMP_TYPE dump_type,BOOL isStdout,LPSTR outFileName);


#endif