#include "utils.h"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//														UTILS FUNC
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * Convert hex digit to byte (4 bits)
 * Return 0xff if failed
 */
BYTE HexDigitToByte(TCHAR digit) {
	if(digit>='0' && digit<='9')
		return digit - '0';
	else if(digit>='a' && digit<='f')
		return digit - 'a' + 10;
	else if(digit>='A' && digit<='F')
		return digit - 'A' + 10;

	return (BYTE)-1;
}


/*
 * Bytes array to hex string
 */
void BytesToHex(LPVOID data,size_t data_size,LPSTR out_str) {
	size_t i;

	for(i=0;i<data_size;i++)
		wsprintf(out_str+(i<<1),"%02X",((LPBYTE)data)[i]);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//														PRIVILEGES FUNC
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * Adjust token privilege with specific privilege
 */
BOOL SetPrivilege(LPSTR szPrivilege) {
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&hToken)) {
		printf("OpenProcessToken() error: 0x%08x\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,szPrivilege,&luid))
		return FALSE; 

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL)) { 
		printf("AdjustTokenPrivileges() error: 0x%08x\n\n", GetLastError());
		return FALSE; 
	} 

	CloseHandle(hToken);

    return TRUE;
}

/*
 * Adjust token privilege with seRestorePrivilege
 */
BOOL SetSeRestorePrivilege() {
	return SetPrivilege(SE_RESTORE_NAME);
}

/*
 * Adjust token privilege with seBackupPrivilege
 */
BOOL SetSeBackupPrivilege() {
	return SetPrivilege(SE_BACKUP_NAME);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//														REGISTRY FUNC
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * Query value in registry (generic)
 */
BOOL RegGetValueEx(HKEY hKeyReg,LPSTR keyName,LPSTR valueName,LPDWORD type,LPVOID val,DWORD valSize,LPDWORD outValSize) {
	HKEY hKey;
	DWORD dwDisposition=0,dwValueSize;
	LONG ret;

	ret = RegCreateKeyEx(hKeyReg,keyName,0,NULL,REG_OPTION_NON_VOLATILE,KEY_QUERY_VALUE,NULL,&hKey,&dwDisposition);

	if((ret==ERROR_SUCCESS)&&(dwDisposition==REG_OPENED_EXISTING_KEY)) {
		dwValueSize = valSize;
		ret = RegQueryValueEx(hKey,valueName,NULL,type,(LPBYTE)val,&dwValueSize);
		if(outValSize && (ret==ERROR_SUCCESS))
			*outValSize = dwValueSize;
		RegCloseKey(hKey);

		if(!valSize)
			return (ret==ERROR_SUCCESS);

		return (ret==ERROR_SUCCESS) && (dwValueSize==valSize);
	}

	return FALSE;
}


/*
 * Add a new node to localAccountInfo linked list
 */
ll_localAccountInfo localAccountInfoNew(ll_localAccountInfo *localAccountInfo,s_localAccountInfo *localAccountEntry) {
	ll_localAccountInfo newEntry;

	if(!(newEntry = (ll_localAccountInfo)VirtualAlloc(NULL,sizeof(l_localAccountInfo),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE)))
		return NULL;

	newEntry->next = *localAccountInfo;
	RtlMoveMemory(&newEntry->info,localAccountEntry,sizeof(s_localAccountInfo));

	*localAccountInfo = newEntry;

	return newEntry;
}


/*
 * Free localAccountInfo linked list
 */
BOOL localAccountInfoFreeAll(ll_localAccountInfo localAccountInfo) {
	ll_localAccountInfo current=localAccountInfo,tmp;

	if(localAccountInfo) {
		do {
			tmp = current->next;
			if(current->info.V)
				VirtualFree(current->info.V,0,MEM_RELEASE);
			if(current->info.NTLM_hash_history)
				VirtualFree(current->info.NTLM_hash_history,0,MEM_RELEASE);
			VirtualFree(current,0,MEM_RELEASE);
			current = tmp;
		}while(current);
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//														DUMPING FUNC
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * Raw dump a ciphered PEK struct
 */
void PEK_cipheredDump(s_NTLM_pek_ciphered *pek_ciphered) {
	TCHAR szPEKCiphered[256];

	BytesToHex(pek_ciphered,sizeof(s_NTLM_pek_ciphered),szPEKCiphered);
	printf("Ciphered PEK = %s\n",szPEKCiphered);
}


/*
 * Raw dump a PEK struct
 */
void PEK_Dump(s_NTLM_pek *pek) {
	TCHAR szPEK[256];

	BytesToHex(pek->decipher_key2,sizeof(pek->decipher_key2),szPEK);
	printf("PEK = %s\n",szPEK);
}

/*
 * Dump to text one entry of a ll_localAccountInfo linked list
 * Format : John The Ripper
 */
void SAM_NTLM_DumpJohn(s_localAccountInfo *localAccountEntry,LPSTR szOut) {
	TCHAR szLM[64],szNT[256];
	UINT i;

	BytesToHex(localAccountEntry->NTLM_hash.NT_hash,WIN_NTLM_HASH_SIZE,szNT);

	if(localAccountEntry->NTLM_hash.hash_type == LM_HASH) {
		BytesToHex(localAccountEntry->NTLM_hash.LM_hash,WIN_NTLM_HASH_SIZE,szLM);
		wsprintf(szOut,"%s:%d:%s:%s:::\r\n",localAccountEntry->szSAMAccountName,localAccountEntry->rid,szLM,szNT);
	}
	else if(localAccountEntry->NTLM_hash.hash_type == NT_HASH)
		wsprintf(szOut,"%s:%d:%s:%s:::\r\n",localAccountEntry->szSAMAccountName,localAccountEntry->rid,SAM_EMPTY_LM,szNT);
	else if(localAccountEntry->NTLM_hash.hash_type == NT_NO_HASH)
		wsprintf(szOut,"%s:%d:%s:%s:::\r\n",localAccountEntry->szSAMAccountName,localAccountEntry->rid,SAM_EMPTY_LM,SAM_EMPTY_NT);

	if(localAccountEntry->NTLM_hash_history) {
		for(i=0;i<localAccountEntry->nbHistoryEntries;i++) {
			BytesToHex(localAccountEntry->NTLM_hash_history[i].NT_hash,WIN_NTLM_HASH_SIZE,szNT);
			BytesToHex(localAccountEntry->NTLM_hash_history[i].LM_hash,WIN_NTLM_HASH_SIZE,szLM);
			wsprintf(szOut+lstrlen(szOut),"%s_hist%d:%d:%s:%s:::\r\n",localAccountEntry->szSAMAccountName,i,localAccountEntry->rid,szLM,szNT);
		}
	}
}


/*
 * Dump to text one entry of a ll_localAccountInfo linked list
 * Format : L0phCrack
 */
void SAM_NTLM_DumpLc(s_localAccountInfo *localAccountEntry,LPSTR szOut) {
	TCHAR szLM[256],szNT[256];
	UINT i;

	BytesToHex(localAccountEntry->NTLM_hash.NT_hash,WIN_NTLM_HASH_SIZE,szNT);

	if(localAccountEntry->NTLM_hash.hash_type == LM_HASH) {
		BytesToHex(localAccountEntry->NTLM_hash.LM_hash,WIN_NTLM_HASH_SIZE,szLM);
		wsprintf(szOut,"%s:\"\":\"\":%s:%s\r\n",localAccountEntry->szSAMAccountName,szLM,szNT);
	}
	else if(localAccountEntry->NTLM_hash.hash_type == NT_HASH)
		wsprintf(szOut,"%s:\"\":\"\":%s:%s\r\n",localAccountEntry->szSAMAccountName,SAM_EMPTY_LM,szNT);
	else if(localAccountEntry->NTLM_hash.hash_type == NT_NO_HASH)
		wsprintf(szOut,"%s:\"\":\"\":%s:%s\r\n",localAccountEntry->szSAMAccountName,SAM_EMPTY_LM,SAM_EMPTY_NT);

	if(localAccountEntry->NTLM_hash_history) {
		for(i=0;i<localAccountEntry->nbHistoryEntries;i++) {
			BytesToHex(localAccountEntry->NTLM_hash_history[i].NT_hash,WIN_NTLM_HASH_SIZE,szNT);
			BytesToHex(localAccountEntry->NTLM_hash_history[i].LM_hash,WIN_NTLM_HASH_SIZE,szLM);
			wsprintf(szOut+lstrlen(szOut),"%s_hist%d:\"\":\"\":%s:%s\r\n",localAccountEntry->szSAMAccountName,i,szLM,szNT);
		}
	}
}


/*
 * Dump to text a ll_localAccountInfo linked list
 * (SAMAccoutnName,deciphered NT, deciphered LM)
 */
BOOL SAM_NTLM_DumpAll(ll_localAccountInfo localAccountInfo,NT_DUMP_TYPE dump_type,BOOL isStdout,LPSTR outFileName) {
	ll_localAccountInfo currentAccount = localAccountInfo;
	TCHAR szHashLine[4096];
	DWORD dwNbWritten,count=0;
	HANDLE hFile;

	if(!currentAccount)
		return FALSE;

	if(!isStdout) {
		if((hFile=CreateFile(outFileName,GENERIC_WRITE,FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL))==INVALID_HANDLE_VALUE)
			return FALSE;
	}
	else
		puts(SZ_DUMP_BEGIN);
	
	do{
		if(dump_type==NTDUMP_JOHN)
			SAM_NTLM_DumpJohn(&currentAccount->info,szHashLine);
		else if(dump_type==NTDUMP_LC)
			SAM_NTLM_DumpLc(&currentAccount->info,szHashLine);
		if(isStdout)
			printf(szHashLine);
		else {
			WriteFile(hFile,szHashLine,lstrlen(szHashLine),&dwNbWritten,NULL);
		}
		currentAccount = currentAccount->next;
		count++;
	}while(currentAccount);

	if(!isStdout) 
		CloseHandle(hFile);
	else
		puts(SZ_DUMP_END);

	if(isStdout)
		printf("\n%d dumped accounts\n\n",count);
	else
		printf("\n%d dumped accounts to %s\n\n",count,outFileName);

	return TRUE;
}
