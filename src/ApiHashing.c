// ApiHashing.c
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

/*=========================================
@ LdrRetrieveFunction Function
===========================================*/
PVOID LdrRetrieveFunction(IN PVOID Module, IN ULONG ApiHash) {

	if (!Module || !ApiHash) {
#ifdef DEBUG
		DBGPRINT("[-] LdrRetrieveFunction Failed -> Invalid Parameters! - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return NULL;
	}

//-------------------------------------------------------------

	PIMAGE_NT_HEADERS						NtHeaders				= { 0 };
	PIMAGE_EXPORT_DIRECTORY					ExportDir				= { 0 };
	DWORD									ExportDirSize			= { 0 };
	PDWORD									AddrOfFunctions			= { 0 };
	PDWORD									AddrOfNames				= { 0 };
	PWORD									AddrOfOrdinals			= { 0 };
	
//-------------------------------------------------------------
	
	// Fetch the NT headers
	NtHeaders = ( PIMAGE_NT_HEADERS ) ( U_PTR ( Module ) + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Fetch the export directory and its size
	ExportDir			= ( PIMAGE_EXPORT_DIRECTORY ) ( U_PTR ( Module ) + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
	ExportDirSize		= NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	// Fetch the three table
	AddrOfFunctions		= ( PDWORD ) ( U_PTR ( Module ) + ExportDir->AddressOfFunctions );
	AddrOfNames			= ( PDWORD ) ( U_PTR ( Module ) + ExportDir->AddressOfNames );
	AddrOfOrdinals		= ( PWORD ) ( U_PTR ( Module ) + ExportDir->AddressOfNameOrdinals );

	// Iterate through exported functions
	for (DWORD i = 0; i < ExportDir->NumberOfNames; i++) {

		CHAR* FunctionName		= ( CHAR* ) ( U_PTR ( Module ) + AddrOfNames [ i ] );
		PVOID FunctionAddress	= ( PVOID ) ( U_PTR ( Module ) + AddrOfFunctions [ AddrOfOrdinals [ i ] ] );
		
		// Check if the hashes match
		if (HashStringDJB2(FunctionName, 0) == ApiHash) {

			// Handle forwarded functions
			if ((((ULONG_PTR)FunctionAddress) >= ((ULONG_PTR)ExportDir)) &&
				(((ULONG_PTR)FunctionAddress) < ((ULONG_PTR)ExportDir) + ExportDirSize))
			{
#ifdef DEBUG
				DBGPRINT("[i] LdrRetrieveFunction -> [%s] Is A Forwarded Function \n", FunctionName);
#endif
				CHAR				Forwarder[MAX_PATH]			= { 0 };
				WCHAR				wModulePath[MAX_PATH]			= { 0 };
				DWORD				Offset						= { 0 };
				PCHAR				pFunctionName				= { 0 };
				PCHAR				FunctionMod					= { 0 };

				MEMCPY(Forwarder, FunctionAddress, STRLEN((PCHAR)FunctionAddress));

				for (DWORD j = 0; j < STRLEN((PCHAR)Forwarder); j++) {

					if (((PCHAR)Forwarder)[j] == '.') {

						Offset				= j;
						Forwarder[j]		= '\0';
						break;
					}
				}

				FunctionMod			= Forwarder;
				pFunctionName		= Forwarder + Offset + 1;

				// Convert ansi name to unicode
				AnsiToUnicode(FunctionMod, wModulePath, MAX_PATH);

				PVOID Module = WorkItemProxyLoadLibraryW(wModulePath);
				return LdrRetrieveFunction(Module, HashStringDJB2(pFunctionName, 0));
			}

			// If it is not a forwarded function, return the address directly
			return FunctionAddress;
		}
	}

#ifdef DEBUG
	DBGPRINT("[-] LdrRetrieveFunction Failed At Hash -> [0x%0.8X] - %s.%d \n", ApiHash, GET_FILENAME(__FILE__), __LINE__);
#endif
	return NULL;
}

/*=========================================
@ LdrGetModule Function
===========================================*/
PVOID LdrGetModule(IN ULONG ModuleHash) {

	PLDR_DATA_TABLE_ENTRY			Dte				= { 0 };
	PLIST_ENTRY						Head			= { 0 };
	PLIST_ENTRY						Entry			= { 0 };

	// Get pointer to the list
	Head  = &NtCurrentTeb()->ProcessEnvironmentBlock->LoaderData->InLoadOrderModuleList;
	Entry = Head->Flink;

	// Return the handle of local .exe image if no hash is given
	if (!ModuleHash) {   
		Dte = C_PTR(Entry);
		return Dte->DllBase;
	}

	// Iterate through listed modules
	for (; Head != Entry; Entry = Entry->Flink) {

		Dte = C_PTR(Entry);

		// Check if the hashes match
		if (HashStringDJB2(Dte->BaseDllName.Buffer, Dte->BaseDllName.Length) == ModuleHash) {
			return Dte->DllBase;
		}
	}

#ifdef DEBUG
	DBGPRINT("[-] LdrGetModule Failed At Hash -> [0x%0.8X] - %s.%d \n", ModuleHash, GET_FILENAME(__FILE__), __LINE__);
#endif
	return NULL;
}