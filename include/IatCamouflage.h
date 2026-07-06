// IatCamouflage.h
#pragma once

#include <Windows.h>
#include "Common.h"

/*=========================================
@ RandomCompileTimeSeed Function
===========================================*/
INT RandomCompileTimeSeed(VOID) {

	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}

/*=========================================
@ AllocateDummyBuffer Function
===========================================*/
PVOID AllocateDummyBuffer(PVOID* AllocatedDummyBuffer) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;

	*(INT*)pAddress = RandomCompileTimeSeed() % 0xFF;

	*AllocatedDummyBuffer = pAddress;
	return pAddress;
}

/*=========================================
@ IatCamouflage Function
===========================================*/
VOID IatCamouflage(VOID) {

	PVOID					pAddress		= { 0 };
	INT*					X				= (INT*)AllocateDummyBuffer(&pAddress);

	if (*X > 350) {

		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	DELETE_PTR(pAddress);
}