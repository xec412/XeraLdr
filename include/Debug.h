// Debug.h
#pragma once

#include <Windows.h>
#include "Common.h"

/* Comment the following line if you would like to disable debug mode */
#define DEBUG

#ifdef DEBUG

VOID CreateDebugConsole();

#define ERROR_BUFFER_SIZE			(MAX_PATH * 2)
#define GET_FILENAME(Path)			(strrchr(Path, '\\') ? strrchr(Path, '\\') + 1 : Path)

#define DBGPRINT(STR, ...)																			\
	if (1) {																						\
		LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUFFER_SIZE);	\
		if (cBuffer) {																				\
			int Length = wsprintfA(cBuffer, STR, __VA_ARGS__);										\
			WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, Length, NULL, NULL);			\
			DELETE_PTR(cBuffer);																	\
		}																							\
	}

#endif // DEBUG