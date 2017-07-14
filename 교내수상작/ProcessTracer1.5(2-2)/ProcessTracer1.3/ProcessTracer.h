#pragma once
/*
ProcessTracer.h
ProcessTracer class ����κ�
������ϴµ� �־ �ٽ� �Լ� �� ������ ����
*/
static char const szRCSID[] = "$Id: ProcessTracer.cpp 84 2011-11-13 00:29:15Z Roger $";
#ifdef _M_X64
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif // _M_X64

#include <windows.h>
#include <map>
#include "SimpleSymbolEngine.h"
#include <stdint.h>
#include <iomanip>
#include "../zyan-disassembler-engine/Zydis/Zydis.hpp"

class ProcessTracer
{
private:
	HANDLE hProcess;
	std::map<DWORD, HANDLE> threadHandles;
	std::map <LPVOID, std::string > dllFileName;

	SimpleSymbolEngine eng;
public:
	ProcessTracer();

	ProcessTracer(int argc, TCHAR **argv);

	void run();

	void OnCreateProcess(DWORD processId, DWORD threadId, CREATE_PROCESS_DEBUG_INFO const & createProcess);

	void OnExitProcess(DWORD threadId, EXIT_PROCESS_DEBUG_INFO const & exitProcess);

	void OnCreateThread(DWORD threadId, CREATE_THREAD_DEBUG_INFO const & createThread);

	void OnExitThread(DWORD threadId, EXIT_THREAD_DEBUG_INFO const & exitThread);

	void OnLoadDll(LOAD_DLL_DEBUG_INFO const & loadDll);

	void OnUnloadDll(UNLOAD_DLL_DEBUG_INFO const & unloadDll);

	void OnOutputDebugString(OUTPUT_DEBUG_STRING_INFO const & debugString);

	void OnException(DWORD threadId, DWORD firstChance, EXCEPTION_RECORD const & exception);

	void MyCreateProcess(int argc, TCHAR ** begin);

	static bool IsExistArgv(int argc);

	bool Zydis(uint8_t*, LPVOID, int);


};