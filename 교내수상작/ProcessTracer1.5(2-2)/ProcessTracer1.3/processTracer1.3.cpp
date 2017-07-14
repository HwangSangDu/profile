/*
NAME
ProcessTracer

DESCRIPTION
About the simplest debugger which is useful!

COPYRIGHT
Copyright (C) 2011 by Roger Orr <rogero@howzatt.demon.co.uk>

This software is distributed in the hope that it will be useful, but
without WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Permission is granted to anyone to make or distribute verbatim
copies of this software provided that the copyright notice and
this permission notice are preserved, and that the distributor
grants the recipent permission for further distribution as permitted
by this notice.

Comments and suggestions are always welcome.
Please report bugs to rogero@howzatt.demon.co.uk.
*/
/*
ProcessTracer class ���Ǻκ�
������ϴµ� �־ �ٽ� �Լ� �� ���� ����

����� ��ɾ� �Ű������� ���μ����� ����
����� �̺�Ʈ�� �̿��Ͽ� ����� �ǽ�
�̺�Ʈ�� ����ü ����
���μ��� ���� , ������ ���� , Load File,Dll ���� , ���� ȣ�� ���� ��� ����
���� �߻� �� �߰� �������� ���
���μ��� ���� �� main ����
*/

#include <windows.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include "ProcessTracer.h" 
#include <iomanip>
#include <atlstr.h>
#include "../zyan-disassembler-engine/Zydis/Zydis.hpp"
#define SIZE (10)
/** Simple process tracer */
/////////////////////////////////////////////////////////////////////////////////////////////////
/*������
ȯ�溯������*/
ProcessTracer::ProcessTracer()
{
	_putenv("_NO_DEBUG_HEAP=1");
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*������
ȯ�溯������
command line parameter�� �Ű������� MyCreateProcessȣ��*/
ProcessTracer::ProcessTracer(int argc, TCHAR **argv)
{
	_putenv("_NO_DEBUG_HEAP=1");
	this->MyCreateProcess(argc, argv);
}



/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : ����� �̺�Ʈ ��� => �̺�Ʈ�� ���� �Լ� ���� => ���μ��� ���� �̺�Ʈ(EXIT_PROCESS_DEBUG_EVENT) �� ����
���μ��� ����� bool completed = true , while (!completed) �ݺ��� �������´�.
���� ����� �̺�Ʈ 2�� �߻� ��  ����ó�� �� ���� => bool attached�� Ȱ��
��ȯ : void
*/
void ProcessTracer::run()
{
	bool completed = false;
	bool attached = false;
	while (!completed)
	{
		DEBUG_EVENT DebugEvent;
		if (!WaitForDebugEvent(&DebugEvent, INFINITE))
		{
			throw std::runtime_error("Debug loop aborted");
		}
		DWORD continueFlag = DBG_CONTINUE;
		switch (DebugEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			OnCreateProcess(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DebugEvent.u.CreateProcessInfo);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			OnExitProcess(DebugEvent.dwThreadId, DebugEvent.u.ExitProcess);
			completed = true;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			OnCreateThread(DebugEvent.dwThreadId, DebugEvent.u.CreateThread);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			OnExitThread(DebugEvent.dwThreadId, DebugEvent.u.ExitThread);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			OnLoadDll(DebugEvent.u.LoadDll);
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			OnUnloadDll(DebugEvent.u.UnloadDll);
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			OnOutputDebugString(DebugEvent.u.DebugString);
			break;
		case EXCEPTION_DEBUG_EVENT:
			if (!attached)
			{
				attached = true;
			}
#ifdef _M_X64
			else if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode
				== STATUS_WX86_BREAKPOINT)
			{
				std::cout << "WOW64 initialised" << std::endl;
			}
#endif 
			else
			{
				OnException(DebugEvent.dwThreadId, DebugEvent.u.Exception.dwFirstChance, 
					DebugEvent.u.Exception.ExceptionRecord);
				continueFlag = (DWORD)DBG_EXCEPTION_NOT_HANDLED;
			}
			break;
		default:
			std::cerr << "Unexpected debug event: " << DebugEvent.dwDebugEventCode << std::endl;
		}
		if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, continueFlag))
			//continueFlag�� ������� ����
		{
			throw std::runtime_error("Error continuing debug event");
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : ���μ��� ����
SimpleSymbolEngine class object �ʱ�ȭ
�ɺ����̺� �ε� / ���μ����� ����������ּ�(lpStartAddress)���
��ȯ : void
*/
void ProcessTracer::OnCreateProcess(DWORD processId, DWORD threadId, CREATE_PROCESS_DEBUG_INFO const & createProcess)
{
	hProcess = createProcess.hProcess;
	threadHandles[threadId] = createProcess.hThread;
	eng.init(hProcess);
	eng.loadModule(createProcess.hFile, createProcess.lpBaseOfImage, std::string());
	std::cout << "CREATE PROCESS " << processId << " at " << eng.addressToString(createProcess.lpStartAddress) << std::endl;

	if (createProcess.hFile)
	{
		CloseHandle(createProcess.hFile);
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : ���� Trace ȣ�� / �����ڵ����  0�̸� ����
��ȯ : void
*/
void ProcessTracer::OnExitProcess(DWORD threadId, EXIT_PROCESS_DEBUG_INFO const & exitProcess)
{
	std::cout << "EXIT PROCESS " << exitProcess.dwExitCode << std::endl;
	//eng.stackTrace(threadHandles[threadId], std::cout);

}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : ������ ���� , ������ �ּ� ���
��ȯ : void
*/
void ProcessTracer::OnCreateThread(DWORD threadId, CREATE_THREAD_DEBUG_INFO const & createThread)
{
	std::cout << "CREATE THREAD " << threadId << " at " << eng.addressToString(createThread.lpStartAddress) << std::endl;
	threadHandles[threadId] = createThread.hThread;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : ������ ���� / ���� ������ ���� ȣ�� /  �����ڵ� 0 �̸� ���� /
��ȯ : void
*/
void ProcessTracer::OnExitThread(DWORD threadId, EXIT_THREAD_DEBUG_INFO const & exitThread)
{
	std::cout << "EXIT THREAD " << threadId << ": " << exitThread.dwExitCode << std::endl;
	//eng.stackTrace(threadHandles[threadId], std::cout);
	threadHandles.erase(threadId);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : DLL Load �� �ּҿ� �ִ� fileName���
��ȯ : void
*/
void ProcessTracer::OnLoadDll(LOAD_DLL_DEBUG_INFO const & loadDll)
{
	void *pString = 0;

	ReadProcessMemory(hProcess, loadDll.lpImageName, &pString, sizeof(pString), 0);

	std::string const fileName(eng.getString(pString, loadDll.fUnicode, MAX_PATH));
	dllFileName[loadDll.lpBaseOfDll] = fileName;
	/*lpImageName => hFile �ּ�
	loadDll.fUnicode => �����ڵ� ����
	���ڿ����� �˻�
	access range check*/

	eng.loadModule(loadDll.hFile, loadDll.lpBaseOfDll, fileName);
	std::cout << "LOAD DLL " << loadDll.lpBaseOfDll << " " << fileName << std::endl;
	if (loadDll.hFile)
	{
		CloseHandle(loadDll.hFile);
	}
}



/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : DLL UnLoad �� Address ���
��ȯ : void
*/
void ProcessTracer::OnUnloadDll(UNLOAD_DLL_DEBUG_INFO const & unloadDll)
{
	unloadDll.lpBaseOfDll;
	std::cout << "UNLOAD DLL " << unloadDll.lpBaseOfDll << " " << dllFileName[unloadDll.lpBaseOfDll] << std::endl;
	eng.unloadModule(unloadDll.lpBaseOfDll);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : ����� ��Ʈ�� ���
��ȯ : void
*/
void ProcessTracer::OnOutputDebugString(OUTPUT_DEBUG_STRING_INFO const & debugString)
{
	std::string const output(eng.getString(debugString.lpDebugStringData,
		debugString.fUnicode,//�����ڵ忩��
		debugString.nDebugStringLength));
	std::cout << "OUTPUT DEBUG STRING: " << output << std::endl;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : �����ڵ� + �ּ� ��� ,  ���� ���� �߰� ���
���� Trace ȣ��(�������� ȣ��) , firstchance - ������ ���ܹ߻� ���� ��Ÿ��.
��ȯ : void
*/
void ProcessTracer::OnException(DWORD threadId, DWORD firstChance, EXCEPTION_RECORD const & exception)
{
	std::cout << "EXCEPTION 0x" << std::hex << exception.ExceptionCode << std::dec;
	std::cout << " at " << eng.addressToString(exception.ExceptionAddress) << std::endl << std::endl;

	if (firstChance)
	{
		if (exception.NumberParameters)
			//NumberParameters - �������� ����
		{
			std::cout << "\n  Parameters:";
			for (DWORD idx = 0; idx != exception.NumberParameters; ++idx)
			{
				std::cout << " " << exception.ExceptionInformation[idx];
			}
		}
		std::cout << std::endl;
		eng.stackTrace(threadHandles[threadId], std::cout);
	}
	else
	{
		struct
		{
			SYMBOL_INFO symInfo;
			char name[4 * 256];
		} SymInfo = { { sizeof(SymInfo.symInfo) }, "" };
		PSYMBOL_INFO pSym = &SymInfo.symInfo;
		pSym->MaxNameLen = sizeof(SymInfo.name);
		DWORD64 uDisplacement(0);
		SymFromAddr(hProcess, reinterpret_cast<ULONG_PTR>(exception.ExceptionAddress), &uDisplacement, pSym);
		if (SIZE < 0)
		{
			std::cout << std::endl << "����SIZE �Ұ���" << std::endl;
			exit(1);
		}
		int size = SIZE;
		int rangeSize = 2 * SIZE + 1;
		uint8_t* data = new uint8_t[rangeSize];
		while (true)
		{
			LPVOID addr = (PBYTE)exception.ExceptionAddress - size;
			ReadProcessMemory(hProcess, addr, data, rangeSize * sizeof(uint8_t), 0);
			bool IsCatchCrashPoint = Zydis(data, addr, rangeSize);
			if (IsCatchCrashPoint == false || size >= 512)
			{
				size++;
				rangeSize += 2; //rangeSize = 2 * size + 1;
				data = (uint8_t *)realloc(data, rangeSize);
			}
			else
				break;
		}
		delete[] data;

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_FULL;
		GetThreadContext(threadHandles[threadId], &context);

		std::cout << std::endl << "�������� ���� " << std::endl << std::endl;
#ifdef _M_IX86 
		std::cout << "EAX = " << std::uppercase << std::hex << std::setw(8) << context.Eax; std::cout << "   ";
		std::cout << "EBX = " << std::uppercase << std::hex << std::setw(8) << context.Ebx; std::cout << "   ";
		std::cout << "ECX = " << std::uppercase << std::hex << std::setw(8) << context.Ecx; std::cout << "   ";
		std::cout << "EDX = " << std::uppercase << std::hex << std::setw(8) << context.Edx << std::endl;
		std::cout << "ESI = " << std::uppercase << std::hex << std::setw(8) << context.Esi; std::cout << "   ";
		std::cout << "EDI = " << std::uppercase << std::hex << std::setw(8) << context.Edi; std::cout << "   ";
		std::cout << "EIP = " << std::uppercase << std::hex << std::setw(8) << context.Eip << std::endl;
		std::cout << "ESP = " << std::uppercase << std::hex << std::setw(8) << context.Esp; std::cout << "   ";
		std::cout << "EBP = " << std::uppercase << std::hex << std::setw(8) << context.Ebp; std::cout << "   ";
		std::cout << "EFL = " << std::uppercase << std::hex << std::setw(8) << context.EFlags << std::endl << std::endl;
#elif _M_X64
		std::cout << "RAX = " << std::uppercase << std::hex << std::setw(16) << context.Rax; std::cout << "   ";
		std::cout << "RBX = " << std::uppercase << std::hex << std::setw(16) << context.Rbx; std::cout << "   ";
		std::cout << "RCX = " << std::uppercase << std::hex << std::setw(16) << context.Rcx; std::cout << "   ";
		std::cout << "EDX = " << std::uppercase << std::hex << std::setw(16) << context.Rdx << std::endl;
		std::cout << "RSI = " << std::uppercase << std::hex << std::setw(16) << context.Rsi; std::cout << "   ";
		std::cout << "RDI = " << std::uppercase << std::hex << std::setw(16) << context.Rdi; std::cout << "   ";
		std::cout << "RIP = " << std::uppercase << std::hex << std::setw(16) << context.Rip << std::endl;
		std::cout << "RSP = " << std::uppercase << std::hex << std::setw(16) << context.Rsp; std::cout << "   ";
		std::cout << "RBP = " << std::uppercase << std::hex << std::setw(16) << context.Rbp; std::cout << "   ";
		std::cout << "R8  = " << std::uppercase << std::hex << std::setw(16) << context.R8 << std::endl;
		std::cout << "R9  = " << std::uppercase << std::hex << std::setw(16) << context.R9; std::cout << "   ";
		std::cout << "R10 = " << std::uppercase << std::hex << std::setw(16) << context.R10; std::cout << "   ";
		std::cout << "R11 = " << std::uppercase << std::hex << std::setw(16) << context.R11; std::cout << "   ";
		std::cout << "R12 = " << std::uppercase << std::hex << std::setw(16) << context.R12 << std::endl;
		std::cout << "R13 = " << std::uppercase << std::hex << std::setw(16) << context.R13; std::cout << "   ";
		std::cout << "R14 = " << std::uppercase << std::hex << std::setw(16) << context.R14; std::cout << "   ";
		std::cout << "R15 = " << std::uppercase << std::hex << std::setw(16) << context.R15; std::cout << "   ";
		std::cout << "EFL = " << std::uppercase << std::hex << std::setw(16) << context.EFlags << std::endl << std::endl;
#endif
		std::cout << " (last chance)" << std::endl;

		TerminateProcess(hProcess, 0);
		CloseHandle(hProcess);
	}

}

bool ProcessTracer::Zydis(uint8_t* data32, LPVOID startAddress, int size)
{
	Zydis::InstructionInfo info;
	Zydis::InstructionDecoder decoder;
	Zydis::IntelInstructionFormatter formatter;
	std::cout << "���� : " << size << std::endl;
#ifdef _M_IX86
	//32��Ʈ �����Ϸ�
	DWORD exceptionAddress32 = (DWORD)startAddress + size / 2;
	decoder.setInstructionPointer((DWORD)startAddress);
	Zydis::MemoryInput input32(&data32[0], size);
	decoder.setDisassemblerMode(Zydis::DisassemblerMode::M32BIT);
	decoder.setDataSource(&input32);
	std::cout << "32 bit �����Ϸ� ..." << std::endl << std::endl;

	while (decoder.decodeInstruction(info))
		if (exceptionAddress32 == info.instrAddress)
			break;

	if (exceptionAddress32 != info.instrAddress || !info.instrPointer)
		return false;
	decoder.setInstructionPointer((DWORD64)startAddress);
	input32.setPosition(0);

	//��ºκ�
	while (decoder.decodeInstruction(info))
	{
		(exceptionAddress32 == info.instrAddress) ? std::cout << "(*)" : std::cout << "   ";
		std::cout << std::hex << std::setw(8) << std::setfill('0') << std::uppercase
			<< info.instrAddress << " ";
		if (info.flags & Zydis::IF_ERROR_MASK)
		{
			std::cout << "db " << std::setw(2) << static_cast<int>(info.data[0]) << std::endl;
		}
		else
		{
			std::cout << formatter.formatInstruction(info) << std::endl;
		}
	}
#elif _M_X64
	//64��Ʈ �����Ϸ�

	DWORD64 exceptionAddress64 = (DWORD64)startAddress + size / 2;
	Zydis::MemoryInput input64(&data32[0], size);
	decoder.setDisassemblerMode(Zydis::DisassemblerMode::M64BIT);
	decoder.setDataSource(&input64);
	decoder.setInstructionPointer((DWORD64)startAddress);
	std::cout << "64 bit �����Ϸ� ..." << std::endl << std::endl;
	while (decoder.decodeInstruction(info))
		if (exceptionAddress64 == info.instrAddress)
			break;

	if (exceptionAddress64 != info.instrAddress || !info.instrPointer)
		return false;
	decoder.setInstructionPointer((DWORD64)startAddress);
	input64.setPosition(0);

	while (decoder.decodeInstruction(info))
	{
		(exceptionAddress64 == info.instrAddress) ? std::cout << "(*)" : std::cout << "   ";
		std::cout << std::hex << std::setw(16) << std::setfill('0') << std::uppercase << info.instrAddress << " ";
		if (info.flags & Zydis::IF_ERROR_MASK)
		{
			std::cout << "db " << std::setw(2) << static_cast<int>(info.data[0]) << std::endl;
		}
		else
		{
			std::cout << formatter.formatInstruction(info) << std::endl;
		}
	}
#endif
	std::cin.get();
	return true;
}
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
��� : �Ű������� command line parameter�� ���� ��Ʈ�� �ּҿ� ������ ��Ʈ�� ���� �ּҸ� �޴´�.
CString cmdLine�� command line parameter copy
command line parameter�� command �� �Ͽ� Process ����.
��ȯ : void
*/
void ProcessTracer::MyCreateProcess(int argc, TCHAR ** begin)
{
	++begin;
	--argc;
	TCHAR** end = begin + argc;
	CString cmdLine;
	for (TCHAR **it = begin; it != end; ++it)
	{
		if (!cmdLine.IsEmpty()) cmdLine += ' ';

		if (_tcschr(*it, ' '))//== true
			//strchr function ã�����ϴ� ���� ������  return NULL
		{
			cmdLine += '"';
			cmdLine += *it;
			cmdLine += '"';
		}
		else
		{
			cmdLine += *it;
		}
	}

	STARTUPINFO startupInfo = { sizeof(startupInfo) };
	startupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_SHOWNORMAL;
	// Assist GUI programs
	PROCESS_INFORMATION ProcessInformation = { 0 };

	if (!CreateProcess(0, const_cast<TCHAR *>(cmdLine.GetString()),
		0, 0, true,
		DEBUG_ONLY_THIS_PROCESS,
		0, 0, &startupInfo, &ProcessInformation))
	{
		std::ostringstream oss;
		oss << GetLastError();
#ifdef UNICODE
		size_t len = _tcslen(*begin) + 1;
		char *str = new char[len];
		wcstombs(str, *begin, len);
		//WBCS => MBCS
		throw std::runtime_error(std::string("Unable to start ") + str + ": " + oss.str());
		delete str;
#else
		throw std::runtime_error(std::string("Unable to start ") + *begin + ": " + oss.str());
#endif
	}
	CloseHandle(ProcessInformation.hProcess);
	CloseHandle(ProcessInformation.hThread);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
/*
��ȯ : bool
��� : command line parameter ���翩��
�����ϸ� true , ������ false
*/
bool ProcessTracer::IsExistArgv(int argc)
{
	if (argc <= 1)
	{
		printf("Syntax: ProcessTracer command_line\n");
		return false;
	}
	return true;
}


