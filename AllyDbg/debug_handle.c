#include "debug_handle.h"
#include "framework.h"
#include "pe_analyse.h"

#include <process.h>

struct global_variable g_global;

void ready_debug_process(const wchar_t* target)
{
	g_global.debugs.debug_thread = (HANDLE)_beginthreadex(NULL, 0, debug_thread, (void*)target, 0, NULL);
	if (g_global.debugs.debug_thread)
	{
	}
	else
	{
		message_box("创建调试线程失败");
		free_memory((LPVOID)target);
	}
}

unsigned int __stdcall debug_thread(void* data)
{
	wchar_t* target = (wchar_t*)data;

	STARTUPINFOW startup;
	ZeroMemory(&startup, sizeof(startup));
	startup.cb = sizeof(startup);
	BOOL state = CreateProcessW(target, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &startup, &g_global.debugs.process_info);
	free_memory(data);
	if (state == FALSE)
	{
		message_box("创建调试进程失败");
		return -1;
	}

	g_global.debugs.is_debuging = 1;
	g_global.debugs.is_detach = 0;
	g_global.debugs.continue_state = DBG_CONTINUE;

	DEBUG_EVENT debug_info;
	ZeroMemory(&debug_info, sizeof(debug_info));
	while (1)
	{
		if(g_global.debugs.is_debuging == 0) break;
		if(g_global.debugs.is_detach == 1) break;

		if (WaitForDebugEvent(&debug_info, 1000))
		{
			switch (debug_info.dwDebugEventCode)
			{
			case EXCEPTION_DEBUG_EVENT: on_exception_debug_event(&debug_info.u.Exception); break;
			case CREATE_THREAD_DEBUG_EVENT: on_create_thread_debug_event(&debug_info.u.CreateThread); break;
			case CREATE_PROCESS_DEBUG_EVENT: on_create_process_debug_event(&debug_info.u.CreateProcessInfo); break;
			case EXIT_THREAD_DEBUG_EVENT: on_exit_thread_debug_event(&debug_info.u.ExitThread); break;
			case EXIT_PROCESS_DEBUG_EVENT: on_exit_process_debug_event(&debug_info.u.ExitProcess); break;
			case LOAD_DLL_DEBUG_EVENT: on_load_dll_debug_event(&debug_info.u.LoadDll); break;
			case UNLOAD_DLL_DEBUG_EVENT: on_unload_dll_debug_event(&debug_info.u.UnloadDll); break;
			case OUTPUT_DEBUG_STRING_EVENT: on_output_debug_string_event(&debug_info.u.DebugString); break;
			case RIP_EVENT: on_rip_debug_event(&debug_info.u.RipInfo); break;
			}
			ContinueDebugEvent(debug_info.dwProcessId, debug_info.dwThreadId, g_global.debugs.continue_state);
		}
		else if (GetLastError() != 121)
		{
			message_box("遇到未知错误");
			g_global.debugs.is_debuging = 0;
		}
	}

	message_box("退出调试线程");
	DebugActiveProcessStop(g_global.debugs.process_info.dwProcessId);
	if (g_global.debugs.is_debuging == 0) TerminateProcess(g_global.debugs.process_info.hProcess, 0);
	CloseHandle(g_global.debugs.process_info.hProcess);
	CloseHandle(g_global.debugs.process_info.hThread);
	g_global.debugs.process_info.hProcess = NULL;
	g_global.debugs.process_info.hThread = NULL;
	g_global.debugs.process_info.dwProcessId = 0;
	g_global.debugs.process_info.dwThreadId = 0;
	return 0;
}

void on_exception_debug_event(EXCEPTION_DEBUG_INFO* exception)
{

}

void on_create_thread_debug_event(CREATE_THREAD_DEBUG_INFO* create_thread)
{

}

void on_create_process_debug_event(CREATE_PROCESS_DEBUG_INFO* create_process)
{
	analyse_file_info(create_process->hProcess, create_process->lpBaseOfImage);
	hex_to_asm(create_process->hProcess);
}

void on_exit_thread_debug_event(EXIT_THREAD_DEBUG_INFO* exit_thread)
{

}

void on_exit_process_debug_event(EXIT_PROCESS_DEBUG_INFO* exit_process)
{

}

void on_load_dll_debug_event(LOAD_DLL_DEBUG_INFO* load_dll)
{

}

void on_unload_dll_debug_event(UNLOAD_DLL_DEBUG_INFO* unload_dll)
{

}

void on_output_debug_string_event(OUTPUT_DEBUG_STRING_INFO* output_string)
{

}

void on_rip_debug_event(RIP_INFO* rip)
{

}
