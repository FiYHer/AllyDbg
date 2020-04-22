#pragma once
#define MAX_STRING 1024

//Win32
#include <Windows.h>
#include <Windowsx.h>
#include <Commctrl.h>
#include <Commdlg.h>
//C
#include <assert.h>
#include <stdio.h>
#include <wchar.h>

//资源文件
#include "resource.h"

//反汇编引擎
#include "disasm/disasm.h"

enum controls_id
{
	LIST_ASM = 2000
};

struct global_variable
{
	wchar_t window_class_name[MAX_STRING];//窗口类名
	HWND window_hwnd;//窗口句柄
	struct control
	{
		HWND list_asm;//汇编显示list
	}controls;
	struct debug
	{
		HANDLE debug_thread;//调试线程句柄
		PROCESS_INFORMATION process_info;//进程信息
		int is_debuging;//是否在调试中
		DWORD continue_state;//debug继续状态
		int is_detach;//是否脱离调试
	}debugs;
	struct pe
	{
		LPVOID image_base_address;//映像基址
		PIMAGE_DOS_HEADER dos;
		PIMAGE_NT_HEADERS nt;
		PIMAGE_SECTION_HEADER section;
	}pes;
};
extern struct global_variable g_global;

inline void message_box(const char* str) 
{ 
	char buffer[MAX_STRING];
	wsprintfA(buffer, "%s 错误代码 : %d", str, GetLastError());
	MessageBoxA(g_global.window_hwnd, buffer, NULL, MB_OK | MB_ICONHAND);
}
inline void to_wchar(const char* text, wchar_t* unicode, int size)
{
	ZeroMemory(unicode, size);
	int length = strlen(text);
	int len = MultiByteToWideChar(CP_ACP, 0, text, length, NULL, 0);
	if(size > len)
		MultiByteToWideChar(CP_ACP, 0, text, length, unicode, len);
}
inline HWND create_control(HWND hWnd, const wchar_t* control, int control_type, int control_id) { return CreateWindowW(control, control, WS_CHILD | WS_VISIBLE | WS_BORDER | control_type, 0, 0, 0, 0, hWnd, (HMENU)control_id, GetModuleHandleW(NULL), NULL); }
inline LPVOID alloc_memory(int size) { return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
inline void free_memory(LPVOID addr) { VirtualFree(addr, 0, MEM_RELEASE); addr = NULL; }


#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' \
version='6.0.0.0' \
processorArchitecture='*' \
publicKeyToken='6595b64144ccf1df' \
language='*'\"")