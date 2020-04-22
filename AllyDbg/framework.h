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

//��Դ�ļ�
#include "resource.h"

//���������
#include "disasm/disasm.h"

enum controls_id
{
	LIST_ASM = 2000
};

struct global_variable
{
	wchar_t window_class_name[MAX_STRING];//��������
	HWND window_hwnd;//���ھ��
	struct control
	{
		HWND list_asm;//�����ʾlist
	}controls;
	struct debug
	{
		HANDLE debug_thread;//�����߳̾��
		PROCESS_INFORMATION process_info;//������Ϣ
		int is_debuging;//�Ƿ��ڵ�����
		DWORD continue_state;//debug����״̬
		int is_detach;//�Ƿ��������
	}debugs;
	struct pe
	{
		LPVOID image_base_address;//ӳ���ַ
		PIMAGE_DOS_HEADER dos;
		PIMAGE_NT_HEADERS nt;
		PIMAGE_SECTION_HEADER section;
	}pes;
};
extern struct global_variable g_global;

inline void message_box(const char* str) 
{ 
	char buffer[MAX_STRING];
	wsprintfA(buffer, "%s ������� : %d", str, GetLastError());
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