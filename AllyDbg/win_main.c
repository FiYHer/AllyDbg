#include "framework.h"

#include "pe_analyse.h"
#include "debug_handle.h"

#include "win_main.h"

struct global_variable g_global;

int _stdcall WinMain(HINSTANCE hInstance, HINSTANCE ignore1, LPSTR ignore2, int nShowCmd)
{
	create_main_window();
	return 0;
}

void create_main_window()
{
	wcscpy(g_global.window_class_name, L"AllyDbg");

	WNDCLASSEXW win_class;
	ZeroMemory(&win_class, sizeof(win_class));
	win_class.cbSize					= sizeof(win_class);
	win_class.style						= CS_HREDRAW | CS_VREDRAW;
	win_class.lpfnWndProc		= window_proc;
	win_class.cbClsExtra			= 0;
	win_class.cbWndExtra			= 0;
	win_class.hInstance				= GetModuleHandleW(NULL);
	win_class.hCursor				= LoadCursorW(NULL, IDC_ARROW);
	win_class.hbrBackground	= (HBRUSH)(COLOR_WINDOW + 1);
	win_class.lpszMenuName   = MAKEINTRESOURCEW(IDR_MENU1);
	win_class.lpszClassName		= g_global.window_class_name;
	if (RegisterClassExW(&win_class) == FALSE)
	{
		message_box("注册窗口类失败");
		return;
	}

	g_global.window_hwnd = CreateWindowW(g_global.window_class_name, g_global.window_class_name,
		WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, win_class.hInstance, NULL);
	if (g_global.window_hwnd == NULL)
	{
		message_box("创建窗口失败");
		return;
	}

	UpdateWindow(g_global.window_hwnd);
	ShowWindow(g_global.window_hwnd, SW_SHOW);

	MSG msg;
	while (GetMessageW(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
}

LRESULT _stdcall window_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE: on_create_event(hWnd,wParam,lParam); return 1;
	case WM_COMMAND:on_command_event(hWnd, wParam, lParam); break;
	case WM_PAINT:on_paint_event(hWnd,wParam,lParam); break;
	case WM_SIZE:on_size_event(hWnd,wParam,lParam); break;
	case WM_CLOSE:on_close_event(hWnd,wParam,lParam); break;
	default: return DefWindowProcW(hWnd, uMsg, wParam, lParam);
	}
	return 0;
}

void on_create_event(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	create_window_controls(hWnd);
}

void on_command_event(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	switch (LOWORD(wParam))
	{
	case ID_CREATE_PROCESS:
	{
		wchar_t* target = select_file(L"Execute File\0*.exe;*.dll;*.sys\0\0");
		if (target)
			ready_debug_process(target);
	}
	break;
	case ID_EXIT_PROCESS:
	{
		g_global.debugs.is_debuging = 0;
	}
	break;
	case ID_DETACH_PROCESS:
	{
		g_global.debugs.is_detach = 1;
	}
	break;
	}
}

void on_paint_event(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hWnd, &ps);
	EndPaint(hWnd, &ps);
}

void on_size_event(HWND hWnd, LPARAM wParam, LPARAM lParam)
{
	resize_controls_size(hWnd);
}

void on_close_event(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	PostQuitMessage(0);
}

void resize_controls_size(HWND hWnd)
{
	RECT window_size;
	GetWindowRect(hWnd, &window_size);
	int width = (int)((window_size.right - window_size.left) * 0.7f);
	int height = (int)((window_size.bottom - window_size.top) * 0.7f);

	MoveWindow(g_global.controls.list_asm, 0, 0, width, height, TRUE);
	set_column(g_global.controls.list_asm, L"指令地址", 0, (int)(width * 0.2f), 1);
	set_column(g_global.controls.list_asm, L"十六进制", 1, (int)(width * 0.25f), 1);
	set_column(g_global.controls.list_asm, L"汇编指令", 2, (int)(width * 0.25f), 1);
	set_column(g_global.controls.list_asm, L"备注内容", 3, (int)(width * 0.3f), 1);




}

void create_window_controls(HWND hWnd)
{
	create_asm_list(hWnd);



}

void create_asm_list(HWND hWnd)
{
	g_global.controls.list_asm = create_control(hWnd, WC_LISTVIEWW, LVS_REPORT, LIST_ASM);
	if (g_global.controls.list_asm == NULL)
	{
		message_box("创建list控件失败");
		exit(-1);
	}

	ListView_SetExtendedListViewStyle(g_global.controls.list_asm, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	set_column(g_global.controls.list_asm, L"指令地址", 0, 0, 0);
	set_column(g_global.controls.list_asm, L"十六进制", 1, 0, 0);
	set_column(g_global.controls.list_asm, L"汇编指令", 2, 0, 0);
	set_column(g_global.controls.list_asm, L"备注内容", 3, 0, 0);

}

void set_column(HWND hWnd, const wchar_t* text, int index, int length, int mode)
{
	LVCOLUMNW column;
	ZeroMemory(&column, sizeof(column));
	column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	column.pszText = (wchar_t*)text;
	column.cx = length;
	column.iSubItem = index;
	if (mode) ListView_SetColumn(hWnd, index, &column);
	else ListView_InsertColumn(hWnd, index, &column);
}

void set_item(HWND hWnd, int index,  int address, const char* hex, const char* asm, const char* command)
{
	wchar_t buffer[MAX_STRING];

	LVITEMW vite;
	ZeroMemory(&vite, sizeof(vite));
	vite.mask = LVIF_TEXT;
	vite.iItem = index;

	wsprintfW(buffer, L"%X", address);
	vite.pszText = buffer;
	vite.iSubItem = 0;
	ListView_InsertItem(hWnd, &vite);

	to_wchar(hex, buffer, MAX_STRING);
	vite.pszText = buffer;
	vite.iSubItem = 1;
	ListView_SetItem(hWnd,&vite);

	to_wchar(asm, buffer, MAX_STRING);
	vite.pszText = buffer;
	vite.iSubItem = 2;
	ListView_SetItem(hWnd, &vite);

	to_wchar(command, buffer, MAX_STRING);
	vite.pszText = buffer;
	vite.iSubItem = 3;
	ListView_SetItem(hWnd, &vite);

}

wchar_t* select_file(const wchar_t* file_type)
{
	OPENFILENAMEW ofn;
	ZeroMemory(&ofn, sizeof(ofn));
	wchar_t *path = alloc_memory(MAX_STRING);
	ofn.lStructSize = sizeof(OPENFILENAMEW);//结构体大小
	ofn.hwndOwner = NULL;//拥有着窗口句柄，为NULL表示对话框是非模态的，实际应用中一般都要有这个句柄
	ofn.lpstrFilter = file_type;//设置过滤
	ofn.nFilterIndex = 1;//过滤器索引
	ofn.lpstrFile = path;//接收返回的文件名，注意第一个字符需要为NULL
	ofn.nMaxFile = MAX_PATH;//缓冲区长度
	ofn.lpstrInitialDir = NULL;//初始目录为默认
	ofn.lpstrTitle = TEXT("请选择一个文件");//使用系统默认标题留空即可
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;//文件、目录必须存在，隐藏只读选项
	if (GetOpenFileNameW(&ofn)) return path;
	free_memory(path);
	return NULL;
}

