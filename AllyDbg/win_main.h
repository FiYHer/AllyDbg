#pragma once

//创建窗口
void create_main_window();

//窗口过程
LRESULT _stdcall window_proc(HWND, UINT, WPARAM, LPARAM);

//创建消息
void on_create_event(HWND, WPARAM, LPARAM);

//控件消息
void on_command_event(HWND, WPARAM, LPARAM);

//绘制消息
void on_paint_event(HWND, WPARAM, LPARAM);

//大小消息
void on_size_event(HWND, LPARAM, LPARAM);

//退出消息
void on_close_event(HWND, WPARAM, LPARAM);

//重置控件大小
void resize_controls_size(HWND);

//创建控件
void create_window_controls(HWND);

//创建汇编代码显示list控件
void create_asm_list(HWND);

//设置column
void set_column(HWND hWnd, const wchar_t* text, int index, int length, int mode);

//设置item
void set_item(HWND hWnd, int index, int address, const char* hex, const char* asm, const char* command);

//选择一个文件
wchar_t* select_file(const wchar_t* file_type);


