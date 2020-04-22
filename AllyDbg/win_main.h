#pragma once

//��������
void create_main_window();

//���ڹ���
LRESULT _stdcall window_proc(HWND, UINT, WPARAM, LPARAM);

//������Ϣ
void on_create_event(HWND, WPARAM, LPARAM);

//�ؼ���Ϣ
void on_command_event(HWND, WPARAM, LPARAM);

//������Ϣ
void on_paint_event(HWND, WPARAM, LPARAM);

//��С��Ϣ
void on_size_event(HWND, LPARAM, LPARAM);

//�˳���Ϣ
void on_close_event(HWND, WPARAM, LPARAM);

//���ÿؼ���С
void resize_controls_size(HWND);

//�����ؼ�
void create_window_controls(HWND);

//������������ʾlist�ؼ�
void create_asm_list(HWND);

//����column
void set_column(HWND hWnd, const wchar_t* text, int index, int length, int mode);

//����item
void set_item(HWND hWnd, int index, int address, const char* hex, const char* asm, const char* command);

//ѡ��һ���ļ�
wchar_t* select_file(const wchar_t* file_type);


