#pragma once
#include <wchar.h>
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib,"dbghelp.lib")

//���Գ���ǰ׼��
void ready_debug_process(const wchar_t* target);

//�����߳�
unsigned int __stdcall debug_thread(void* data);

//�쳣
void on_exception_debug_event(EXCEPTION_DEBUG_INFO* exception);

//�����߳�
void on_create_thread_debug_event(CREATE_THREAD_DEBUG_INFO* create_thread);

//��������
void on_create_process_debug_event(CREATE_PROCESS_DEBUG_INFO* create_process);

//�����߳�
void on_exit_thread_debug_event(EXIT_THREAD_DEBUG_INFO* exit_thread);

//��������
void on_exit_process_debug_event(EXIT_PROCESS_DEBUG_INFO* exit_process);

//����dll
void on_load_dll_debug_event(LOAD_DLL_DEBUG_INFO* load_dll);

//ж��dll
void on_unload_dll_debug_event(UNLOAD_DLL_DEBUG_INFO* unload_dll);

//���string
void on_output_debug_string_event(OUTPUT_DEBUG_STRING_INFO* output_string);

//rip
void on_rip_debug_event(RIP_INFO* rip);






