#pragma once
#include <Windows.h>
#include <wchar.h>

//�Ƴ������ַ
int erase_random_address(const wchar_t* target);

//����pe��Ϣ
void analyse_file_info(HANDLE hProcess, LPVOID pBaseAddr);

//����ʮ������
void hex_to_asm(HANDLE hProcess);








