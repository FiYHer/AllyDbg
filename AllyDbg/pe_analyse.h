#pragma once
#include <Windows.h>
#include <wchar.h>

//移除随机基址
int erase_random_address(const wchar_t* target);

//解析pe信息
void analyse_file_info(HANDLE hProcess, LPVOID pBaseAddr);

//解析十六进制
void hex_to_asm(HANDLE hProcess);








