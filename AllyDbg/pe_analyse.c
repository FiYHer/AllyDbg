#include "pe_analyse.h"
#include "framework.h"
#include "win_main.h"

struct global_variable g_global;

int erase_random_address(const wchar_t* target)
{
	HANDLE file = CreateFileW(target, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		message_box("打开文件失败");
		return 0;
	}

	DWORD reader;
	IMAGE_DOS_HEADER dos;
	BOOL state = ReadFile(file, &dos, sizeof(dos), &reader, NULL);
	if (state == FALSE || dos.e_magic != IMAGE_DOS_SIGNATURE)
	{
		CloseHandle(file);
		message_box("Dos头有误");
		return 0;
	}

	SetFilePointer(file, dos.e_lfanew, 0, FILE_BEGIN);
	IMAGE_NT_HEADERS nt;
	state = ReadFile(file, &nt, sizeof(nt), &reader, NULL);
	if (state == FALSE || nt.Signature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(file);
		message_box("Nt头有误");
		return 0;
	}

	if (nt.OptionalHeader.DllCharacteristics != 32768)
	{
		nt.OptionalHeader.DllCharacteristics = 32768;
		SetFilePointer(file, dos.e_lfanew, 0, FILE_BEGIN);
		state = WriteFile(file, &nt, sizeof(nt), &reader, NULL);
		if (state == FALSE)
		{
			message_box("修改标志失败");
			CloseHandle(file);
			return 0;
		}
	}

	CloseHandle(file);
	return 1;
}

void analyse_file_info(HANDLE hProcess, LPVOID pBaseAddr)
{
	if (g_global.pes.dos == NULL) g_global.pes.dos = (PIMAGE_DOS_HEADER)alloc_memory(sizeof(IMAGE_DOS_HEADER));
	if (g_global.pes.nt == NULL) g_global.pes.nt = (PIMAGE_NT_HEADERS)alloc_memory(sizeof(IMAGE_NT_HEADERS));
	
	DWORD reader;
	BOOL state = ReadProcessMemory(hProcess, pBaseAddr, g_global.pes.dos, sizeof(IMAGE_DOS_HEADER), &reader);
	if (state == FALSE)
	{
		message_box("读取dos失败");
		return;
	}

	state = ReadProcessMemory(hProcess, (LPCVOID)((DWORD)pBaseAddr + g_global.pes.dos->e_lfanew), g_global.pes.nt, sizeof(IMAGE_NT_HEADERS), &reader);
	if (state == FALSE)
	{
		message_box("读取nt失败");
		return;
	}

	if (g_global.pes.section) free_memory(g_global.pes.section);
	g_global.pes.section = alloc_memory(sizeof(IMAGE_SECTION_HEADER) * g_global.pes.nt->FileHeader.NumberOfSections);
	state = ReadProcessMemory(hProcess, (LPCVOID)((DWORD)pBaseAddr + g_global.pes.dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)), g_global.pes.section, sizeof(IMAGE_SECTION_HEADER) * g_global.pes.nt->FileHeader.NumberOfSections, &reader);
	if (state == FALSE)
	{
		message_box("读取section失败");
		return;
	}

	g_global.pes.image_base_address = pBaseAddr;
	return;
}

void hex_to_asm(HANDLE hProcess)
{
	int code_base = g_global.pes.nt->OptionalHeader.BaseOfCode;
	int code_length = g_global.pes.nt->OptionalHeader.SizeOfCode;

	unsigned char* hex_data = alloc_memory(code_length);
	DWORD reader;
	BOOL state = ReadProcessMemory(hProcess, (LPCVOID)((DWORD)g_global.pes.image_base_address + code_base), hex_data, code_length, &reader);
	if (state == FALSE)
	{
		message_box("读取十六进制数据错误");
		free_memory(hex_data);
		return;
	}

	for (int i = 0, index = 0; i < code_length; index++)
	{
		unsigned char* data = hex_data + i;

		t_disasm asm_info;
		ulong len = Disasm(data, code_length - i, g_global.pes.nt->OptionalHeader.ImageBase + code_base + i, &asm_info, DISASM_FILE);

		set_item(g_global.controls.list_asm, index, g_global.pes.nt->OptionalHeader.ImageBase + code_base + i, asm_info.dump, asm_info.result, asm_info.comment);

		i += len;
	}

	free_memory(hex_data);
	return;
}
