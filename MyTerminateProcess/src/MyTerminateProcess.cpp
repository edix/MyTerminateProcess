#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS(x) ((x) >= 0)

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

typedef NTSTATUS (NTAPI *NTQUERYSYSTEMINFORMATION)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


bool CloseProcessHandles( DWORD dwProcessId, HANDLE hProcessHandle )
{
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	ULONG handleInfoSize = 0x10000;
	NTSTATUS NtStatus = 0;
	HANDLE hDuplicateHandle = NULL;
	bool fResult = false;

	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if ( NtQuerySystemInformation == NULL )
	{
		return fResult;
	}

	// 
	// NtQuerySystemInformation won't give us the correct buffer size, so we have to guess it
	//
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while (handleInfo != NULL)
	{
		NtStatus = NtQuerySystemInformation(SystemHandleInformation, &handleInfo, handleInfoSize, NULL);
		if ( NtStatus == STATUS_INFO_LENGTH_MISMATCH )
		{
			handleInfoSize *= 2;
			PSYSTEM_HANDLE_INFORMATION pTemp = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
			if ( pTemp == NULL )
			{
				//
				// error, no memory anymore...
				//
				printf( "not enough memory (alloc %u bytes)!\n", handleInfoSize );
				break;
			}
			handleInfo = pTemp;
		}
		else
			break;
	}

	if ( NT_SUCCESS(NtStatus) && handleInfo )
	{
		//
		// allocated buffer, duplicate handle and close handle
		//
		for ( unsigned int n = 0; n < handleInfo->HandleCount; n++ )
		{
			 SYSTEM_HANDLE handle = handleInfo->Handles[n];
			 if ( handle.ProcessId != dwProcessId )
				 continue;

			 if ( DuplicateHandle(hProcessHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &hDuplicateHandle, 0, FALSE, DUPLICATE_CLOSE_SOURCE) == FALSE )
			 {
				 printf( "can't get handle %08x from process %u", handle.Handle, handle.ProcessId );
				 continue;
			 }

			 CloseHandle( hDuplicateHandle );

			 if ( !fResult ) 
				 fResult = true;

		}
	}

	free(handleInfo);
	handleInfo = NULL;

	return fResult;
}

//void PrintLastError()
//{
//	DWORD dwError;
//	char* szErrorMessage = NULL;
//
//	dwError = GetLastError();
//	FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError, 0, szErrorMessage, 0, NULL );
//
//	printf( "Error Code: %u\nError Message: %s\n", dwError, szErrorMessage );
//
//	LocalFree( szErrorMessage );
//}

bool KillProcess( DWORD dwProcessId )
{
	HANDLE hProcess = NULL;
	bool fResult = false;

	printf( "Killing process %u ...\n", dwProcessId );

	hProcess = OpenProcess( PROCESS_TERMINATE | PROCESS_DUP_HANDLE, FALSE, dwProcessId );
	if ( hProcess == NULL )
	{
		printf( "OpenProcess failed!\n" );
		//PrintLastError();
		return fResult;
	}

	if (TerminateProcess(hProcess, 0) == FALSE)
	{
		//
		// TerminateProcess failed, try to close all handles - because the program might wait for some open handles
		//
		// ignore file-system handles
		//
		fResult = CloseProcessHandles( dwProcessId, hProcess );

	}
	// close handle 
	CloseHandle( hProcess );

	return fResult;
}

int main(int argc, char* argv[])
{
	DWORD dwProcessId;

	if ( argc == 2 )
	{
		dwProcessId = atol(argv[1]);

		KillProcess( atol(argv[1]) );
	}
	else
	{
		printf( "usage: myterminateprocess.exe <process-id>\n" );
	}

	return 0;
}