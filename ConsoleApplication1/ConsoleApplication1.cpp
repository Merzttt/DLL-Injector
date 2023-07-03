#include <Windows.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <VersionHelpers.h>
#include <atlstr.h>

#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

BOOL InjectDLL(DWORD ProcessID, LPCSTR DLL_PATH)
{
    LPVOID LoadLibAddy, RemoteString;

    if (!ProcessID)
        return false;

    HANDLE Proc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, ProcessID);

    if (!Proc)
    {
        std::cout << "OpenProcess() failed: " << GetLastError() << std::endl;
        return false;
    }

    LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_PATH) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(Proc, RemoteString, (LPVOID)DLL_PATH, strlen(DLL_PATH) + 1, NULL);
    CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, RemoteString, NULL, NULL);

    CloseHandle(Proc);

    return true;
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    DWORD dwThreadId, dwProcessId;
    HINSTANCE hInstance;
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    if (!hWnd)
        return TRUE;        // Not a window
    if (!::IsWindowVisible(hWnd))
        return TRUE;        // Not visible
    if (!SendMessage(hWnd, WM_GETTEXT, sizeof(szProcessName), (LPARAM)szProcessName))
        return TRUE;        // No window title

    dwThreadId = GetWindowThreadProcessId(hWnd, &dwProcessId);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
    if (hProcess != NULL)
    {
        HMODULE hModule;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded))
        {
            GetModuleBaseName(hProcess, hModule, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }
        CloseHandle(hProcess);
    }

    std::wcout << "PID: " << dwProcessId << '\t' << szProcessName << std::endl;

    return TRUE;
}

int main() {
    if (IsWindowsXPOrGreater()) {
        std::cout << "Available Targets:\n\n" << std::endl;
        EnumWindows(EnumWindowsProc, NULL);
        std::cout << "\nPick Target ProcessID: ";
        DWORD PID;
        std::cin >> PID;

        char modulePath[MAX_PATH];
        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        std::string injectorPath(modulePath);
        std::size_t lastSlash = injectorPath.find_last_of("\\/");
        std::string dllPath = injectorPath.substr(0, lastSlash + 1) + "MainDLL.dll";
        InjectDLL(PID, dllPath.c_str());
    }
    else {
        std::cout << "Method not supported by OS. Terminating." << std::endl;
        return 0;
    }

    return 0;
}