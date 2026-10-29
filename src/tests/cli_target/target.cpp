// Test debuggee for x64dbg-cli. The mode is selected with the first argument.
#include <windows.h>
#include <stdio.h>
#include <string.h>

// A function that the debugger can find by name (bp cli_target.marker_func).
extern "C" __declspec(dllexport) __declspec(noinline) void marker_func()
{
    HANDLE h = CreateFileW(L"C:\\x64dbg-cli-no-such-file.bin", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if(h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
    Sleep(50);
}

static const char knownString[] = "x64dbg-cli-known-string";

static DWORD WINAPI threadMain(LPVOID)
{
    Sleep(1);
    return 0;
}

int main(int argc, char** argv)
{
    const char* mode = argc > 1 ? argv[1] : "call";
    if(!strcmp(mode, "call"))
    {
        marker_func();
        ExitProcess(7);
    }
    if(!strcmp(mode, "loop"))
    {
        for(;;)
            Sleep(10);
    }
    if(!strcmp(mode, "except"))
    {
        *(volatile int*)0 = 1;
        return 0;
    }
    if(!strcmp(mode, "threads"))
    {
        for(;;)
        {
            HANDLE h[4];
            for(int i = 0; i < 4; i++)
                h[i] = CreateThread(nullptr, 0, threadMain, nullptr, 0, nullptr);
            WaitForMultipleObjects(4, h, TRUE, INFINITE);
            for(int i = 0; i < 4; i++)
                CloseHandle(h[i]);
        }
    }
    if(!strcmp(mode, "ods"))
    {
        OutputDebugStringA("hello-ods");
        Sleep(100);
        return 0;
    }
    if(!strcmp(mode, "print"))
    {
        puts("hello-from-debuggee");
        fflush(stdout);
        return 0;
    }
    if(!strcmp(mode, "wait"))
    {
        Sleep(INFINITE);
        return 0;
    }
    if(!strcmp(mode, "unload"))
    {
        HMODULE module = LoadLibraryW(L"winhttp.dll");
        if(module)
            FreeLibrary(module);
        Sleep(100);
        ExitProcess(0);
    }
    if(!strcmp(mode, "strings"))
    {
        volatile const char* p = knownString;
        (void)p;
        Sleep(INFINITE);
        return 0;
    }
    return 3;
}
