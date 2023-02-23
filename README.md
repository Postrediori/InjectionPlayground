# InjectionPlayground

## Description

This project contains a collection of several DLL injection mthods:
* Creating remote thread in a target process (CreateRemoteThread, RtlCreateUserThread, NtCreateThreadEx)
* Injection of shellcode with SetThreadContext
* Injection with QueueUserApc
* Injection by setting windows hooks with SetWindowsHook

The code is capable of injection into both x64 and x86 processes (platform-specific injection DLLs are also generated).

Compiled using Visual Studio 2019 & C++17.

Project consists of the following parts:
* InjectedDll &ndash; project with DLL payload that is injected into a process. It shows a message box with information about process and thread.
* WindowsHookDll &ndash; DLL payload for SetWindowsHook method. The difference is an exported function that is needed for setting a hook for window events.
* InjectionLib &ndash; static library for code that is common between InjectedDll and WindowsHookDll. Logging stuff and messaging functions.
* InjectionPlayground &ndash; console utility that inject a DLL into all processes with specified executable names.

Usage of a console utility:

```
InjectionPlayground <process name> [injection method id]
```

Injection methods:
* 1 - CreateRemoteThread (default)
* 2 - RtlCreateUserThread
* 3 - NtCreateThreadEx
* 4 - SetThreadContext
* 5 - QueueUserApc
* 6 - SetWindowsHook


## TODO

* [ ] InjectDllByOEP - injection loader function is contained in the injected DLL itself. May be useful for dealing with complex loading process

Really don't know whether the following is worth adding:
* [ ] SetThreadContext & LoadLibraryExW injections. Requires updated shellcode
* [ ] Reflective injection
* [ ] Inject from driver in kernel space


## Links

Used code from:
* [InjectCollection](https://github.com/AzureGreen/InjectCollection/) by [AzureGreen on GitHub](https://github.com/AzureGreen) &ndash; Some helpful utilities and `Define.h`
* [3 Effective DLL Injection Techniques for Setting API Hooks](https://www.apriorit.com/dev-blog/679-windows-dll-injection-for-api-hooks)

Related code:
* [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) by [stephenfewer](https://github.com/stephenfewer) &ndash; Another injection technique
* [injection](https://github.com/odzhan/injection) by [odzhan](https://github.com/odzhan/injection) &ndash; Collection of injection methods
