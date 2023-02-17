# InjectionPlayground

## Description

Collection of injection techniques using:
* CreateRemoteThread
* RtlCreateUserThread
* NtCreateThreadEx
* SetThreadContext (now only x64)

Compiled using Visual Studio 2019 & C++17.

Project consists of the following parts:
* InjectedDll &ndash; project with DLL payload that is injected into a process. It shows a message box with information about process and thread.
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


## TODO

* [ ] SetThreadContext & LoadLibraryExW injection (e.g. winword.exe). Requires updated shellcode
* [ ] QueueUserApc
* [ ] InjectDllByOEP
* [ ] x86 injection (add build plan for DLL project).


Really don't know whether the following is worth adding:
* [ ] SetThreadContext for x86
* [ ] SetWindowsHookEx
* [ ] Reflective injection
* [ ] Inject from driver in kernel space


## Links

Used code from:
* [InjectCollection](https://github.com/AzureGreen/InjectCollection/) by [AzureGreen on GitHub](https://github.com/AzureGreen) &ndash; Some helpful utilities and `Define.h`
* [3 Effective DLL Injection Techniques for Setting API Hooks](https://www.apriorit.com/dev-blog/679-windows-dll-injection-for-api-hooks)

Related code:
* [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) by [stephenfewer](https://github.com/stephenfewer) &ndash; Another injection technique
* [injection](https://github.com/odzhan/injection) by [odzhan](https://github.com/odzhan/injection) &ndash; Collection of injection methods
