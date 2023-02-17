# Description

Collection of injection techniques using:
* CreateRemoteThread
* RtlCreateUserThread
* SetThreadContext (now only x64 and only for processes that import LoadLibraryW)

# Links

Used code from:
* [InjectCollection](https://github.com/AzureGreen/InjectCollection/) by [AzureGreen on GitHub](https://github.com/AzureGreen) &ndash; Some helpful utilities and `Define.h`
* [3 Effective DLL Injection Techniques for Setting API Hooks](https://www.apriorit.com/dev-blog/679-windows-dll-injection-for-api-hooks)

Related code:
* [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) by [stephenfewer](https://github.com/stephenfewer) &ndash; Another injection technique
* [injection](https://github.com/odzhan/injection) by [odzhan](https://github.com/odzhan/injection) &ndash; Collection of injection methods
