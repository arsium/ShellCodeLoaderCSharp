# ShellCodeLoader
A small shellcode loader library written in C#.
<br>
This small library allows you to inject shellcode in memory of current launched file or any other processes.
Useful to use as red team or in a remote access tool. Works for 32 & 64 bit shellcode.

Note : 
* has been tested on same proces and notepad and all works fine

I added some test payloads which I've converted with 
* First with : Donut (https://github.com/TheWover/donut) : turns my payload into raw shellcode
* Second with HxD Editor (https://mh-nexus.de/en/downloads.php?product=HxD20) : gives me an array of raw bytes from payloads converted with Donut

How to use it ?

For same process:

```
ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp64.rawData);
cpp.LoadWithKernel32();//can be LoadWithNTDelegates , LoadWithKernel32Delegates or LoadWithNT
cpp.Dispose();
```
For other processes:

```
Process Target = Process.GetProcessesByName("notepad")[0];
ShellCodeLoader.ShellCodeLoaderEx cpp = new ShellCodeLoader.ShellCodeLoaderEx(Target, PayloadCpp64.rawData);
cpp.LoadWithKernel32();//or cpp.LoadWithNT();
cpp.Dispose();
```

MapView:

```
ShellCodeLoader.MapView cpp = new ShellCodeLoader.MapView(PayloadCpp64.rawData);
cpp.LoadWithNtMapView();
cpp.Dispose();
```

MapView with target:

```
ShellCodeLoader.MapView cpp = new ShellCodeLoader.MapView(Target, PayloadCpp64.rawData);
cpp.LoadWithNtMapView();
cpp.Dispose();
```

Includes : 

* Asynchronous (a simple Task.Run to not block main thread)
* Loading with Kernel32
* Loading with NtDll
* NtDll : NtAllocateVirtualMemory
* NtDll : NtWriteVirtualMemory
* NtDll : NtProtectVirtualMemory
* NtDll : NtFreeVirtualMemory
* NtDll : NtCreateThreadEx
* NtDll : NtCreateSection
* NtDll : NtMapViewOfSection
* Kernel32 : GetCurrentProcess
* Kernel32 : VirtualAlloc
* Kernel32 : VirtualAllocEx
* Kernel32 : VirtualFree
* Kernel32 : VirtualProtect
* Kernel32 : VirtualProtectEx
* Kernel32 : WriteProcessMemory
* Kernel32 : CreateRemoteThread
* Kernel32 : GetModuleHandle
* Kernel32 : GetProcAddress
* Enumeration : PageProtection
* Enumeration : TypeAlloc
* Enumeration: FreeType
* Enumeration : SectionAccess
* Enumeration : MappingAttributes
* Delegates : all functions have been written with delegate style except GetModuleHandle and GetProcAddress

TODO :
* <s>Inject shellcode in another process with VirtualEx and NtEx functions</s>
* Check if shellcode is 64 or 32 bit before injection

Known : 
* Debugging 32 bit test injection involves PInvokeStackImbalance
