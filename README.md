# ShellCodeLoader
A small shellcode loader library written in C#
This small library allows you to inject shellcode in memory of current launched file. 
Useful to use as red team or in a remote access tool. Works for 32 & 64 bit Executable

Note : Shellcode for 32 bit works ONLY for 32 bit and vice-versa (64 bit). 

I added some test payloads which I've converted with 
* First with : Donut (https://github.com/TheWover/donut) : turns my payload into raw shellcode
* Second with HxD Editor (https://mh-nexus.de/en/downloads.php?product=HxD20) : gives me an array of raw bytes from payloads converted with Donut


Includes : 

* Asynchronous (a simple Task.Run to not block main thread)
* Loading with Kernel32
* Loading with NtDll
* NtDll : NtAllocateVirtualMemory
* NtDll : NtWriteVirtualMemory
* NtDll : NtProtectVirtualMemory
* NtDll : NtFreeVirtualMemory
* Kernel32 : GetCurrentProcess
* Kernel32 : VirtualAlloc
* Kernel32 : VirtualFree
* Kernel32 : VirtualProtect
* Kernel32 : WriteProcessMemory
* Kernel32 : GetModuleHandle
* Kernel32 : GetProcAddress
* Enumeration : PageProtection
* Enumeration : TypeAlloc
* Enumeration: FreeType
* Delegates : all functions have been written with delegate style except GetModuleHandle and GetProcAddress

TODO :
* Inject shellcode in another process with VirtualEx and NtEx functions
* Check if shellcode is 64 or 32 bit before injection

Known : 
* Debugging 32 bit test injection involves PInvokeStackImbalance
