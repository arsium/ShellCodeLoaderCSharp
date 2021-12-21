using System;
using System.Runtime.InteropServices;
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
|| Please let this credit for all the time I worked on ||
*/
namespace ShellCodeLoader
{
    internal class Shared
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate void ShellCodeCaller();

        [Flags]
        internal enum TypeAlloc : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_PHYSICAL = 0x00400000,
            MEM_TOP_DOWN = 0x00100000,
            MEM_WRITE_WATCH = 0x00200000
        }

        [Flags]
        internal enum FreeType : uint
        {
            MEM_DECOMMIT = 0x00004000,
            MEM_RELEASE = 0x00008000,
            MEM_COALESCE_PLACEHOLDERS = 0x00000001,
            MEM_PRESERVE_PLACEHOLDER = 0x00000002
        }

        [Flags]
        internal enum PageProtection : uint
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [Flags]
        internal enum AccessMask : uint
        {
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000
        }
    }
}
