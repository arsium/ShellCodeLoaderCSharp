using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
|| Please let this credit for all the time I worked on ||
 */
namespace ShellCodeLoader
{
    public class ShellCodeLoader : IDisposable
    {
        private byte[] ShellCode;
        private IntPtr ptr;
        /// <summary>
        /// Default is false.
        /// </summary>
        public bool Asynchronous { get; set; }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void ShellCodeCaller();

        public ShellCodeLoader(byte[] shellCode) 
        {
            this.ShellCode = shellCode;
            Asynchronous = false;
        }

        public void LoadWithNT() 
        {

            if (this.Asynchronous)
            {
                Task.Run(() =>
                {
                    this.ptr = IntPtr.Zero;
                    uint RegionSize = (uint)ShellCode.Length;
                    Imports.NtAllocateVirtualMemory(Imports.GetCurrentProcess(), ref ptr, IntPtr.Zero, ref RegionSize, Imports.TypeAlloc.MEM_COMMIT | Imports.TypeAlloc.MEM_RESERVE, Imports.PageProtection.PAGE_EXECUTE_READWRITE);
                    UIntPtr bytesWritten;
                    Imports.NtWriteVirtualMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out bytesWritten);
                    Imports.PageProtection flOld = new Imports.PageProtection();
                    Imports.NtProtectVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, Imports.PageProtection.PAGE_EXECUTE_READ, ref flOld);
                    ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
                    load();
                    Imports.NtFreeVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, Imports.FreeType.MEM_RELEASE);
                });
            }
            else 
            {
                this.ptr = IntPtr.Zero;
                uint RegionSize = (uint)ShellCode.Length;
                Imports.NtAllocateVirtualMemory(Imports.GetCurrentProcess(), ref ptr, IntPtr.Zero, ref RegionSize, Imports.TypeAlloc.MEM_COMMIT | Imports.TypeAlloc.MEM_RESERVE, Imports.PageProtection.PAGE_EXECUTE_READWRITE);
                UIntPtr bytesWritten;
                Imports.NtWriteVirtualMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out bytesWritten);
                Imports.PageProtection flOld = new Imports.PageProtection();
                Imports.NtProtectVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, Imports.PageProtection.PAGE_EXECUTE_READ, ref flOld);
                ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
                load();
                Imports.NtFreeVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, Imports.FreeType.MEM_RELEASE);
            }
        }

        public void LoadWithKernel32()
        {
            if (this.Asynchronous)
            {
                Task.Run(() =>
                {
                    this.ptr = Imports.VirtualAlloc(IntPtr.Zero, (IntPtr)ShellCode.Length, Imports.TypeAlloc.MEM_COMMIT | Imports.TypeAlloc.MEM_RESERVE, Imports.PageProtection.PAGE_EXECUTE_READWRITE);
                    uint RegionSize = (uint)ShellCode.Length;
                    UIntPtr writtenBytes;
                    Imports.WriteProcessMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out writtenBytes);
                    Imports.PageProtection flOld;
                    Imports.VirtualProtect(ptr, RegionSize, Imports.PageProtection.PAGE_EXECUTE_READ, out flOld);
                    ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
                    load();
                    Imports.VirtualFree(ptr, (uint)0, Imports.FreeType.MEM_RELEASE);
                });
            }
            else 
            {
                this.ptr = Imports.VirtualAlloc(IntPtr.Zero, (IntPtr)ShellCode.Length, Imports.TypeAlloc.MEM_COMMIT | Imports.TypeAlloc.MEM_RESERVE, Imports.PageProtection.PAGE_EXECUTE_READWRITE);
                uint RegionSize = (uint)ShellCode.Length;
                UIntPtr writtenBytes;
                Imports.WriteProcessMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out writtenBytes);
                Imports.PageProtection flOld;
                Imports.VirtualProtect(ptr, RegionSize, Imports.PageProtection.PAGE_EXECUTE_READ, out flOld);
                ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
                load();
                Imports.VirtualFree(ptr, (uint)0, Imports.FreeType.MEM_RELEASE);
            }
        }
        private static class Imports 
        {
            internal const String KERNEL32 = "kernel32.dll";
            internal const String NTDLL = "ntdll.dll";

            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true)]
            public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref uint RegionSize, TypeAlloc AllocationType, PageProtection Protect);
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true)]
            public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buffer, UIntPtr bufferSize, out UIntPtr written);
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true)]
            public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint numberOfBytes, PageProtection newProtect, ref PageProtection oldProtect);
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true)]
            public static extern uint NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, FreeType FreeType);
          
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr GetCurrentProcess();
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr VirtualAlloc(IntPtr address, IntPtr numBytes, TypeAlloc commitOrReserve, PageProtection pageProtectionMode);
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr VirtualFree(IntPtr lpAddress, uint dwSize, FreeType FreeType);
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true)]
            public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, PageProtection flNewProtect, out PageProtection lpflOldProtect);
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

            public enum PageProtection : uint
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
            public enum TypeAlloc : uint
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
            public enum FreeType : uint
            {
                MEM_DECOMMIT = 0x00004000,
                MEM_RELEASE = 0x00008000,
                MEM_COALESCE_PLACEHOLDERS = 0x00000001,
                MEM_PRESERVE_PLACEHOLDER = 0x00000002
            }
        }

        private bool _disposed = false;

        // Instantiate a SafeHandle instance.
        private SafeHandle _safeHandle = new SafeFileHandle(IntPtr.Zero, true);

        // Public implementation of Dispose pattern callable by consumers.
        public void Dispose() => Dispose(true);

        // Protected implementation of Dispose pattern.
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                // Dispose managed state (managed objects).
                _safeHandle?.Dispose();
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
