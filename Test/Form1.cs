using System;
using System.Windows.Forms;
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||

    Each payload has been converted using :
    -First donut : https://github.com/TheWover/donut to convert the payload to shellcode
    -Second HxD Editor :  https://mh-nexus.de/en/downloads.php?product=HxD20 to get directly raw bytes exported to .cs
 */
namespace Test
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp64.rawData);
                cpp.LoadWithNT();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp64.rawData);
                csharp.LoadWithNT();
                csharp.Dispose();
            }
            else 
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp32.rawData);
                cpp.Asynchronous = true;
                cpp.LoadWithNT();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp32.rawData);
                csharp.LoadWithNT();
                csharp.Dispose();
            }
        }
        private void button2_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp64.rawData);
                cpp.LoadWithKernel32();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp64.rawData);
                csharp.LoadWithKernel32();
                csharp.Dispose();
            }
            else
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp32.rawData);
                cpp.Asynchronous = true;
                cpp.LoadWithKernel32();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp32.rawData);
                csharp.LoadWithKernel32();
                csharp.Dispose();
            }
        }
    }
}
