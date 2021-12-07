using System;
using System.Diagnostics;
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

            //MessageBox.Show(Process.GetProcessById(33008).ProcessName);
            /*Process Target = Process.GetProcessesByName("ProcessHacker")[0];//notepad
            MessageBox.Show(Target.MainWindowTitle);
            ShellCodeLoader.ShellCodeLoaderEx cpp = new ShellCodeLoader.ShellCodeLoaderEx(Target, PayloadCpp64.rawData);
            cpp.LoadWithKernel32();
            cpp.LoadWithNT();
            cpp.Dispose();*/

            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.ShellCodeLoader dlang = new ShellCodeLoader.ShellCodeLoader(Test.PayloadD_DLL_64.rawData);//Payload D_64 not working ?
                dlang.LoadWithNT();
                dlang.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(Test.PayloadCSharp64.rawData);
                csharp.LoadWithNT();
                csharp.Dispose();
            }
            else
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadD_DLL_32.rawData);
                cpp.Asynchronous = true;
                cpp.LoadWithNT();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp32.rawData);
                csharp.LoadWithNT();
                csharp.Dispose();
            }
        }

        private void injectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Process Target = Process.GetProcessesByName(listView1.SelectedItems[0].SubItems[1].Text)[0];
           // MessageBox.Show(Target.MainWindowTitle);
            ShellCodeLoader.ShellCodeLoaderEx cpp = new ShellCodeLoader.ShellCodeLoaderEx(Target, PayloadCpp64.rawData);
            cpp.LoadWithNT();
            cpp.Dispose();
            //ShellCodeLoader.ShellCodeLoaderEx csharp = new ShellCodeLoader.ShellCodeLoaderEx(Target, PayloadCSharp64.rawData);
            //csharp.LoadWithNT();
            //csharp.Dispose();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp64.rawData);//same process
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

        private void button3_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp64.rawData);
                cpp.LoadWithNTDelegates();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp64.rawData);
                csharp.LoadWithNTDelegates();
                csharp.Dispose();
            }
            else
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp32.rawData);
                cpp.Asynchronous = true;
                cpp.LoadWithNTDelegates();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp32.rawData);
                csharp.LoadWithNTDelegates();
                csharp.Dispose();
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp64.rawData);
                cpp.LoadWithKernel32Delegates();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp64.rawData);
                csharp.LoadWithKernel32Delegates();
                csharp.Dispose();
            }
            else
            {
                ShellCodeLoader.ShellCodeLoader cpp = new ShellCodeLoader.ShellCodeLoader(PayloadCpp32.rawData);
                cpp.Asynchronous = true;
                cpp.LoadWithKernel32Delegates();
                cpp.Dispose();
                ShellCodeLoader.ShellCodeLoader csharp = new ShellCodeLoader.ShellCodeLoader(PayloadCSharp32.rawData);
                csharp.LoadWithKernel32Delegates();
                csharp.Dispose();
            }
        }

        private void refreshToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            foreach (Process p in Process.GetProcesses()) 
            {
                ListViewItem I = new ListViewItem(p.Id.ToString());
                I.SubItems.Add(p.ProcessName);
                listView1.Items.Add(I);
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            if (IntPtr.Size == 8)
            {
                ShellCodeLoader.MapView cpp = new ShellCodeLoader.MapView(PayloadCpp64.rawData);
                ShellCodeLoader.MapView csharp = new ShellCodeLoader.MapView(PayloadCSharp64.rawData);
                cpp.LoadWithNtMapView();
                csharp.LoadWithNtMapView();
                cpp.Dispose();
                csharp.Dispose();
            }
            else 
            {
                ShellCodeLoader.MapView cpp = new ShellCodeLoader.MapView(PayloadCpp32.rawData);
                ShellCodeLoader.MapView csharp = new ShellCodeLoader.MapView(PayloadCSharp32.rawData);
                cpp.LoadWithNtMapView();
                csharp.LoadWithNtMapView();
                cpp.Dispose();
                csharp.Dispose();
            }
        }

        private void injectWithMapViewToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Process Target = Process.GetProcessesByName(listView1.SelectedItems[0].SubItems[1].Text)[0];
            ShellCodeLoader.MapView cpp = new ShellCodeLoader.MapView(Target, PayloadCpp64.rawData);
            ShellCodeLoader.MapView csharp = new ShellCodeLoader.MapView(Target, PayloadCSharp64.rawData);
            cpp.LoadWithNtMapView();
            csharp.LoadWithNtMapView();
            cpp.Dispose();
            csharp.Dispose();
        }
    }
}
