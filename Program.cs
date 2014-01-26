using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Killer {

    static class Program {

        private const uint TB_BUTTONCOUNT = 0x0418;   // WM_USER+24
        private const uint TB_GETBUTTON = 0x0417;     // WM_USER+23
        private const uint TB_DELETEBUTTON = 0x0416;  // WM_USER+22

        private static object key = new object();     // concurrency protection

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length.Equals(1))
            {
                KillProgram(args[0]);
            }

            CleanUpNotifyIcons();
        }

        // Kill a program by name
        private static void KillProgram(string name)
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                process.Kill();
            }
        }

        // Clean-up tray/notify icons.
        // Getted from http://www.codeproject.com/Articles/19620/LP-TrayIconBuster
        private static uint CleanUpNotifyIcons()
        {
            uint removedCount = 0;

            // prevent concurrency problems
            lock (key)
            {
                IntPtr hWnd = IntPtr.Zero;
                FindNestedWindow(ref hWnd, "Shell_TrayWnd");
                FindNestedWindow(ref hWnd, "TrayNotifyWnd");
                FindNestedWindow(ref hWnd, "SysPager");
                FindNestedWindow(ref hWnd, "ToolbarWindow32");

                // create an object so we can exchange data with other process
                using (LP_Process process = new LP_Process(hWnd))
                {
                    ToolBarButton tbb = new ToolBarButton();
                    IntPtr remoteButtonPtr = process.Allocate(tbb);
                    TrayData td = new TrayData();
                    process.Allocate(td);
                    uint itemCount = (uint)SendMessage(hWnd, TB_BUTTONCOUNT,
                        IntPtr.Zero, IntPtr.Zero);
                    bool foundSomeExe = false;
                    // for safety reasons we perform two passes:
                    // pass1 = search for my own NotifyIcon
                    // pass2 = search phantom icons and remove them pass2 doesnt happen if pass1 fails
                    for (int pass = 1; pass <= 2; pass++)
                    {
                        for (uint item = 0; item < itemCount; item++)
                        {
                            // index changes when previous items got removed !
                            uint item2 = item - removedCount;
                            uint SOK = (uint)SendMessage(hWnd, TB_GETBUTTON,
                                new IntPtr(item2), remoteButtonPtr);
                            if (SOK != 1) throw new ApplicationException("TB_GETBUTTON failed");
                            process.Read(tbb, remoteButtonPtr);
                            process.Read(td, tbb.dwData);
                            if (td.hWnd == IntPtr.Zero) throw new ApplicationException("Invalid window handle");
                            using (LP_Process proc = new LP_Process(td.hWnd))
                            {
                                string filename = proc.GetImageFileName();
                                if (pass == 1 && filename != null)
                                {
                                    filename = filename.ToLower();
                                    if (filename.EndsWith(".exe"))
                                    {
                                        foundSomeExe = true;
                                        break;
                                    }
                                }
                                // a phantom icon has no imagefilename
                                if (pass == 2 && filename == null)
                                {
                                    SOK = (uint)SendMessage(hWnd, TB_DELETEBUTTON,
                                        new IntPtr(item2), IntPtr.Zero);
                                    if (SOK != 1) throw new ApplicationException("TB_DELETEBUTTON failed");
                                    removedCount++;
                                }
                            }
                        }
                        // if I did not see myself, I will not run the second
                        // pass, which would try and remove phantom icons
                        if (!foundSomeExe) throw new ApplicationException(
                            "Failed to find any real icon");
                    }
                }
            }
            return removedCount;
        }

        // Find a topmost or nested window with specified name
        private static void FindNestedWindow(ref IntPtr hWnd, string name)
        {
            if (hWnd == IntPtr.Zero)
            {
                hWnd = FindWindow(name, null);
            }
            else
            {
                hWnd = FindWindowEx(hWnd, IntPtr.Zero, name, null);
            }
            if (hWnd == IntPtr.Zero) throw new ApplicationException("Failed to locate window " + name);
        }

        [DllImport("user32.dll", EntryPoint = "SendMessageA", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr SendMessage(IntPtr Hdc, uint Msg_Const, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", EntryPoint = "FindWindowA", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        public static extern IntPtr FindWindow(string lpszClass, string lpszWindow);

        [DllImport("user32.dll", EntryPoint = "FindWindowExA", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

        // ToolBarButton struct used for TB_GETBUTTON message.
        [StructLayout(LayoutKind.Sequential)]
        public class ToolBarButton
        {
            public uint iBitmap;
            public uint idCommand;
            public byte fsState;
            public byte fsStyle;
            private byte bReserved0;
            private byte bReserved1;
            public IntPtr dwData;
            public uint iString;
        }

        // TrayData struct used for extra info for ToolBarButton.
        [StructLayout(LayoutKind.Sequential)]
        public class TrayData
        {
            public IntPtr hWnd;
            public uint uID;
            public uint uCallbackMessage;
            private uint reserved0;
            private uint reserved1;
            public IntPtr hIcon;
        }
    }

    public class LP_Pinner : IDisposable
    {
        private GCHandle handle;
        private bool disposed;
        private IntPtr ptr;

        // Creates an instance op LP_Pinner, and pins the argument.
        public LP_Pinner(object obj)
        {
            handle = GCHandle.Alloc(obj, GCHandleType.Pinned);
            ptr = handle.AddrOfPinnedObject();
        }

        // Undoes the pinning.
        ~LP_Pinner()
        {
            Dispose();
        }

        // Disposes of the object's internal resources.
        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                handle.Free();
                ptr = IntPtr.Zero;
            }
        }

        // Returns the pointer to the pinned object.
        public IntPtr Ptr { get { return ptr; } }
    }

    public class LP_Process : IDisposable
    {
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_READWRITE = 0x0004;

        private IntPtr hProcess;
        private uint ownerProcessID;
        private ArrayList allocations = new ArrayList();
        
        // Creates an instance of LP_Process, owner of the window.
        public LP_Process(IntPtr hWnd)
        {
            GetWindowThreadProcessId(hWnd, ref ownerProcessID);
            hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
                PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, false, ownerProcessID);
        }

        // Disposes of an LP_Process (closing all open handles).
        public void Dispose()
        {
            if (hProcess != IntPtr.Zero)
            {
                foreach (IntPtr ptr in allocations)
                {
                    VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
                }
                CloseHandle(hProcess);
            }
        }

        // Gets the file name of the process image.
        public string GetImageFileName()
        {
            StringBuilder sb = new StringBuilder(1024);
            bool OK = GetProcessImageFileName(hProcess, sb, sb.Capacity - 1);
            if (!OK) return null;
            return sb.ToString();
        }

        // Allocates a chunck of memory in the process.
        // The memory gets freed when the LP_Process object is disposed.
        public IntPtr Allocate(object managedObject)
        {
            int size = Marshal.SizeOf(managedObject);
            IntPtr ptr = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT, PAGE_READWRITE);
            if (ptr != IntPtr.Zero) allocations.Add(ptr);
            return ptr;
        }

        // Reads an object's data from the process memory at ptr.
        public void Read(object obj, IntPtr ptr)
        {
            using (LP_Pinner pin = new LP_Pinner(obj))
            {
                uint bytesRead = 0;
                int size = Marshal.SizeOf(obj);
                if (!ReadProcessMemory(hProcess, ptr, pin.Ptr, size, ref bytesRead))
                {
                    int err = GetLastError();
                    string s = "Read failed; err=" + err + "; bytesRead=" + bytesRead;
                    throw new ApplicationException(s);
                }
            }
        }

        // Reads a string from the process memory at ptr.
        public string ReadString(int size, IntPtr ptr)
        {
            StringBuilder sb = new StringBuilder(size);
            uint bytesRead = 0;
            if (!ReadProcessMemory(hProcess, ptr, sb, size, ref bytesRead))
            {
                int err = GetLastError();
                string s = "Read failed; err=" + err + "; bytesRead=" + bytesRead;
                throw new ApplicationException(s);
            }
            return sb.ToString();
        }

        // Write an object's data to the process memory at ptr.
        public void Write(object obj, int size, IntPtr ptr)
        {
            using (LP_Pinner pin = new LP_Pinner(obj))
            {
                uint bytesWritten = 0;
                if (!WriteProcessMemory(hProcess, ptr, pin.Ptr, size, ref bytesWritten))
                {
                    int err = GetLastError();
                    string s = "Write failed; err=" + err + "; bytesWritten=" + bytesWritten;
                    throw new ApplicationException(s);
                }
            }
        }

        // Retrieves the identifier of the thread that created the specified window
        // and the identifier of the process that created the window. 
        [DllImport("user32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, ref uint procId);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle,
            uint procID);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, int address,
            int size, uint allocationType, uint protection);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr address,
            int size, uint freeType);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteProcessMemory(IntPtr hProcess,
            IntPtr otherAddress, IntPtr localAddress, int size,
            ref uint bytesWritten);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadProcessMemory(IntPtr hProcess,
            IntPtr otherAddress, IntPtr localAddress, int size,
            ref uint bytesRead);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadProcessMemory(IntPtr hProcess,
            IntPtr otherAddress, StringBuilder localAddress, int size,
            ref uint bytesRead);

        [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetProcessImageFileName(IntPtr hProcess,
            StringBuilder fileName, int fileNameSize);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int GetLastError();
    }
}