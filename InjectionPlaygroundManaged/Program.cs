using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectionPlaygroundManaged
{
    class Program
    {
        static string WatchedProcess = "";
        static string InjectedDllName = "";

        static void Usage()
        {
            Console.WriteLine("Usage: InjectionPlaygroundManaged.exe [Process Name] [DLL File Name]");
            Console.WriteLine();
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Usage();
                return;
            }

            if (args.Length >= 1)
            {
                WatchedProcess = args[0].ToLower();
            }

            if (args.Length >= 2)
            {
                InjectedDllName = args[1];
            }
            else
            {
                InjectedDllName = Environment.Is64BitProcess ? "InjectedDll.x64.dll" : "InjectedDll.x86.dll";
            }

            Console.WriteLine("Monitor is running as {0} process", Environment.Is64BitProcess ? "X64" : "X86");
            Console.WriteLine("Injection DLL file: {0}", InjectedDllName);

            InjectedDllName = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, InjectedDllName));

            using (ManagementEventWatcher startWatch = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace")))
            using (ManagementEventWatcher stopWatch = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace")))
            {
                startWatch.EventArrived += new EventArrivedEventHandler(startWatch_EventArrived);
                startWatch.Start();

                stopWatch.EventArrived += new EventArrivedEventHandler(stopWatch_EventArrived);
                stopWatch.Start();

                if (WatchedProcess != "")
                {
                    Console.WriteLine("Waiting for processes with name \"{0}\"", WatchedProcess);
                }

                Console.WriteLine("Press ESC to exit");
                do
                {
                    while (!Console.KeyAvailable)
                    {
                        System.Threading.Thread.Sleep(50);
                    }
                } while (Console.ReadKey(true).Key != ConsoleKey.Escape);

                startWatch.Stop();
                stopWatch.Stop();
            }
        }

        static void stopWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            string name = e.NewEvent.Properties["ProcessName"].Value.ToString();
            int processId = int.Parse(e.NewEvent.Properties["ProcessID"].Value.ToString());
            Console.WriteLine("Process stopped PID={0} Name={1}", processId, name);
        }

        static void startWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            string name = e.NewEvent.Properties["ProcessName"].Value.ToString();
            int processId = int.Parse(e.NewEvent.Properties["ProcessID"].Value.ToString());
            Console.WriteLine("Process started PID={0} Name={1}", processId, name);

            if (WatchedProcess == name.ToLower())
            {
                Process proc = Process.GetProcessById(processId);

                if (InjectIntoProcess(proc, InjectedDllName))
                {
                    Console.WriteLine("Injected DLL {0} to Process PID={1}", InjectedDllName, processId);
                }
                else
                {
                    Console.WriteLine("Failed to inject DLL to PID={0}", processId);
                }
            }
        }

        static bool InjectIntoProcess(Process proc, string dllPath)
        {
            // Get handle of the process - with required privileges
            IntPtr procHandle = Win32Utils.OpenProcess(Win32Utils.PROCESS_CREATE_THREAD/* | Win32Utils.PROCESS_QUERY_INFORMATION*/ |
                Win32Utils.PROCESS_VM_OPERATION | Win32Utils.PROCESS_VM_WRITE/* | Win32Utils.PROCESS_VM_READ*/, false, proc.Id);
            if (procHandle == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error: OpenProcess");
                return false;
            }
            Console.WriteLine("Opened handle to process == {0}", procHandle);

            // searching for the address of LoadLibraryA and storing it in a pointer
            IntPtr kernel32Dll = Win32Utils.GetModuleHandle("kernel32.dll");
            if (kernel32Dll == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error: GetModuleHandle");
                return false;
            }
            IntPtr loadLibraryAddr = Win32Utils.GetProcAddress(kernel32Dll, "LoadLibraryA");
            if (loadLibraryAddr == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error: GetProcAddress");
                return false;
            }

            // name of the dll we want to inject
            UIntPtr dllPathBufferLen = (UIntPtr)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char)));

            // alocating some memory on the target process - enough to store the name of the dll
            // and storing its address in a pointer
            IntPtr allocMemAddress = Win32Utils.VirtualAllocEx(procHandle, IntPtr.Zero,
                dllPathBufferLen, Win32Utils.MEM_COMMIT | Win32Utils.MEM_RESERVE, Win32Utils.PAGE_READWRITE);
            if (allocMemAddress == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error: VirtualAllocEx");
                return false;
            }
            Console.WriteLine("Created virtual memory == {0}", allocMemAddress);

            // writing the name of the dll there
            bool status = true;
            IntPtr pThread = IntPtr.Zero;
            do
            {
                UIntPtr bytesWritten;
                byte[] dllNameBytes = Encoding.Default.GetBytes(dllPath + char.MinValue);
                Console.WriteLine("Writing buffer of lenght={0} with dll name", dllNameBytes.Length);
                if (!Win32Utils.WriteProcessMemory(procHandle, allocMemAddress, dllNameBytes,
                    dllPathBufferLen, out bytesWritten))
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.Error.WriteLine("Error: WriteProcessMemory error == {0}", error);
                    status = false;
                    break;
                }

                if (bytesWritten != dllPathBufferLen)
                {
                    Console.Error.WriteLine("Error: WriteProcessMemory incorrect buffer size written");
                    status = false;
                    break;
                }
                Console.WriteLine("Wrote buffer to virtual memory == {0}", bytesWritten);

                // creating a thread that will call LoadLibraryA with allocMemAddress as argument
                pThread = Win32Utils.CreateRemoteThread(procHandle, IntPtr.Zero, UIntPtr.Zero, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
                if (pThread == IntPtr.Zero)
                {
                    // Get the last error
                    int error = Marshal.GetLastWin32Error();

                    Console.Error.WriteLine("Error: CreateRemoteThread Error={0}", error);
                    status = false;
                    break;
                }
                Console.WriteLine("Created remote thread with handle == {0}", pThread);

                const uint WaitingTime = 100; // INFINITY : uint.MaxValue
                uint waitStatus = Win32Utils.WaitForSingleObject(pThread, WaitingTime);
                if (waitStatus == Win32Utils.WAIT_FAILED)
                {
                    Console.Error.WriteLine("Error: WaitForSingleObject");
                    status = false;
                    break;
                }
                Console.WriteLine("Thread wait status == {0}", waitStatus);

                UIntPtr exitStatus;
                if (!Win32Utils.GetExitCodeThread(pThread, out exitStatus))
                {
                    Console.Error.WriteLine("Error: GetExitCodeThread");
                    break;
                }

                Console.WriteLine("Thread exit status == {0}", exitStatus);
            } while (false);

            if (pThread != IntPtr.Zero)
            {
                if (!Win32Utils.CloseHandle(pThread))
                {
                    Console.Error.WriteLine("Error: CloseHandle");
                }
            }

            if (allocMemAddress != IntPtr.Zero)
            {
                if (!Win32Utils.VirtualFreeEx(procHandle, allocMemAddress, UIntPtr.Zero, Win32Utils.MEM_RELEASE))
                {
                    Console.Error.WriteLine("Error: VirtualFreeEx");
                }
            }

            return status;
        }
    }
}
